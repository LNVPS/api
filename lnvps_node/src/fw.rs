//! The packet filter around a node's guests.
//!
//! 4c1 put the data plane in its own network namespace, which settled a whole
//! class of rules by construction: there is no interface from `br-lnvps` to the
//! operator's LAN, so there is nothing to write a rule against. What is left is
//! what no topology can express.
//!
//! - **A guest may only source the addresses LNVPS assigned it.** The route
//!   server's `AllowedIPs` already stops one node claiming another's addresses,
//!   but it cannot see *inside* a node: both guests' addresses legitimately
//!   belong to that node's peer, so guest A pretending to be guest B is
//!   invisible from the far end and has to be caught here.
//! - **Guests may not talk to each other at layer 2.** They share a bridge, and
//!   proxy ARP tells each of them that every address is on-link, so without
//!   this a tenant can ARP-poison or ND-poison their neighbours — an attack
//!   that never reaches the IP layer the rest of this module filters at.
//!   Dropping the bridge's forward hook does not disconnect them: it forces
//!   their traffic to be *routed* by the node, which is where it can be
//!   checked, and is exactly what they would get if they were on two different
//!   nodes.
//! - **TCP MSS is clamped to the path MTU**, because a guest that ignores path
//!   MTU discovery otherwise gets a connection that opens and then hangs.
//!
//! The ruleset is owned wholesale and replaced in one transaction. The daemon
//! never appends to an operator's chains: it builds a complete table and swaps
//! it, so there is no moment when a guest is running unfiltered and no way for
//! a half-applied ruleset to survive a crash.
//!
//! **nftables only.** Rules are built as [`nftables`] schema objects and
//! exchanged with the kernel as JSON — never as text this file formats and the
//! machine parses back. Hand-written `nft` syntax has to be re-parsed to be
//! read, and scraping `nft list` output means a node's safety depends on the
//! output format of whatever nftables version an operator happens to have.
//! `iptables` was supported in an earlier draft and dropped: it cannot express
//! the layer 2 rule at all (that is `ebtables`, a third tool), it has no
//! equivalent of a typed exchange, and a second code path enforcing "the same"
//! policy is a second code path to get subtly wrong.

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField};
use nftables::schema::{Chain, NfListObject, Nftables, Rule, Set, SetTypeValue, Table};
use nftables::stmt::{Counter, JumpTarget, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use serde::{Deserialize, Serialize};

use crate::net::{DesiredDataPlane, GUEST_BRIDGE, TUNNEL_INTERFACE};

/// The name of everything this module owns.
///
/// One name, so an operator looking at their own firewall can see at a glance
/// which parts are LNVPS's, and so the daemon can delete its own work without
/// having to remember what it created.
pub const TABLE: &str = "lnvps";

/// The chain every packet from a guest is checked against first.
const SOURCE_CHAIN: &str = "source";

/// One guest, as the filter sees it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Binding {
    pub address: IpAddr,
    /// The guest's MAC, when LNVPS assigned one.
    ///
    /// A guest can set its own MAC, so this is not a strong identity — but
    /// pairing it with the address means a spoofing guest has to get both right
    /// *and* still cannot use an address that belongs to a guest on another
    /// node. Binding to the switch port instead is stronger and arrives in
    /// increment 5, when the daemon starts creating the ports.
    pub mac: Option<String>,
}

/// What the filter should enforce, derived from LNVPS's data plane document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    pub bindings: Vec<Binding>,
}

impl Policy {
    /// Read a policy out of the data plane document.
    ///
    /// The guest list is LNVPS's, never the node's own view of what is on the
    /// bridge: a node that derived the allowed addresses from the interfaces it
    /// could see would authorise whatever an operator attached.
    pub fn from_desired(desired: &DesiredDataPlane) -> Result<Self> {
        let mut bindings = Vec::new();
        for guest in &desired.guests {
            let address = guest
                .address
                .split('/')
                .next()
                .unwrap_or_default()
                .parse::<IpAddr>()
                .with_context(|| {
                    format!("LNVPS sent {}, which is not an address", guest.address)
                })?;
            bindings.push(Binding {
                address,
                // Lower-cased because that is how nftables states a MAC, and a
                // policy that differs from the machine's only by case would
                // read as drift on every comparison.
                mac: guest.mac.as_ref().map(|m| m.to_lowercase()),
            });
        }
        bindings.sort();
        bindings.dedup();
        Ok(Self { bindings })
    }

    fn of(&self, v6: bool) -> impl Iterator<Item = &Binding> {
        self.bindings
            .iter()
            .filter(move |b| b.address.is_ipv6() == v6)
    }
}

/// A short, stable name for a policy.
///
/// Rendered into a rule comment and read back off the machine, which is what
/// makes a refresh a no-op when nothing has changed. Derived from the policy
/// rather than from the built ruleset, so a change in *how* the rules are
/// expressed does not masquerade as a change in who is allowed.
pub fn fingerprint(policy: &Policy) -> String {
    let joined = policy
        .bindings
        .iter()
        .map(|b| format!("{}@{}", b.address, b.mac.as_deref().unwrap_or("-")))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "lnvps:{}",
        &crate::control_auth::sha256_hex(joined.as_bytes())[..16]
    )
}

/// What the filter currently is on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    /// Whether this machine can filter at all. `false` is a fact the health
    /// gate needs rather than an error to retry: a node with no nftables is not
    /// a node with a broken one, and the difference is what the operator reads.
    pub available: bool,
    /// Whether LNVPS's ruleset is currently loaded.
    pub present: bool,
    /// Whether guest-to-guest traffic is blocked at layer 2.
    ///
    /// Separate from `present` because it is a separate table with a separate
    /// hook, and a node with IP filtering but no L2 isolation is a real state
    /// worth naming rather than rounding down to "filtered".
    pub isolated: bool,
    /// How many guest addresses the loaded ruleset admits, for LNVPS's own
    /// reporting: a node whose count does not match the document it was sent is
    /// a node whose filter is stale, and a stale filter is how a returned
    /// address stays usable.
    pub bindings: usize,
    /// Which ruleset is loaded, as the machine states it.
    ///
    /// Carried in a rule comment rather than remembered by the daemon, because
    /// the question is what the *kernel* is enforcing. A daemon that trusted
    /// its own memory would keep reporting the ruleset it once applied after an
    /// operator flushed the table by hand.
    pub ruleset: Option<String>,
    /// Packets dropped for claiming an address the guest was not assigned.
    ///
    /// Reported because it is the one number here that says something about a
    /// *customer* rather than about the node: a guest that is spoofing is
    /// either compromised or hostile, and LNVPS would rather find out from a
    /// counter than from an upstream abuse report.
    pub spoofed_packets: u64,
}

/// Talking to nftables.
///
/// A trait for the same reason [`crate::net::NetOps`] is one: the policy and
/// the decisions are worth testing without root, and the end-to-end harness
/// needs to drive the real thing inside a namespace. Both directions are typed
/// — a ruleset in, a ruleset out — so nothing here formats or parses nft
/// syntax.
#[async_trait]
pub trait FirewallOps: Send + Sync {
    /// Whether this machine has a working nftables.
    async fn available(&self) -> bool;
    /// Load a ruleset, atomically.
    async fn apply(&self, ruleset: &Nftables<'_>) -> Result<()>;
    /// Read the machine's current ruleset back.
    async fn ruleset(&self) -> Result<Nftables<'static>>;
}

/// Load `policy` onto the machine, replacing whatever was there before.
///
/// A machine already running this exact ruleset is left alone. Reloading would
/// be harmless — the swap is atomic — but it would mean the daemon reported a
/// change on every poll, and a log in which everything changes constantly is a
/// log in which nothing can be noticed.
pub async fn apply(ops: &dyn FirewallOps, policy: &Policy) -> Result<Vec<String>> {
    if !ops.available().await {
        bail!(
            "This machine has no working nftables, so guests cannot be filtered \
             and none will be placed here"
        );
    }
    let tag = fingerprint(policy);
    if observe(ops).await.ruleset.as_deref() == Some(tag.as_str()) {
        return Ok(Vec::new());
    }
    ops.apply(&ruleset(policy))
        .await
        .context("Cannot load the guest firewall")?;
    Ok(vec![format!(
        "loaded firewall {tag} with {} guest bindings",
        policy.bindings.len()
    )])
}

/// Read the loaded ruleset back.
///
/// Every field is taken from the machine's own JSON rather than from anything
/// the daemon remembers, so an operator who flushes the table by hand is
/// reported as unfiltered — and gets it rebuilt on the next refresh.
pub async fn observe(ops: &dyn FirewallOps) -> FirewallState {
    if !ops.available().await {
        return FirewallState::default();
    }
    let Ok(current) = ops.ruleset().await else {
        return FirewallState {
            available: true,
            ..Default::default()
        };
    };
    let mut state = FirewallState {
        available: true,
        ..Default::default()
    };
    for object in current.objects.iter() {
        let NfObjectRef::List(object) = object.into() else {
            continue;
        };
        match object {
            NfListObject::Chain(chain)
                if chain.table == TABLE
                    && chain.family == NfFamily::Bridge
                    && chain.policy == Some(NfChainPolicy::Drop) =>
            {
                state.isolated = true;
            }
            NfListObject::Chain(chain) if chain.table == TABLE && chain.hook.is_some() => {
                state.present = true;
            }
            // The set the return path is checked against: its size is how many
            // guests this machine will currently deliver to.
            NfListObject::Set(set) if set.table == TABLE && set.name.starts_with("assigned") => {
                state.bindings += set.elem.as_ref().map(|e| e.len()).unwrap_or(0);
            }
            NfListObject::Rule(rule) if rule.table == TABLE => {
                let Some(comment) = rule.comment.as_deref().filter(|c| c.starts_with("lnvps:"))
                else {
                    continue;
                };
                state.ruleset = Some(comment.to_string());
                // The counter on the same rule as the tag, so a counter added
                // elsewhere — by a later version of this file, or by an
                // operator — is never reported as spoofing.
                for statement in rule.expr.iter() {
                    if let Statement::Counter(Counter::Anonymous(Some(counter))) = statement {
                        state.spoofed_packets = counter.packets.unwrap_or(0) as u64;
                    }
                }
            }
            _ => {}
        }
    }
    state
}

/// Borrowed view of an object in a ruleset, list or command.
///
/// nftables states input as commands and output as bare objects; observation
/// only ever sees the latter, but matching on both means a future caller
/// reading back its own transaction does not silently see nothing.
enum NfObjectRef<'a, 'b> {
    List(&'a NfListObject<'b>),
    Other,
}

impl<'a, 'b> From<&'a nftables::schema::NfObject<'b>> for NfObjectRef<'a, 'b> {
    fn from(object: &'a nftables::schema::NfObject<'b>) -> Self {
        match object {
            nftables::schema::NfObject::ListObject(o) => NfObjectRef::List(o),
            nftables::schema::NfObject::CmdObject(_) => NfObjectRef::Other,
        }
    }
}

/// The whole ruleset, as one transaction.
///
/// nftables applies a batch atomically, so the delete and the rebuild either
/// both happen or neither does. The alternative — flushing and then adding —
/// leaves a window in which guests are unfiltered, which on a machine carrying
/// other people's customers is not a window worth having.
pub fn ruleset(policy: &Policy) -> Nftables<'static> {
    let mut batch = Batch::new();
    let tag = fingerprint(policy);

    // Added before it is deleted, so the delete has something to delete:
    // nftables fails a transaction that removes what does not exist, which
    // would mean the very first run on a freshly booted node always errored.
    for family in [NfFamily::INet, NfFamily::Bridge] {
        batch.add(NfListObject::Table(Table {
            family,
            name: TABLE.into(),
            handle: None,
        }));
        batch.delete(NfListObject::Table(Table {
            family,
            name: TABLE.into(),
            handle: None,
        }));
        batch.add(NfListObject::Table(Table {
            family,
            name: TABLE.into(),
            handle: None,
        }));
    }

    // Guests LNVPS gave a MAC are held to the pair; guests without one are
    // allowed on address alone. Two sets rather than one, so it is visible in
    // the loaded ruleset which guests are held to which standard.
    for v6 in [false, true] {
        let family = if v6 { "6" } else { "4" };
        batch.add(NfListObject::Set(Box::new(set(
            &format!("bound{family}"),
            SetTypeValue::Concatenated(
                vec![nftables::schema::SetType::EtherAddr, address_type(v6)].into(),
            ),
            policy
                .of(v6)
                .filter_map(|b| {
                    b.mac.as_ref().map(|mac| {
                        Expression::Named(NamedExpression::Concat(vec![
                            Expression::String(mac.clone().into()),
                            Expression::String(b.address.to_string().into()),
                        ]))
                    })
                })
                .collect(),
        ))));
        batch.add(NfListObject::Set(Box::new(set(
            &format!("guest{family}"),
            SetTypeValue::Single(address_type(v6)),
            policy
                .of(v6)
                .filter(|b| b.mac.is_none())
                .map(|b| Expression::String(b.address.to_string().into()))
                .collect(),
        ))));
        batch.add(NfListObject::Set(Box::new(set(
            &format!("assigned{family}"),
            SetTypeValue::Single(address_type(v6)),
            policy
                .of(v6)
                .map(|b| Expression::String(b.address.to_string().into()))
                .collect(),
        ))));
    }

    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: TABLE.into(),
        name: SOURCE_CHAIN.into(),
        newname: None,
        handle: None,
        dev: None,
        _type: None,
        hook: None,
        prio: None,
        policy: None,
    }));
    for v6 in [false, true] {
        batch.add(rule(
            SOURCE_CHAIN,
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Concat(vec![
                        field("ether", "saddr"),
                        field(protocol(v6), "saddr"),
                    ])),
                    right: Expression::String(
                        format!("@bound{}", if v6 { "6" } else { "4" }).into(),
                    ),
                    op: Operator::EQ,
                }),
                Statement::Return(None),
            ],
            None,
        ));
        batch.add(rule(
            SOURCE_CHAIN,
            vec![
                Statement::Match(Match {
                    left: field(protocol(v6), "saddr"),
                    right: Expression::String(
                        format!("@guest{}", if v6 { "6" } else { "4" }).into(),
                    ),
                    op: Operator::EQ,
                }),
                Statement::Return(None),
            ],
            None,
        ));
    }
    // The drop that carries the tag and the counter. Both live here because
    // this is the rule that says "a guest lied about who it is": the tag makes
    // the ruleset identifiable, and the counter makes the lying visible.
    batch.add(rule(
        SOURCE_CHAIN,
        vec![
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Drop(None),
        ],
        Some(tag),
    ));

    batch.add(NfListObject::Chain(hooked(
        NfFamily::INet,
        "forward",
        NfHook::Forward,
    )));

    // Checked before anything else, including established connections: an
    // address that has been returned to the pool may already be another
    // customer's, and a flow opened while it was still ours must not outlive
    // the assignment.
    batch.add(rule(
        "forward",
        vec![
            iif(GUEST_BRIDGE),
            Statement::Jump(JumpTarget {
                target: SOURCE_CHAIN.into(),
            }),
        ],
        None,
    ));

    // Clamped to the route's MTU rather than to a number decided here. A guest
    // that ignores path MTU discovery otherwise opens a connection that works
    // until the first large transfer and then hangs, which is a far worse
    // failure than a slightly small segment.
    batch.add(rule("forward", vec![clamp_mss()], None));

    batch.add(rule(
        "forward",
        vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                    key: "state".into(),
                    family: None,
                    dir: None,
                })),
                right: Expression::List(vec![
                    Expression::String("established".into()),
                    Expression::String("related".into()),
                ]),
                op: Operator::IN,
            }),
            Statement::Accept(None),
        ],
        None,
    ));

    // Out of the guest network and up the tunnel. Anything a guest sends is
    // LNVPS-addressed by the rule above, so there is nowhere else for it to go.
    batch.add(rule(
        "forward",
        vec![
            iif(GUEST_BRIDGE),
            oif(TUNNEL_INTERFACE),
            Statement::Accept(None),
        ],
        None,
    ));

    for v6 in [false, true] {
        let assigned = format!("@assigned{}", if v6 { "6" } else { "4" });
        // Back down the tunnel, but only to an address LNVPS actually placed
        // here. The route server should not be sending anything else, and if it
        // does, the node not delivering it is the cheaper mistake.
        batch.add(rule(
            "forward",
            vec![
                iif(TUNNEL_INTERFACE),
                oif(GUEST_BRIDGE),
                daddr_in(v6, &assigned),
                Statement::Accept(None),
            ],
            None,
        ));
        // Two guests on this node, routed rather than bridged. They can reach
        // each other from different nodes, so refusing it here would make the
        // network behave differently depending on where LNVPS happened to
        // place them.
        batch.add(rule(
            "forward",
            vec![
                iif(GUEST_BRIDGE),
                oif(GUEST_BRIDGE),
                daddr_in(v6, &assigned),
                Statement::Accept(None),
            ],
            None,
        ));
    }

    batch.add(NfListObject::Chain(hooked(
        NfFamily::INet,
        "input",
        NfHook::Input,
    )));
    batch.add(rule(
        "input",
        vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iif })),
                right: Expression::String("lo".into()),
                op: Operator::EQ,
            }),
            Statement::Accept(None),
        ],
        None,
    ));
    batch.add(rule(
        "input",
        vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::CT(nftables::expr::CT {
                    key: "state".into(),
                    family: None,
                    dir: None,
                })),
                right: Expression::List(vec![
                    Expression::String("established".into()),
                    Expression::String("related".into()),
                ]),
                op: Operator::IN,
            }),
            Statement::Accept(None),
        ],
        None,
    ));
    batch.add(rule(
        "input",
        vec![
            iif(GUEST_BRIDGE),
            Statement::Jump(JumpTarget {
                target: SOURCE_CHAIN.into(),
            }),
        ],
        None,
    ));
    // The guest's own gateway: it must be able to resolve and ping it, or it
    // has no working network and no way to say so. Neighbour discovery is not
    // optional the way ICMPv4 arguably is — without it IPv6 does not function
    // at all — and the same two rules serve the route server, which has to
    // prove the node is reachable before customers are placed on it.
    for interface in [GUEST_BRIDGE, TUNNEL_INTERFACE] {
        batch.add(rule(
            "input",
            vec![iif(interface), icmp_types(false), Statement::Accept(None)],
            None,
        ));
        batch.add(rule(
            "input",
            vec![iif(interface), icmp_types(true), Statement::Accept(None)],
            None,
        ));
    }

    // LNVPS reaching the node itself: the control API and the libvirtd it
    // drives, both of which exist only inside the tunnel.
    //
    // Without these the node is unreachable for everything except ping, which
    // is a state it can stay in indefinitely while looking healthy: the tunnel
    // is up, handshakes happen, and every call LNVPS makes to it times out.
    //
    // Bound to the tunnel interface, never the guest bridge. The bridge shares
    // this namespace with the tunnel, so a customer VM can address the node's
    // inner address — and libvirtd on that address is root on the machine.
    for port in [CONTROL_PORT, LIBVIRT_TLS_PORT] {
        batch.add(rule(
            "input",
            vec![
                iif(TUNNEL_INTERFACE),
                Statement::Match(Match {
                    left: field("tcp", "dport"),
                    right: Expression::Number(port as u32),
                    op: Operator::EQ,
                }),
                Statement::Accept(None),
            ],
            None,
        ));
    }

    // A second table, in the bridge family, because layer 2 is a different path
    // through the kernel: a frame from one guest to another never reaches the
    // forward hook above.
    batch.add(NfListObject::Chain(hooked(
        NfFamily::Bridge,
        "forward",
        NfHook::Forward,
    )));

    batch.to_nftables()
}

/// A named set, empty when there is nothing in it.
///
/// Every node looks like that on its first day, and the rules referring to the
/// set still load and match nothing — which is the correct behaviour for a node
/// with no guests, and better than a ruleset that only exists once a customer
/// arrives.
fn set(
    name: &str,
    set_type: SetTypeValue<'static>,
    elements: Vec<Expression<'static>>,
) -> Set<'static> {
    Set {
        family: NfFamily::INet,
        table: TABLE.into(),
        name: name.to_string().into(),
        handle: None,
        set_type,
        policy: None,
        flags: None,
        // `None` rather than an empty list: nftables rejects an empty element
        // expression, and a node with no guests — every node, on its first day
        // — must still get a working ruleset.
        elem: (!elements.is_empty()).then(|| elements.into()),
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }
}

/// A chain the kernel calls, dropping anything no rule accepted.
fn hooked(family: NfFamily, name: &str, hook: NfHook) -> Chain<'static> {
    Chain {
        family,
        table: TABLE.into(),
        name: name.to_string().into(),
        newname: None,
        handle: None,
        dev: None,
        _type: Some(NfChainType::Filter),
        hook: Some(hook),
        prio: Some(0),
        policy: Some(NfChainPolicy::Drop),
    }
}

fn rule(
    chain: &str,
    expr: Vec<Statement<'static>>,
    comment: Option<String>,
) -> NfListObject<'static> {
    NfListObject::Rule(Rule {
        family: NfFamily::INet,
        table: TABLE.into(),
        chain: chain.to_string().into(),
        expr: expr.into(),
        handle: None,
        index: None,
        comment: comment.map(Into::into),
    })
}

fn field(protocol: &str, name: &str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: protocol.to_string().into(),
            field: name.to_string().into(),
        },
    )))
}

fn protocol(v6: bool) -> &'static str {
    if v6 { "ip6" } else { "ip" }
}

fn address_type(v6: bool) -> nftables::schema::SetType {
    if v6 {
        nftables::schema::SetType::Ipv6Addr
    } else {
        nftables::schema::SetType::Ipv4Addr
    }
}

fn iif(name: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::String(name.to_string().into()),
        op: Operator::EQ,
    })
}

fn oif(name: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Oifname,
        })),
        right: Expression::String(name.to_string().into()),
        op: Operator::EQ,
    })
}

fn daddr_in(v6: bool, set: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: field(protocol(v6), "daddr"),
        right: Expression::String(set.to_string().into()),
        op: Operator::EQ,
    })
}

/// The port the node's control API listens on, which LNVPS dials.
///
/// Stated here as well as in [`crate::config`] because the filter has to agree
/// with the listener it lets through, and both are fleet-wide: an operator who
/// moves either makes their own node unreachable, which is self-correcting.
pub const CONTROL_PORT: u16 = 8890;

/// The port a node's libvirtd serves TLS on.
///
/// Stated here as well as in [`crate::libvirt`] because the filter has to agree
/// with the daemon it lets through, and a port read from a config file the
/// operator can edit would be a filter hole they can widen.
pub const LIBVIRT_TLS_PORT: u16 = crate::libvirt::TLS_PORT;

/// `tcp option maxseg size set rt mtu`, for SYNs only.
fn clamp_mss() -> Statement<'static> {
    Statement::Mangle(nftables::stmt::Mangle {
        key: Expression::Named(NamedExpression::TcpOption(nftables::expr::TcpOption {
            name: "maxseg".into(),
            field: Some("size".into()),
        })),
        value: Expression::Named(NamedExpression::RT(nftables::expr::RT {
            key: nftables::expr::RTKey::MTU,
            family: None,
        })),
    })
}

/// The ICMP types a guest and the route server are allowed to send us.
fn icmp_types(v6: bool) -> Statement<'static> {
    let types = if v6 {
        vec![
            "echo-request",
            "nd-neighbor-solicit",
            "nd-neighbor-advert",
            "nd-router-solicit",
        ]
    } else {
        vec!["echo-request"]
    };
    // An anonymous set, not a list: nftables reads a list as a bitmask, and an
    // ICMP type is an enumeration rather than flags — it rejects the ruleset
    // outright, which is the good outcome compared with matching nothing.
    Statement::Match(Match {
        left: field(if v6 { "icmpv6" } else { "icmp" }, "type"),
        right: Expression::Named(NamedExpression::Set(
            types
                .into_iter()
                .map(|t| nftables::expr::SetItem::Element(Expression::String(t.to_string().into())))
                .collect(),
        )),
        op: Operator::EQ,
    })
}

/// A machine with no packet filter at all.
///
/// The counterpart of [`crate::net::UnavailableKernel`], and not a mock: it is
/// what a node looks like before anything has been installed on it, and
/// reporting that truthfully is what makes the health gate say "this node
/// cannot filter its guests" rather than assuming it can.
pub struct UnavailableFirewall;

#[async_trait]
impl FirewallOps for UnavailableFirewall {
    async fn available(&self) -> bool {
        false
    }

    async fn apply(&self, _ruleset: &Nftables<'_>) -> Result<()> {
        bail!("This machine has no nftables")
    }

    async fn ruleset(&self) -> Result<Nftables<'static>> {
        bail!("This machine has no nftables")
    }
}

pub use system::SystemFirewall;

mod system {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    use super::*;
    use crate::netns;

    /// The machine's own nftables, inside the data plane namespace.
    ///
    /// Inside, because a ruleset loaded in the machine's namespace would filter
    /// the operator's traffic and not a single guest packet — the guests are
    /// not there. nftables has no "in this namespace" argument, and the
    /// [`nftables`] crate's own helpers spawn on whichever thread the runtime
    /// picks, so the process is started from a thread that has already entered
    /// the namespace and inherits it.
    pub struct SystemFirewall {
        namespace: netns::Handle,
    }

    impl SystemFirewall {
        pub fn new(namespace: netns::Handle) -> Self {
            Self { namespace }
        }

        /// Run `nft -j` with the given arguments, in the namespace.
        fn nft(&self, args: &[&str], stdin: String) -> Result<String> {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            self.namespace.enter(move || {
                let mut child = Command::new("nft")
                    .arg("-j")
                    .args(&args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .context("Cannot run nft")?;
                child
                    .stdin
                    .take()
                    .expect("stdin was piped")
                    .write_all(stdin.as_bytes())
                    .context("Cannot write a ruleset to nft")?;
                let out = child.wait_with_output().context("Cannot run nft")?;
                if !out.status.success() {
                    // nftables' own complaint, not ours: it names the offending
                    // expression, which an exit code does not.
                    bail!(
                        "nft failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            })
        }
    }

    #[async_trait]
    impl FirewallOps for SystemFirewall {
        async fn available(&self) -> bool {
            // Run it rather than looking for it on `PATH`: the question is
            // whether it works, and an `nft` that cannot reach its kernel
            // module is an `nft` this node does not have.
            self.nft(&["list", "ruleset"], String::new()).is_ok()
        }

        async fn apply(&self, ruleset: &Nftables<'_>) -> Result<()> {
            let payload = serde_json::to_string(ruleset).context("Cannot encode the ruleset")?;
            self.nft(&["-f", "-"], payload)?;
            Ok(())
        }

        async fn ruleset(&self) -> Result<Nftables<'static>> {
            let listed = self.nft(&["list", "ruleset"], String::new())?;
            serde_json::from_str(&listed).context("Cannot read the machine's ruleset")
        }
    }
}

#[cfg(test)]
pub mod tests;
