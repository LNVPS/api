//! What the filter decides, tested without root.
//!
//! Whether the rules actually drop a spoofing guest is proved by
//! `lnvps_e2e/tests/tunnel_netns.rs`, which loads them into a real kernel and
//! sends real packets. What is worth asserting here is the reasoning: which
//! addresses are admitted, in what order the checks happen, and what the node
//! says about machines that cannot filter.
//!
//! The assertions read the same typed objects the kernel is sent, so a test
//! that passes is a test about the ruleset rather than about a string.

use std::sync::Mutex;

use nftables::schema::{NfCmd, NfObject};

use super::*;
use crate::net::{DesiredDataPlane, DesiredGuest, DesiredTunnel};

/// A machine with nftables, holding whatever was last loaded onto it.
#[derive(Default)]
pub struct FakeFirewall {
    /// Whether this machine has a working nftables at all.
    pub has_nft: bool,
    loaded: Mutex<Vec<NfObject<'static>>>,
    /// How many times a ruleset has been loaded, which is how "nothing changed"
    /// is told apart from "changed to the same thing".
    pub loads: Mutex<usize>,
}

impl FakeFirewall {
    pub fn with_nft() -> Self {
        Self {
            has_nft: true,
            ..Default::default()
        }
    }

    /// The objects the kernel would be holding: what a transaction added, less
    /// what it deleted. Enough for observation to be tested against the same
    /// shape the real thing returns.
    fn kernel_view(commands: &Nftables<'_>) -> Vec<NfObject<'static>> {
        let mut out = Vec::new();
        for object in commands.objects.iter() {
            match object {
                NfObject::CmdObject(NfCmd::Add(list)) => {
                    out.push(NfObject::ListObject(clone_static(list)))
                }
                NfObject::CmdObject(NfCmd::Delete(_)) => out.clear(),
                _ => {}
            }
        }
        out
    }

    fn objects(&self) -> Vec<NfObject<'static>> {
        self.loaded.lock().unwrap().clone()
    }
}

/// The schema borrows, and a fake machine has to own what it was given.
fn clone_static(object: &NfListObject<'_>) -> NfListObject<'static> {
    let json = serde_json::to_string(object).expect("the schema round-trips");
    serde_json::from_str(&json).expect("the schema round-trips")
}

#[async_trait]
impl FirewallOps for FakeFirewall {
    async fn available(&self) -> bool {
        self.has_nft
    }

    async fn apply(&self, ruleset: &Nftables<'_>) -> Result<()> {
        if !self.has_nft {
            bail!("no nftables on this machine");
        }
        *self.loaded.lock().unwrap() = Self::kernel_view(ruleset);
        *self.loads.lock().unwrap() += 1;
        Ok(())
    }

    async fn ruleset(&self) -> Result<Nftables<'static>> {
        Ok(Nftables {
            objects: self.objects().into(),
        })
    }
}

fn desired(guests: Vec<DesiredGuest>) -> DesiredDataPlane {
    DesiredDataPlane {
        tunnel: DesiredTunnel {
            address4: Some("10.66.0.2/32".to_string()),
            address6: None,
            gateway4: None,
            gateway6: None,
            server_public_key: "0".repeat(64),
            endpoint: "198.51.100.1:51820".to_string(),
            keepalive: Some(25),
            mtu: 1420,
        },
        gateways: vec!["203.0.113.1".to_string()],
        guests,
    }
}

fn guest(address: &str, mac: Option<&str>) -> DesiredGuest {
    DesiredGuest {
        address: address.to_string(),
        gateway: "203.0.113.1".to_string(),
        mac: mac.map(|m| m.to_string()),
    }
}

fn policy(guests: Vec<DesiredGuest>) -> Policy {
    Policy::from_desired(&desired(guests)).unwrap()
}

/// The rules in one chain, in the order the kernel will evaluate them.
fn chain_rules<'a, 'b>(
    objects: &'a [NfObject<'b>],
    family: NfFamily,
    chain: &str,
) -> Vec<&'a Rule<'b>> {
    objects
        .iter()
        .filter_map(|o| match o {
            NfObject::ListObject(NfListObject::Rule(r))
                if r.chain == chain && r.family == family =>
            {
                Some(r)
            }
            NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r)))
                if r.chain == chain && r.family == family =>
            {
                Some(r)
            }
            _ => None,
        })
        .collect()
}

fn set_elements(objects: &[NfObject<'_>], name: &str) -> Vec<String> {
    objects
        .iter()
        .filter_map(|o| match o {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) if s.name == name => Some(s),
            NfObject::ListObject(NfListObject::Set(s)) if s.name == name => Some(s),
            _ => None,
        })
        .flat_map(|s| s.elem.iter().flat_map(|e| e.iter()))
        .map(|e| serde_json::to_string(e).unwrap())
        .collect()
}

/// The policy is LNVPS's list, not the node's view of its own bridge: a node
/// that authorised whatever it found attached would authorise whatever the
/// operator attached.
#[test]
fn the_policy_comes_from_the_document() {
    let policy = policy(vec![
        guest("203.0.113.5", Some("AA:BB:CC:DD:EE:FF")),
        guest("2001:db8::5", None),
    ]);

    assert_eq!(policy.bindings.len(), 2);
    // Lower-cased, because that is how nftables states a MAC, and a ruleset
    // that differs from the machine's only by case reads as drift on every
    // single comparison.
    assert_eq!(
        policy.bindings[0].mac.as_deref(),
        Some("aa:bb:cc:dd:ee:ff"),
        "{policy:?}"
    );
}

/// An address with a prefix is still an address. LNVPS sends guest addresses
/// both ways depending on the range, and a filter that only understood one form
/// would silently drop that guest's traffic.
#[test]
fn a_guest_address_may_carry_a_prefix() {
    let policy = policy(vec![guest("203.0.113.5/24", None)]);
    assert_eq!(policy.bindings[0].address.to_string(), "203.0.113.5");
}

/// A malformed address is named rather than skipped: quietly dropping the guest
/// from the policy would leave it running with no filter entry at all, which
/// fails open.
#[test]
fn a_malformed_address_is_refused() {
    let err = Policy::from_desired(&desired(vec![guest("not-an-address", None)])).unwrap_err();
    assert!(err.to_string().contains("not-an-address"), "{err}");
}

/// A guest LNVPS gave a MAC is held to the pair; one without is admitted on
/// address alone, and visibly in the weaker set rather than through a hole in
/// the strong one.
#[test]
fn a_mac_binds_the_address_to_it() {
    let objects = ruleset(&policy(vec![
        guest("203.0.113.5", Some("aa:bb:cc:dd:ee:ff")),
        guest("203.0.113.6", None),
    ]))
    .objects
    .to_vec();

    let bound = set_elements(&objects, "bound4");
    assert_eq!(bound.len(), 1, "{bound:?}");
    assert!(bound[0].contains("aa:bb:cc:dd:ee:ff") && bound[0].contains("203.0.113.5"));

    let unbound = set_elements(&objects, "guest4");
    assert_eq!(unbound, vec!["\"203.0.113.6\"".to_string()]);

    // Both are deliverable to; only one may claim the stronger check.
    assert_eq!(set_elements(&objects, "assigned4").len(), 2);
}

/// The transaction deletes before it rebuilds, and adds the table first so the
/// delete has something to delete — otherwise the very first run on a freshly
/// booted node fails, which is the run that matters most.
#[test]
fn the_ruleset_is_replaced_atomically() {
    let objects = ruleset(&Policy::default()).objects.to_vec();
    let table_ops: Vec<&'static str> = objects
        .iter()
        .filter_map(|o| match o {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(_))) => Some("add"),
            NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(_))) => Some("delete"),
            _ => None,
        })
        .collect();
    assert_eq!(
        table_ops,
        vec!["add", "delete", "add", "add", "delete", "add"],
        "one family's table, then the other's"
    );
}

/// A node with no guests still gets a complete, working ruleset. Every node
/// looks like this on its first day, and a filter that only appeared once a
/// customer arrived would leave the first one unprotected.
#[test]
fn a_node_with_no_guests_still_loads() {
    let objects = ruleset(&Policy::default()).objects.to_vec();
    assert!(!chain_rules(&objects, NfFamily::INet, "forward").is_empty());
    assert!(set_elements(&objects, "assigned4").is_empty());
}

/// Anti-spoof is checked before conntrack. An address that has gone back in the
/// pool may already be someone else's, and a flow opened while it was still
/// this guest's must not outlive the assignment.
#[test]
fn spoofing_is_checked_before_established_connections() {
    let objects = ruleset(&Policy::default()).objects.to_vec();
    let forward = chain_rules(&objects, NfFamily::INet, "forward");

    let jump = forward
        .iter()
        .position(|r| r.expr.iter().any(|s| matches!(s, Statement::Jump(_))))
        .expect("guest traffic is checked");
    let conntrack = forward
        .iter()
        .position(|r| {
            serde_json::to_string(&r.expr)
                .unwrap()
                .contains("established")
        })
        .expect("established connections are accepted");
    assert!(jump < conntrack, "{forward:#?}");
}

/// Layer 2 is a different path through the kernel: a frame from one guest to
/// another never reaches the forward hook, so proxy ARP would otherwise let a
/// tenant poison their neighbours.
#[test]
fn guests_are_isolated_from_each_other_at_layer_two() {
    let objects = ruleset(&Policy::default()).objects.to_vec();
    let bridge = objects.iter().find_map(|o| match o {
        NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) if c.family == NfFamily::Bridge => {
            Some(c)
        }
        _ => None,
    });
    let bridge = bridge.expect("a bridge chain");
    assert_eq!(bridge.hook, Some(NfHook::Forward));
    assert_eq!(bridge.policy, Some(NfChainPolicy::Drop));
}

/// Clamped to the route's MTU rather than to a number decided when the rules
/// were built: the tunnel's MTU can change under the filter, and a stale clamp
/// hangs large transfers exactly like no clamp at all.
#[test]
fn the_mss_is_clamped_to_the_path() {
    let objects = ruleset(&Policy::default()).objects.to_vec();
    let mangle = chain_rules(&objects, NfFamily::INet, "forward")
        .iter()
        .any(|r| {
            r.expr.iter().any(|s| {
                matches!(s, Statement::Mangle(m) if serde_json::to_string(&m.value).unwrap().contains("mtu"))
            })
        });
    assert!(mangle, "{objects:#?}");
}

/// Return traffic is delivered only to addresses LNVPS placed here, and a guest
/// can reach a neighbour on the same node because it could reach one on a
/// different node. A network that behaved differently depending on where LNVPS
/// happened to place a VM would be a network nobody could reason about.
#[test]
fn only_assigned_addresses_are_delivered() {
    let objects = ruleset(&policy(vec![guest("203.0.113.5", None)]))
        .objects
        .to_vec();
    let accepts: Vec<String> = chain_rules(&objects, NfFamily::INet, "forward")
        .iter()
        .filter(|r| r.expr.iter().any(|s| matches!(s, Statement::Accept(_))))
        .map(|r| serde_json::to_string(&r.expr).unwrap())
        .collect();

    assert!(
        accepts.iter().any(|r| r.contains(TUNNEL_INTERFACE)
            && r.contains(GUEST_BRIDGE)
            && r.contains("@assigned4")),
        "{accepts:#?}"
    );
    assert!(
        accepts
            .iter()
            .any(|r| r.matches(GUEST_BRIDGE).count() == 2 && r.contains("@assigned4")),
        "two guests on one node should reach each other through it: {accepts:#?}"
    );
}

/// Neighbour discovery is accepted. ICMPv4 is arguably optional; ICMPv6 is not,
/// and a node that dropped it would report a configured tunnel with no working
/// IPv6 guest behind it.
#[test]
fn neighbour_discovery_survives() {
    let objects = ruleset(&Policy::default()).objects.to_vec();
    let input = serde_json::to_string(&chain_rules(&objects, NfFamily::INet, "input")).unwrap();
    assert!(input.contains("nd-neighbor-solicit"), "{input}");
    assert!(input.contains("echo-request"), "{input}");
}

/// A machine already running this exact ruleset is left alone. Reloading is
/// harmless — the swap is atomic — but a daemon that reported a change on every
/// poll would produce a log in which nothing can be noticed.
#[tokio::test]
async fn a_machine_already_filtered_is_left_alone() {
    let fake = FakeFirewall::with_nft();
    let policy = policy(vec![guest("203.0.113.5", None)]);

    assert!(!apply(&fake, &policy).await.unwrap().is_empty());
    assert!(apply(&fake, &policy).await.unwrap().is_empty());
    assert_eq!(*fake.loads.lock().unwrap(), 1);
}

/// A guest arriving or leaving changes the tag, so the next refresh reloads.
/// The tag is derived from the policy rather than from the built ruleset, so a
/// change in how the rules are expressed cannot masquerade as a change in who
/// is allowed.
#[test]
fn the_tag_follows_the_guests() {
    let none = fingerprint(&Policy::default());
    let one = fingerprint(&policy(vec![guest("203.0.113.5", None)]));
    let bound = fingerprint(&policy(vec![guest(
        "203.0.113.5",
        Some("aa:bb:cc:dd:ee:ff"),
    )]));

    assert_ne!(none, one);
    assert_ne!(one, bound, "binding a MAC is a different policy");
    assert!(none.starts_with("lnvps:"));
}

/// The tag is read back off the machine rather than remembered, so an operator
/// who flushes the table by hand gets it rebuilt on the next refresh instead of
/// the daemon insisting it is already there.
#[tokio::test]
async fn a_flushed_table_is_rebuilt() {
    let fake = FakeFirewall::with_nft();
    let policy = policy(vec![guest("203.0.113.5", None)]);
    apply(&fake, &policy).await.unwrap();

    *fake.loaded.lock().unwrap() = Vec::new();
    assert!(!apply(&fake, &policy).await.unwrap().is_empty());
    assert_eq!(*fake.loads.lock().unwrap(), 2);
}

/// A machine running someone else's idea of the ruleset — an older daemon, a
/// half-applied change — is reloaded rather than accepted.
#[tokio::test]
async fn a_stale_ruleset_is_replaced() {
    let fake = FakeFirewall::with_nft();
    apply(&fake, &policy(vec![guest("203.0.113.5", None)]))
        .await
        .unwrap();

    let changed = apply(&fake, &policy(vec![guest("203.0.113.6", None)]))
        .await
        .unwrap();
    assert!(!changed.is_empty(), "a different guest list must reload");
    assert_eq!(set_elements(&fake.objects(), "assigned4").len(), 1);
}

/// A machine with no nftables is refused outright rather than configured
/// without a filter: an unfiltered node is a node where one customer can be
/// another, and it is better for it to carry nobody.
#[tokio::test]
async fn a_machine_with_no_filter_is_refused() {
    let err = apply(&FakeFirewall::default(), &Policy::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no working nftables"), "{err}");
    assert!(err.to_string().contains("none will be placed"), "{err}");
}

/// Observation reads the machine, not what was applied: the case worth catching
/// is the one where the two disagree.
#[tokio::test]
async fn observation_reads_the_machine() {
    let fake = FakeFirewall::with_nft();
    let policy = policy(vec![
        guest("203.0.113.5", Some("aa:bb:cc:dd:ee:ff")),
        guest("2001:db8::5", None),
    ]);
    apply(&fake, &policy).await.unwrap();

    let state = observe(&fake).await;
    assert!(state.available);
    assert!(state.present);
    assert!(
        state.isolated,
        "the layer 2 table is part of being filtered"
    );
    assert_eq!(state.bindings, 2, "one guest per family");
    assert_eq!(state.ruleset, Some(fingerprint(&policy)));
    assert_eq!(state.spoofed_packets, 0, "nothing has lied yet");
}

/// A machine with nftables and no ruleset loaded reports exactly that, rather
/// than an error. It is the state a node is in before its first apply and after
/// somebody flushes the table by hand, and the health gate needs to tell it
/// apart from "no firewall at all".
#[tokio::test]
async fn an_unfiltered_machine_says_so() {
    let state = observe(&FakeFirewall::with_nft()).await;
    assert!(state.available);
    assert!(!state.present);
    assert!(!state.isolated);
    assert_eq!(state.ruleset, None);

    // ...and a machine with no nftables at all is a third, distinct answer.
    let state = observe(&FakeFirewall::default()).await;
    assert!(!state.available);
    assert!(!state.present);
}

/// The drop counter is read off the rule that carries the tag, so a counter
/// added elsewhere — by a later version of this file, or by an operator — is
/// never reported as a customer spoofing.
#[tokio::test]
async fn spoofed_packets_are_counted() {
    let fake = FakeFirewall::with_nft();
    apply(&fake, &Policy::default()).await.unwrap();

    // The kernel filling in a counter, which is what the real one returns.
    let mut objects = fake.objects();
    for object in objects.iter_mut() {
        if let NfObject::ListObject(NfListObject::Rule(rule)) = object {
            if rule.comment.is_some() {
                let mut expr = rule.expr.to_vec();
                expr[0] = Statement::Counter(Counter::Anonymous(Some(
                    nftables::stmt::AnonymousCounter {
                        packets: Some(42),
                        bytes: Some(3528),
                    },
                )));
                rule.expr = expr.into();
            }
        }
    }
    *fake.loaded.lock().unwrap() = objects;

    assert_eq!(observe(&fake).await.spoofed_packets, 42);
}

/// A machine with nothing installed reports that, rather than pretending. It is
/// the state every node is in before the operator has finished setting it up,
/// and the integration tests run against it because it needs no root.
#[tokio::test]
async fn an_unequipped_machine_is_honest() {
    let none = UnavailableFirewall;
    assert!(!none.available().await);
    assert!(none.apply(&ruleset(&Policy::default())).await.is_err());
    assert!(none.ruleset().await.is_err());
    assert_eq!(observe(&none).await, FirewallState::default());
}

/// A machine that cannot be read is reported as unfiltered, not as filtered.
/// Failing the other way would mean an unreadable node passing the health gate.
#[tokio::test]
async fn an_unreadable_machine_is_not_assumed_filtered() {
    struct Unreadable;

    #[async_trait]
    impl FirewallOps for Unreadable {
        async fn available(&self) -> bool {
            true
        }
        async fn apply(&self, _ruleset: &Nftables<'_>) -> Result<()> {
            Ok(())
        }
        async fn ruleset(&self) -> Result<Nftables<'static>> {
            bail!("nft: unable to talk to the kernel")
        }
    }

    // Loading works; it is only reading back that fails, which is the awkward
    // case — the daemon has every reason to believe it succeeded.
    Unreadable
        .apply(&ruleset(&Policy::default()))
        .await
        .unwrap();

    let state = observe(&Unreadable).await;
    assert!(state.available, "the tool is there");
    assert!(!state.present, "but nothing can be claimed about the rules");
}
