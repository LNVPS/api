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
//! never appends to an operator's chains: it renders a complete table and swaps
//! it, so there is no moment when a guest is running unfiltered and no way for
//! a half-applied ruleset to survive a crash.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::net::{DesiredDataPlane, GUEST_BRIDGE, TUNNEL_INTERFACE};

/// The name of everything this module owns, in every backend.
///
/// One name, so an operator looking at their own firewall can see at a glance
/// which parts are LNVPS's, and so the daemon can delete its own work without
/// having to remember what it created.
pub const TABLE: &str = "lnvps";

/// Which packet filter this machine has.
///
/// Marketplace hardware is hardware LNVPS did not choose: a current Debian has
/// `nft` and an older CentOS may only have `iptables`. Detected at runtime and
/// reported, so a node that filters differently from the fleet says so rather
/// than being assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Nft,
    Iptables,
}

impl Backend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::Nft => "nft",
            Backend::Iptables => "iptables",
        }
    }
}

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
                mac: guest.mac.as_ref().map(|m| m.to_lowercase()),
            });
        }
        bindings.sort();
        bindings.dedup();
        Ok(Self { bindings })
    }

    fn v4(&self) -> impl Iterator<Item = &Binding> {
        self.bindings.iter().filter(|b| b.address.is_ipv4())
    }

    fn v6(&self) -> impl Iterator<Item = &Binding> {
        self.bindings.iter().filter(|b| b.address.is_ipv6())
    }
}

/// What the filter currently is on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    /// `None` when the machine has no packet filter at all, which is a fact
    /// the health gate needs rather than an error to retry.
    pub backend: Option<Backend>,
    /// Whether LNVPS's ruleset is currently loaded.
    pub present: bool,
    /// Whether guest-to-guest traffic is blocked at layer 2.
    ///
    /// Separate from `present` because it is a separate mechanism — a second
    /// table in `nft`, a different program under `iptables` — and a node with
    /// IP filtering but no L2 isolation is a real state worth naming rather
    /// than rounding down to "filtered".
    pub isolated: bool,
    /// How many guest bindings the loaded ruleset enforces, for LNVPS's own
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

/// A short, stable name for a rendered ruleset.
///
/// Comparing this against the machine is what makes a refresh a no-op: the
/// alternative, reloading unconditionally every few seconds, is atomic and
/// therefore safe, but it means the daemon can never answer "did anything
/// change?" — and that answer is what an operator reads when something is
/// wrong.
pub fn fingerprint(policy: &Policy) -> String {
    policy_tag(policy)
}

/// Running the filter's own tools.
///
/// A trait for the same reason [`crate::net::NetOps`] is one: the rendering and
/// the decisions are worth testing without root, and the end-to-end harness
/// needs to drive the real thing inside a namespace.
#[async_trait]
pub trait FirewallOps: Send + Sync {
    /// Run `program` with `args`, writing `stdin` to it. `Err` for a non-zero
    /// exit, carrying the program's own complaint.
    async fn run(&self, program: &str, args: &[&str], stdin: &str) -> Result<String>;
    /// Whether `program` exists and runs on this machine.
    async fn available(&self, program: &str) -> bool;
}

/// Which backend to use, preferring `nft`.
///
/// `nft` first because it can replace a whole table atomically and express the
/// layer 2 rule in the same tool; `iptables` is the compatibility answer for
/// machines that do not have it. `None` is reported rather than raised: a node
/// with no packet filter is not a node with a broken one, and the difference
/// matters to the operator reading the message.
pub async fn detect(ops: &dyn FirewallOps) -> Option<Backend> {
    if ops.available("nft").await {
        Some(Backend::Nft)
    } else if ops.available("iptables-restore").await {
        Some(Backend::Iptables)
    } else {
        None
    }
}

/// Load `policy` onto the machine, replacing whatever was there before.
///
/// A machine already running this exact ruleset is left alone. Reloading would
/// be harmless — every backend here swaps atomically — but it would mean the
/// daemon reported a change on every poll, and a log where everything changes
/// constantly is a log in which nothing can be noticed.
pub async fn apply(ops: &dyn FirewallOps, policy: &Policy) -> Result<Vec<String>> {
    let Some(backend) = detect(ops).await else {
        bail!(
            "This machine has neither nft nor iptables, so guests cannot be \
             filtered and none will be placed here"
        );
    };
    if observe(ops).await.ruleset.as_deref() == Some(policy_tag(policy).as_str()) {
        return Ok(Vec::new());
    }
    match backend {
        Backend::Nft => apply_nft(ops, policy).await,
        Backend::Iptables => apply_iptables(ops, policy).await,
    }
}

async fn apply_nft(ops: &dyn FirewallOps, policy: &Policy) -> Result<Vec<String>> {
    ops.run("nft", &["-f", "-"], &render_nft(policy))
        .await
        .context("Cannot load the nftables ruleset")?;
    Ok(vec![format!(
        "loaded nft table inet {TABLE} with {} guest bindings",
        policy.bindings.len()
    )])
}

async fn apply_iptables(ops: &dyn FirewallOps, policy: &Policy) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    ops.run("iptables-restore", &[], &render_iptables(policy, false))
        .await
        .context("Cannot load the iptables ruleset")?;
    changed.push(format!(
        "loaded iptables chains for {} guest bindings",
        policy.v4().count()
    ));

    // IPv6 is a separate program with a separate ruleset, and a machine may
    // have one and not the other. Missing IPv6 is not a failure — a v4-only
    // node is a working node — but silently leaving v6 unfiltered would be, so
    // it is only skipped when the tool genuinely is not there.
    if ops.available("ip6tables-restore").await {
        ops.run("ip6tables-restore", &[], &render_iptables(policy, true))
            .await
            .context("Cannot load the ip6tables ruleset")?;
        changed.push(format!(
            "loaded ip6tables chains for {} guest bindings",
            policy.v6().count()
        ));
    }

    // Layer 2 isolation is a third program under this backend. Without it
    // guests can still reach each other directly on the bridge, so the node
    // says so rather than reporting a filter it does not have.
    if ops.available("ebtables").await {
        ops.run("ebtables", &["-P", "FORWARD", "DROP"], "")
            .await
            .context("Cannot isolate guests from each other")?;
        changed.push("isolated guests at layer 2 with ebtables".to_string());
    } else {
        changed.push("no ebtables: guests are not isolated from each other at layer 2".to_string());
    }
    Ok(changed)
}

/// Read the loaded ruleset back.
pub async fn observe(ops: &dyn FirewallOps) -> FirewallState {
    let backend = detect(ops).await;
    match backend {
        Some(Backend::Nft) => {
            let listed = ops
                .run("nft", &["list", "table", "inet", TABLE], "")
                .await
                .unwrap_or_default();
            FirewallState {
                backend,
                present: listed.contains("hook forward"),
                ruleset: loaded_tag(&listed),
                spoofed_packets: nft_counter(&listed),
                isolated: ops
                    .run("nft", &["list", "table", "bridge", TABLE], "")
                    .await
                    .map(|out| out.contains("policy drop"))
                    .unwrap_or(false),
                bindings: count_elements(&listed),
            }
        }
        Some(Backend::Iptables) => {
            let listed = ops
                // `-c` because the counters are the point of reading it back;
                // without them this is a dump of what the daemon already knows.
                .run("iptables-save", &["-c", "-t", "filter"], "")
                .await
                .unwrap_or_default();
            FirewallState {
                backend,
                present: listed.contains(&format!("{TABLE}-source")),
                ruleset: loaded_tag(&listed),
                spoofed_packets: iptables_counter(&listed),
                isolated: ops
                    .run("ebtables", &["-L", "FORWARD"], "")
                    .await
                    .map(|out| out.contains("policy: DROP"))
                    .unwrap_or(false),
                bindings: listed
                    .lines()
                    .filter(|l| l.contains(&format!("-A {TABLE}-source")) && l.contains("-s "))
                    .count(),
            }
        }
        None => FirewallState::default(),
    }
}

/// The ruleset tag the machine is carrying, from a rule comment.
///
/// Read out of the dump rather than remembered, so an operator who flushes the
/// table by hand gets it rebuilt on the next refresh instead of the daemon
/// insisting it is already there.
fn loaded_tag(listed: &str) -> Option<String> {
    listed
        .split("lnvps:")
        .nth(1)
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
        })
        .filter(|tag| !tag.is_empty())
}

/// The spoof counter from an `nft list table` dump.
///
/// Taken from the line that also carries our tag, so a counter added to some
/// other rule — by a future version of this file, or by an operator — is not
/// reported as spoofing.
fn nft_counter(listed: &str) -> u64 {
    listed
        .lines()
        .find(|l| l.contains("lnvps:") && l.contains("counter"))
        .and_then(|l| {
            let rest = l.split("packets ").nth(1)?;
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0)
}

/// The same, from `iptables-save -c`, where counters lead the rule as `[p:b]`.
fn iptables_counter(listed: &str) -> u64 {
    listed
        .lines()
        .find(|l| l.contains(&format!("-A {TABLE}-source")) && l.contains("-j DROP"))
        .and_then(|l| l.trim().strip_prefix('[')?.split(':').next()?.parse().ok())
        .unwrap_or(0)
}

/// Count the guest addresses in an `nft list table` dump.
///
/// The elements are counted rather than the rules, because the rules are a
/// fixed skeleton: what changes as guests come and go is the set contents, and
/// that is the number worth comparing against LNVPS's document.
fn count_elements(listed: &str) -> usize {
    let mut total = 0;
    let mut in_set = false;
    for line in listed.lines() {
        let line = line.trim();
        if line.starts_with("set ") || line.starts_with("map ") {
            in_set = true;
        } else if in_set && line == "}" {
            in_set = false;
        } else if in_set && line.starts_with("elements = {") {
            total += line.matches(',').count() + 1;
        } else if in_set && (line.contains(" . ") || line.contains(',')) && !line.contains("type") {
            total += line.matches(',').count();
        }
    }
    total
}

/// The whole nftables ruleset, as one atomic transaction.
///
/// `nft -f` applies a file in a single transaction, so the `delete` and the
/// rebuild either both happen or neither does. The alternative — flushing then
/// adding — leaves a window in which guests are unfiltered, which on a machine
/// carrying other people's customers is not a window worth having.
pub fn render_nft(policy: &Policy) -> String {
    render_nft_tagged(policy, &policy_tag(policy))
}

/// The tag a rendered ruleset carries, derived from the policy alone.
///
/// Not from the rendered text, which would be circular: the text contains the
/// tag.
fn policy_tag(policy: &Policy) -> String {
    let joined = policy
        .bindings
        .iter()
        .map(|b| format!("{}@{}", b.address, b.mac.as_deref().unwrap_or("-")))
        .collect::<Vec<_>>()
        .join(",");
    crate::control_auth::sha256_hex(joined.as_bytes())[..16].to_string()
}

fn render_nft_tagged(policy: &Policy, tag: &str) -> String {
    let mut out = String::new();

    // `table` before `delete table` so the delete has something to delete: nft
    // fails a transaction that deletes what does not exist, which would mean
    // the very first run of a freshly booted node always errored.
    let _ = writeln!(out, "table inet {TABLE} {{}}");
    let _ = writeln!(out, "delete table inet {TABLE}");
    let _ = writeln!(out, "table inet {TABLE} {{");

    render_nft_set(
        &mut out,
        "bound4",
        "ether_addr . ipv4_addr",
        bound(policy, false),
    );
    render_nft_set(
        &mut out,
        "bound6",
        "ether_addr . ipv6_addr",
        bound(policy, true),
    );
    render_nft_set(&mut out, "guest4", "ipv4_addr", unbound(policy, false));
    render_nft_set(&mut out, "guest6", "ipv6_addr", unbound(policy, true));
    render_nft_set(&mut out, "assigned4", "ipv4_addr", addresses(policy, false));
    render_nft_set(&mut out, "assigned6", "ipv6_addr", addresses(policy, true));

    let _ = write!(
        out,
        r#"
    chain source {{
        ether saddr . ip saddr @bound4 return
        ether saddr . ip6 saddr @bound6 return
        ip saddr @guest4 return
        ip6 saddr @guest6 return
        counter drop comment "lnvps:{tag}"
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;

        # Checked before anything else, including established connections: an
        # address that has been returned to the pool may already be another
        # customer's, and a flow opened while it was still ours must not
        # outlive the assignment.
        iifname "{GUEST_BRIDGE}" jump source

        # Clamped to the route's MTU rather than a number written down here.
        # A guest that ignores path MTU discovery otherwise opens a connection
        # that works until the first large transfer and then hangs, which is a
        # much worse failure than a slightly small segment.
        tcp flags syn / syn,rst tcp option maxseg size set rt mtu

        ct state established,related accept

        # Out of the guest network, up the tunnel. Anything a guest sends is
        # LNVPS-addressed by the rule above, so there is nowhere else for it.
        iifname "{GUEST_BRIDGE}" oifname "{TUNNEL_INTERFACE}" accept

        # Back down, but only to an address LNVPS actually placed here. The
        # route server should not be sending anything else, and if it does, the
        # node not delivering it is the cheaper mistake.
        iifname "{TUNNEL_INTERFACE}" oifname "{GUEST_BRIDGE}" ip daddr @assigned4 accept
        iifname "{TUNNEL_INTERFACE}" oifname "{GUEST_BRIDGE}" ip6 daddr @assigned6 accept

        # Two guests on this node, routed rather than bridged. They can reach
        # each other from different nodes, so refusing it here would make the
        # network behave differently depending on where LNVPS happened to place
        # them.
        iifname "{GUEST_BRIDGE}" oifname "{GUEST_BRIDGE}" ip daddr @assigned4 accept
        iifname "{GUEST_BRIDGE}" oifname "{GUEST_BRIDGE}" ip6 daddr @assigned6 accept
    }}

    chain input {{
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept

        # The guest's own gateway: it must be able to resolve and ping it, or
        # it has no working network and no way to say so. ICMPv6 is not
        # optional the way ICMPv4 arguably is — without neighbour discovery
        # IPv6 does not function at all.
        iifname "{GUEST_BRIDGE}" jump source
        iifname "{GUEST_BRIDGE}" icmp type {{ echo-request }} accept
        iifname "{GUEST_BRIDGE}" icmpv6 type {{ echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept

        # The tunnel, so the route server can prove the node is reachable
        # before customers are placed on it.
        iifname "{TUNNEL_INTERFACE}" icmp type {{ echo-request }} accept
        iifname "{TUNNEL_INTERFACE}" icmpv6 type {{ echo-request, nd-neighbor-solicit, nd-neighbor-advert }} accept
    }}
}}

# A second table, in the bridge family, because layer 2 is a different path
# through the kernel: a frame from one guest to another never reaches the
# forward hook above. Guests share a bridge and proxy ARP tells each of them
# that every address is on-link, so without this a tenant can ARP-poison or
# ND-poison their neighbours. Dropping the bridge's forward hook does not cut
# them off from each other — it forces their traffic through the node, which is
# where it can be checked.
table bridge {TABLE} {{}}
delete table bridge {TABLE}
table bridge {TABLE} {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}
}}
"#
    );
    out
}

/// A set, or a comment saying why there is not one.
///
/// nft rejects an empty `elements = {{ }}`, and a node with no guests yet — every
/// node, on its first day — must still get a working ruleset. The set is
/// declared empty in that case, so the rules referring to it still load and
/// match nothing, which is the correct behaviour for a node with no guests.
fn render_nft_set(out: &mut String, name: &str, kind: &str, elements: Vec<String>) {
    let _ = writeln!(out, "    set {name} {{");
    let _ = writeln!(out, "        type {kind}");
    if !elements.is_empty() {
        let _ = writeln!(out, "        elements = {{ {} }}", elements.join(", "));
    }
    let _ = writeln!(out, "    }}");
}

/// `mac . address` pairs, for guests LNVPS gave a MAC.
fn bound(policy: &Policy, v6: bool) -> Vec<String> {
    policy
        .bindings
        .iter()
        .filter(|b| b.address.is_ipv6() == v6)
        .filter_map(|b| b.mac.as_ref().map(|m| format!("{m} . {}", b.address)))
        .collect()
}

/// Addresses for guests with no MAC, which are allowed on address alone.
///
/// Weaker, and deliberately a separate set rather than a hole in the strong
/// one: it is visible in the loaded ruleset which guests are held to which
/// standard.
fn unbound(policy: &Policy, v6: bool) -> Vec<String> {
    policy
        .bindings
        .iter()
        .filter(|b| b.address.is_ipv6() == v6 && b.mac.is_none())
        .map(|b| b.address.to_string())
        .collect()
}

/// Every assigned address, however it is bound.
fn addresses(policy: &Policy, v6: bool) -> Vec<String> {
    policy
        .bindings
        .iter()
        .filter(|b| b.address.is_ipv6() == v6)
        .map(|b| b.address.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The same policy for `iptables-restore`.
///
/// One rule per guest rather than an `ipset`: that is another package which may
/// not be installed, and a node's guest count is small enough that a linear
/// chain costs nothing measurable.
///
/// The built-in chains are written directly, and the file is loaded *without*
/// `--noflush`, which replaces the whole table in one atomic call. On any other
/// machine that would be unforgivable — it would erase the operator's own
/// firewall — but this table lives in the data plane namespace, where the only
/// rules that have ever existed are these. It is also what makes the refresh
/// idempotent: appending to `FORWARD` on every poll leaves a node that has been
/// up for a month carrying a month of duplicate jumps.
pub fn render_iptables(policy: &Policy, v6: bool) -> String {
    let tag = policy_tag(policy);
    let host = if v6 { 128 } else { 32 };
    let icmp = if v6 { "icmpv6" } else { "icmp" };
    let source = format!("{TABLE}-source");
    let mut out = String::from("*filter\n");
    let _ = writeln!(out, ":INPUT DROP [0:0]");
    let _ = writeln!(out, ":FORWARD DROP [0:0]");
    let _ = writeln!(out, ":OUTPUT ACCEPT [0:0]");
    let _ = writeln!(out, ":{source} - [0:0]");

    // Anti-spoof, as its own chain so the same check can be reached from both
    // the forward and the input path without being written twice and drifting.
    for binding in policy.bindings.iter().filter(|b| b.address.is_ipv6() == v6) {
        match &binding.mac {
            Some(mac) => {
                let _ = writeln!(
                    out,
                    "-A {source} -s {}/{host} -m mac --mac-source {mac} -j RETURN",
                    binding.address
                );
            }
            None => {
                let _ = writeln!(out, "-A {source} -s {}/{host} -j RETURN", binding.address);
            }
        }
    }
    let _ = writeln!(out, "-A {source} -m comment --comment lnvps:{tag} -j DROP");

    // Checked before conntrack, so a returned address stops working the moment
    // LNVPS reassigns it rather than when its connections happen to end.
    let _ = writeln!(out, "-A FORWARD -i {GUEST_BRIDGE} -j {source}");
    let _ = writeln!(
        out,
        "-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    );
    let _ = writeln!(
        out,
        "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    );
    let _ = writeln!(
        out,
        "-A FORWARD -i {GUEST_BRIDGE} -o {TUNNEL_INTERFACE} -j ACCEPT"
    );
    for binding in policy.bindings.iter().filter(|b| b.address.is_ipv6() == v6) {
        let _ = writeln!(
            out,
            "-A FORWARD -o {GUEST_BRIDGE} -d {}/{host} -j ACCEPT",
            binding.address
        );
    }

    let _ = writeln!(out, "-A INPUT -i lo -j ACCEPT");
    let _ = writeln!(
        out,
        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    );
    let _ = writeln!(out, "-A INPUT -i {GUEST_BRIDGE} -j {source}");
    let _ = writeln!(
        out,
        "-A INPUT -i {GUEST_BRIDGE} -p {icmp} --{icmp}-type echo-request -j ACCEPT"
    );
    let _ = writeln!(
        out,
        "-A INPUT -i {TUNNEL_INTERFACE} -p {icmp} --{icmp}-type echo-request -j ACCEPT"
    );
    if v6 {
        // Neighbour discovery is not optional the way ICMPv4 arguably is:
        // without it IPv6 does not function at all, so a node that dropped it
        // would report a configured tunnel and no working v6 guests.
        for kind in [
            "neighbour-solicitation",
            "neighbour-advertisement",
            "router-solicitation",
        ] {
            let _ = writeln!(out, "-A INPUT -p icmpv6 --icmpv6-type {kind} -j ACCEPT");
        }
    }
    let _ = writeln!(out, "COMMIT");
    out
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
    async fn run(&self, program: &str, _args: &[&str], _stdin: &str) -> Result<String> {
        bail!("{program} is not available on this machine")
    }

    async fn available(&self, _program: &str) -> bool {
        false
    }
}

pub use system::SystemFirewall;

mod system {
    use std::process::Stdio;

    use super::*;
    use crate::netns;

    /// The machine's own firewall tools, run inside the data plane namespace.
    ///
    /// Inside, because a ruleset loaded in the machine's namespace would filter
    /// the operator's traffic and not a single guest packet — the guests are
    /// not there. `nft` has no "in this namespace" flag, so the process is
    /// spawned from a thread that has already entered it and inherits it.
    pub struct SystemFirewall {
        namespace: netns::Handle,
    }

    impl SystemFirewall {
        pub fn new(namespace: netns::Handle) -> Self {
            Self { namespace }
        }
    }

    #[async_trait]
    impl FirewallOps for SystemFirewall {
        async fn run(&self, program: &str, args: &[&str], stdin: &str) -> Result<String> {
            let (program, stdin) = (program.to_string(), stdin.to_string());
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            self.namespace.enter(move || {
                let mut child = std::process::Command::new(&program)
                    .args(&args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("Cannot run {program}"))?;
                {
                    use std::io::Write as _;
                    let mut pipe = child.stdin.take().expect("stdin was piped");
                    pipe.write_all(stdin.as_bytes())
                        .with_context(|| format!("Cannot write to {program}"))?;
                }
                let out = child
                    .wait_with_output()
                    .with_context(|| format!("Cannot run {program}"))?;
                if !out.status.success() {
                    // The tool's own complaint, not ours: "nft: syntax error"
                    // names the problem far better than an exit code.
                    bail!(
                        "{program} failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            })
        }

        async fn available(&self, program: &str) -> bool {
            // Run it rather than looking for it on `PATH`: the question is
            // whether it works, and a `nft` that cannot load its kernel module
            // is a `nft` this node does not have.
            self.run(program, &["--version"], "").await.is_ok()
        }
    }
}

#[cfg(test)]
pub mod tests;
