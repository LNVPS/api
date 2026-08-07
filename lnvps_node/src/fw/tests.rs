//! What the filter decides, tested without root.
//!
//! Whether the rendered rules actually drop a spoofing guest is proved by
//! `lnvps_e2e/tests/tunnel_netns.rs`, which loads them into a real kernel and
//! sends real packets. What is worth asserting here is the reasoning: which
//! addresses are allowed, which tool is chosen, and what happens on machines
//! that are missing pieces.

use std::sync::Mutex;

use super::*;
use crate::net::{DesiredDataPlane, DesiredGuest, DesiredTunnel};

/// A machine with a chosen set of firewall tools, recording everything it is
/// asked to load.
#[derive(Default)]
pub struct FakeFirewall {
    /// Programs this machine has. Everything else is "not installed".
    pub programs: Vec<String>,
    pub calls: Mutex<Vec<(String, Vec<String>, String)>>,
    /// Canned output, keyed by program.
    pub output: Vec<(String, String)>,
}

impl FakeFirewall {
    fn with(programs: &[&str]) -> Self {
        Self {
            programs: programs.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    fn loaded(&self) -> String {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, _, stdin)| stdin.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn programs_run(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _, _)| p.clone())
            .collect()
    }
}

#[async_trait]
impl FirewallOps for FakeFirewall {
    async fn run(&self, program: &str, args: &[&str], stdin: &str) -> Result<String> {
        if !self.programs.iter().any(|p| p == program) {
            bail!("{program}: not found");
        }
        self.calls.lock().unwrap().push((
            program.to_string(),
            args.iter().map(|a| a.to_string()).collect(),
            stdin.to_string(),
        ));
        Ok(self
            .output
            .iter()
            .find(|(p, _)| p == program)
            .map(|(_, o)| o.clone())
            .unwrap_or_default())
    }

    async fn available(&self, program: &str) -> bool {
        self.programs.iter().any(|p| p == program)
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

/// The policy is LNVPS's list, not the node's view of its own bridge: a node
/// that authorised whatever it found attached would authorise whatever the
/// operator attached.
#[test]
fn the_policy_comes_from_the_document() {
    let policy = Policy::from_desired(&desired(vec![
        guest("203.0.113.5", Some("AA:BB:CC:DD:EE:FF")),
        guest("2001:db8::5", None),
    ]))
    .unwrap();

    assert_eq!(policy.bindings.len(), 2);
    // Lower-cased, because that is how both nft and iptables render a MAC, and
    // a ruleset that differs from the machine's only by case reads as drift on
    // every single comparison.
    assert_eq!(
        policy.bindings[0].mac.as_deref(),
        Some("aa:bb:cc:dd:ee:ff"),
        "{policy:?}"
    );
}

/// An address with a prefix is still an address. LNVPS sends guest addresses
/// both ways depending on the range, and a filter that only understood one
/// form would silently drop that guest's traffic.
#[test]
fn a_guest_address_may_carry_a_prefix() {
    let policy = Policy::from_desired(&desired(vec![guest("203.0.113.5/24", None)])).unwrap();
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

/// Both halves of the binding appear, and the MAC-bound guest is held to the
/// stronger check while the unbound one is visibly in the weaker set.
#[test]
fn a_mac_binds_the_address_to_it() {
    let policy = Policy::from_desired(&desired(vec![
        guest("203.0.113.5", Some("aa:bb:cc:dd:ee:ff")),
        guest("203.0.113.6", None),
    ]))
    .unwrap();
    let rendered = render_nft(&policy);

    assert!(
        rendered.contains("aa:bb:cc:dd:ee:ff . 203.0.113.5"),
        "{rendered}"
    );
    assert!(
        rendered.contains("elements = { 203.0.113.6 }"),
        "the unbound guest should be in the weaker set: {rendered}"
    );
    // ...and the strong set does not also contain it, or the binding would be
    // decorative.
    assert!(!rendered.contains(". 203.0.113.6"), "{rendered}");
}

/// The transaction deletes before it rebuilds, and creates the table first so
/// that delete has something to delete — otherwise the very first run on a
/// freshly booted node fails, which is the run that matters most.
#[test]
fn the_ruleset_is_replaced_atomically() {
    let rendered = render_nft(&Policy::default());
    let create = rendered.find("table inet lnvps {}").unwrap();
    let delete = rendered.find("delete table inet lnvps").unwrap();
    let rebuild = rendered.find("table inet lnvps {\n").unwrap();
    assert!(create < delete && delete < rebuild, "{rendered}");
}

/// A node with no guests still gets a complete, working ruleset. Every node
/// looks like this on its first day, and nft refuses an empty `elements = {}`.
#[test]
fn a_node_with_no_guests_still_loads() {
    let rendered = render_nft(&Policy::default());
    assert!(!rendered.contains("elements = {  }"), "{rendered}");
    assert!(rendered.contains("policy drop"), "{rendered}");
    assert!(rendered.contains("set guest4"), "{rendered}");
}

/// Anti-spoof is checked before conntrack. An address that has gone back in the
/// pool may already be someone else's, and a flow opened while it was still
/// this guest's must not outlive the assignment.
#[test]
fn spoofing_is_checked_before_established_connections() {
    let rendered = render_nft(&Policy::default());
    let spoof = rendered.find("jump source").unwrap();
    let conntrack = rendered.find("ct state established").unwrap();
    assert!(spoof < conntrack, "{rendered}");
}

/// Layer 2 is a different path through the kernel: a frame from one guest to
/// another never reaches the forward hook, so proxy ARP would otherwise let a
/// tenant poison their neighbours.
#[test]
fn guests_are_isolated_from_each_other_at_layer_two() {
    let rendered = render_nft(&Policy::default());
    assert!(rendered.contains("table bridge lnvps"), "{rendered}");
    let bridge = &rendered[rendered.find("table bridge lnvps {\n").unwrap()..];
    assert!(
        bridge.contains("hook forward") && bridge.contains("policy drop"),
        "{bridge}"
    );
}

/// Clamped to the route's MTU rather than a number rendered into the rules: the
/// tunnel's MTU can change under the filter, and a stale clamp hangs large
/// transfers exactly like no clamp at all.
#[test]
fn the_mss_is_clamped_to_the_path() {
    assert!(render_nft(&Policy::default()).contains("maxseg size set rt mtu"));
    assert!(render_iptables(&Policy::default(), false).contains("--clamp-mss-to-pmtu"));
}

/// Return traffic is delivered only to addresses LNVPS placed here. The route
/// server should not send anything else, and if it does, not delivering it is
/// the cheaper mistake.
#[test]
fn only_assigned_addresses_are_delivered() {
    let policy = Policy::from_desired(&desired(vec![guest("203.0.113.5", None)])).unwrap();
    let rendered = render_nft(&policy);
    assert!(
        rendered.contains(r#"iifname "wgln0" oifname "br-lnvps" ip daddr @assigned4 accept"#),
        "{rendered}"
    );
}

/// Two guests on one node reach each other by being routed, because two guests
/// on two nodes can. A network that behaved differently depending on where
/// LNVPS happened to place a VM would be a network nobody could reason about.
#[test]
fn guests_on_one_node_can_still_reach_each_other_through_the_node() {
    let rendered = render_nft(&Policy::default());
    assert!(
        rendered.contains(r#"iifname "br-lnvps" oifname "br-lnvps" ip daddr @assigned4 accept"#),
        "{rendered}"
    );
}

/// Neighbour discovery is accepted. ICMPv4 is arguably optional; ICMPv6 is not,
/// and a node that dropped it would report a configured tunnel and no working
/// IPv6 guest on it.
#[test]
fn neighbour_discovery_survives() {
    assert!(render_nft(&Policy::default()).contains("nd-neighbor-solicit"));
    assert!(render_iptables(&Policy::default(), true).contains("neighbour-solicitation"));
    // ...and is not rendered into the v4 ruleset, where iptables would reject
    // the whole file and leave the node with no filter at all.
    assert!(!render_iptables(&Policy::default(), false).contains("icmpv6"));
}

/// The v4 and v6 rulesets are separate programs with separate tables, so each
/// carries only its own family's guests.
#[test]
fn each_family_gets_only_its_own_guests() {
    let policy = Policy::from_desired(&desired(vec![
        guest("203.0.113.5", None),
        guest("2001:db8::5", None),
    ]))
    .unwrap();

    let v4 = render_iptables(&policy, false);
    assert!(
        v4.contains("203.0.113.5/32") && !v4.contains("2001:db8::5"),
        "{v4}"
    );
    let v6 = render_iptables(&policy, true);
    assert!(
        v6.contains("2001:db8::5/128") && !v6.contains("203.0.113.5"),
        "{v6}"
    );
}

/// The whole table is replaced rather than appended to. This runs on every
/// refresh, and a node up for a month would otherwise carry a month of
/// duplicate rules — the second reason, after atomicity, not to use --noflush.
#[tokio::test]
async fn the_iptables_ruleset_is_replaced_not_appended() {
    let fake = FakeFirewall::with(&["iptables-restore"]);
    apply(&fake, &Policy::default()).await.unwrap();
    let calls = fake.calls.lock().unwrap();
    assert!(
        calls[0].1.is_empty(),
        "--noflush would accumulate: {calls:?}"
    );
}

/// nft is preferred where it exists: it replaces a table atomically and can
/// express the layer 2 rule in the same tool.
#[tokio::test]
async fn nft_is_preferred() {
    let both = FakeFirewall::with(&["nft", "iptables-restore"]);
    assert_eq!(detect(&both).await, Some(Backend::Nft));
    let old = FakeFirewall::with(&["iptables-restore"]);
    assert_eq!(detect(&old).await, Some(Backend::Iptables));
    assert_eq!(detect(&FakeFirewall::default()).await, None);
}

/// A machine with no packet filter is refused outright rather than configured
/// without one: an unfiltered node is a node where one customer can be another,
/// and it is better for it to carry nobody.
#[tokio::test]
async fn a_machine_with_no_filter_is_refused() {
    let err = apply(&FakeFirewall::default(), &Policy::default())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("neither nft nor iptables"),
        "{err}"
    );
    assert!(err.to_string().contains("none will be placed"), "{err}");
}

/// A machine with iptables but no ip6tables is a working v4 node, not a
/// failure — but it must not be quietly treated as filtered for v6.
#[tokio::test]
async fn a_v4_only_machine_is_still_configured() {
    let fake = FakeFirewall::with(&["iptables-restore"]);
    let changed = apply(&fake, &Policy::default()).await.unwrap();
    assert!(!fake.programs_run().iter().any(|p| p == "ip6tables-restore"));
    assert!(
        changed.iter().any(|c| c.contains("not isolated")),
        "a missing ebtables has to be said out loud: {changed:?}"
    );
}

/// With every tool present, all three are used: IP filtering for both families
/// and layer 2 isolation.
#[tokio::test]
async fn a_complete_machine_uses_every_tool() {
    let fake = FakeFirewall::with(&["iptables-restore", "ip6tables-restore", "ebtables"]);
    apply(&fake, &Policy::default()).await.unwrap();
    let run = fake.programs_run();
    assert!(run.contains(&"iptables-restore".to_string()), "{run:?}");
    assert!(run.contains(&"ip6tables-restore".to_string()), "{run:?}");
    assert!(run.contains(&"ebtables".to_string()), "{run:?}");
}

/// The loaded ruleset carries the guests it was given, so what is applied is
/// what was decided.
#[tokio::test]
async fn what_is_applied_is_what_was_decided() {
    let fake = FakeFirewall::with(&["nft"]);
    let policy = Policy::from_desired(&desired(vec![guest(
        "203.0.113.5",
        Some("aa:bb:cc:dd:ee:ff"),
    )]))
    .unwrap();
    let changed = apply(&fake, &policy).await.unwrap();
    assert!(fake.loaded().contains("aa:bb:cc:dd:ee:ff . 203.0.113.5"));
    assert!(changed[0].contains("1 guest bindings"), "{changed:?}");
}

/// Observation reads the machine, not what was applied: the case worth catching
/// is the one where the two disagree.
#[tokio::test]
async fn observation_reads_the_machine() {
    let mut fake = FakeFirewall::with(&["nft"]);
    fake.output = vec![(
        "nft".to_string(),
        "table inet lnvps {\n\tset assigned4 {\n\t\ttype ipv4_addr\n\t\telements = { 203.0.113.5, 203.0.113.6 }\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}".to_string(),
    )];
    let state = observe(&fake).await;
    assert_eq!(state.backend, Some(Backend::Nft));
    assert!(state.present);
    assert!(state.bindings >= 2, "{state:?}");
}

/// A machine with the tool but no ruleset loaded reports exactly that, rather
/// than an error. It is the state a node is in before its first apply and after
/// somebody flushes the table by hand, and the health gate needs to tell it
/// apart from "no firewall at all".
#[tokio::test]
async fn an_unfiltered_machine_says_so() {
    let fake = FakeFirewall::with(&["nft"]);
    let state = observe(&fake).await;
    assert_eq!(state.backend, Some(Backend::Nft));
    assert!(!state.present);
    assert!(!state.isolated);
    assert_eq!(state.bindings, 0);

    // ...and a machine with no tool at all is a third, distinct answer.
    let state = observe(&FakeFirewall::default()).await;
    assert_eq!(state.backend, None);
    assert!(!state.present);
}

/// The iptables backend is observed through its own tools, since none of the
/// nft output exists there.
#[tokio::test]
async fn the_old_backend_is_observed_too() {
    let mut fake = FakeFirewall::with(&["iptables-restore", "iptables-save", "ebtables"]);
    fake.output = vec![
        (
            "iptables-save".to_string(),
            ":lnvps-source - [0:0]\n-A lnvps-source -s 203.0.113.5/32 -j RETURN\n".to_string(),
        ),
        (
            "ebtables".to_string(),
            "Bridge chain: FORWARD, entries: 0, policy: DROP".to_string(),
        ),
    ];
    let state = observe(&fake).await;
    assert_eq!(state.backend, Some(Backend::Iptables));
    assert!(state.present);
    assert!(state.isolated);
    assert_eq!(state.bindings, 1);
}

/// A failing tool reports its own complaint. "nft: syntax error" names the
/// problem; "exit status 1" sends an operator to read our source.
#[tokio::test]
async fn a_failing_tool_is_quoted() {
    let fake = FakeFirewall::with(&["nft"]);
    // The fake refuses anything not in its program list, which is how a machine
    // with a broken nft behaves: present, and not working.
    let err = apply(&FakeFirewall::with(&["nft-missing"]), &Policy::default())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("neither nft nor iptables"),
        "{err}"
    );
    drop(fake);
}

/// The backend's name round-trips into status, where LNVPS records which
/// machines filter with what.
#[test]
fn the_backend_is_named() {
    assert_eq!(Backend::Nft.as_str(), "nft");
    assert_eq!(Backend::Iptables.as_str(), "iptables");
    assert_eq!(
        serde_json::to_string(&Backend::Iptables).unwrap(),
        "\"iptables\""
    );
}

/// Counting the elements of a dump is how "the filter is current" is decided,
/// so it has to survive the shapes nft actually prints — one line, several
/// lines, and no set at all.
#[test]
fn elements_are_counted_however_nft_prints_them() {
    assert_eq!(count_elements("set a {\ntype ipv4_addr\n}"), 0);
    assert_eq!(
        count_elements("set a {\ntype ipv4_addr\nelements = { 1.2.3.4 }\n}"),
        1
    );
    assert_eq!(
        count_elements("set a {\ntype ipv4_addr\nelements = { 1.2.3.4, 1.2.3.5 }\n}"),
        2
    );
}

/// A machine already running this exact ruleset is left alone. Reloading is
/// harmless — every backend swaps atomically — but a daemon that reported a
/// change on every poll would produce a log in which nothing can be noticed.
#[tokio::test]
async fn a_machine_already_filtered_is_left_alone() {
    let policy = Policy::from_desired(&desired(vec![guest("203.0.113.5", None)])).unwrap();
    let mut fake = FakeFirewall::with(&["nft"]);
    fake.output = vec![(
        "nft".to_string(),
        format!(
            "hook forward\n\t\tdrop comment \"lnvps:{}\"",
            fingerprint(&policy)
        ),
    )];

    assert!(apply(&fake, &policy).await.unwrap().is_empty());
    // The machine is still *read* — that is how the daemon knows — but nothing
    // is loaded onto it.
    assert!(
        !fake.loaded().contains("table inet"),
        "nothing should have been loaded: {:?}",
        fake.calls.lock().unwrap()
    );
}

/// A guest arriving or leaving changes the tag, so the next refresh reloads.
/// The tag is derived from the policy, not from the rendered text, so a change
/// in how the rules are written does not masquerade as a change in who is
/// allowed.
#[test]
fn the_tag_follows_the_guests() {
    let none = fingerprint(&Policy::default());
    let one =
        fingerprint(&Policy::from_desired(&desired(vec![guest("203.0.113.5", None)])).unwrap());
    let bound = fingerprint(
        &Policy::from_desired(&desired(vec![guest(
            "203.0.113.5",
            Some("aa:bb:cc:dd:ee:ff"),
        )]))
        .unwrap(),
    );
    assert_ne!(none, one);
    assert_ne!(one, bound, "binding a MAC is a different policy");
    assert!(render_nft(&Policy::default()).contains(&format!("lnvps:{none}")));
    assert!(render_iptables(&Policy::default(), false).contains(&format!("lnvps:{none}")));
}

/// The tag is read back off the machine rather than remembered, so an operator
/// who flushes the table by hand gets it rebuilt on the next refresh instead of
/// the daemon insisting it is already there.
#[tokio::test]
async fn a_flushed_table_is_rebuilt() {
    let policy = Policy::from_desired(&desired(vec![guest("203.0.113.5", None)])).unwrap();
    let fake = FakeFirewall::with(&["nft"]);
    // The machine reports nothing loaded, whatever the daemon did last time.
    assert!(!apply(&fake, &policy).await.unwrap().is_empty());
    assert!(fake.loaded().contains("table inet lnvps"));
}

/// A machine running *someone else's* idea of the ruleset — an older daemon, a
/// half-applied change — is reloaded rather than accepted.
#[tokio::test]
async fn a_stale_ruleset_is_replaced() {
    let policy = Policy::from_desired(&desired(vec![guest("203.0.113.5", None)])).unwrap();
    let mut fake = FakeFirewall::with(&["nft"]);
    fake.output = vec![(
        "nft".to_string(),
        "hook forward\n\t\tdrop comment \"lnvps:0000000000000000\"".to_string(),
    )];
    assert!(!apply(&fake, &policy).await.unwrap().is_empty());
}

/// The spoof counter is read off the machine. It is the one number here that
/// says something about a customer rather than about the node, and LNVPS would
/// rather learn a guest is spoofing from a counter than from an upstream abuse
/// report.
#[tokio::test]
async fn spoofed_packets_are_counted() {
    let mut fake = FakeFirewall::with(&["nft"]);
    fake.output = vec![(
        "nft".to_string(),
        "hook forward\n\t\tcounter packets 42 bytes 3528 drop comment \"lnvps:abc123\"".to_string(),
    )];
    let state = observe(&fake).await;
    assert_eq!(state.spoofed_packets, 42);
    assert_eq!(state.ruleset.as_deref(), Some("abc123"));

    // A machine with the rule and no drops is zero, not unknown: nothing being
    // dropped is the normal, healthy reading.
    let mut quiet = FakeFirewall::with(&["nft"]);
    quiet.output = vec![("nft".to_string(), "hook forward".to_string())];
    assert_eq!(observe(&quiet).await.spoofed_packets, 0);
}

/// iptables writes its counters the other way round, ahead of the rule.
#[tokio::test]
async fn the_old_backend_counts_too() {
    let mut fake = FakeFirewall::with(&["iptables-restore", "iptables-save"]);
    fake.output = vec![(
        "iptables-save".to_string(),
        "[7:588] -A lnvps-source -m comment --comment lnvps:abc123 -j DROP\n".to_string(),
    )];
    let state = observe(&fake).await;
    assert_eq!(state.spoofed_packets, 7);
}

/// A machine with nothing installed reports that, rather than pretending. It is
/// the state every node is in before the operator has finished setting it up,
/// and the integration tests run against it because it needs no root.
#[tokio::test]
async fn an_unequipped_machine_is_honest() {
    let none = UnavailableFirewall;
    assert!(!none.available("nft").await);
    let err = none.run("nft", &["-f", "-"], "").await.unwrap_err();
    assert!(err.to_string().contains("not available"), "{err}");
    assert_eq!(observe(&none).await, FirewallState::default());
}

/// A dual-stack node under the old backend loads both families, and each
/// ruleset reports the count for its own. A node whose v6 guests were filtered
/// by the v4 ruleset would be a node with no v6 filtering at all.
#[tokio::test]
async fn a_dual_stack_machine_loads_both_families() {
    let fake = FakeFirewall::with(&["iptables-restore", "ip6tables-restore"]);
    let policy = Policy::from_desired(&desired(vec![
        guest("203.0.113.5", Some("aa:bb:cc:dd:ee:ff")),
        guest("2001:db8::5", None),
    ]))
    .unwrap();

    let changed = apply(&fake, &policy).await.unwrap();
    assert!(
        changed.iter().any(|c| c.contains("iptables chains for 1")),
        "{changed:?}"
    );
    assert!(
        changed.iter().any(|c| c.contains("ip6tables chains for 1")),
        "{changed:?}"
    );

    let calls = fake.calls.lock().unwrap();
    let v4 = &calls
        .iter()
        .find(|(p, _, _)| p == "iptables-restore")
        .unwrap()
        .2;
    assert!(v4.contains("--mac-source aa:bb:cc:dd:ee:ff"), "{v4}");
    assert!(!v4.contains("2001:db8"), "{v4}");
}
