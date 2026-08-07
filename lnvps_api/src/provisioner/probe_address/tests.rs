//! Where a probe VM sits, and why nothing writes it down.

use super::*;

fn tunnel(address6: Option<&str>) -> Tunnel {
    Tunnel {
        id: 1,
        address4: Some("10.66.0.2/32".to_string()),
        address6: address6.map(str::to_string),
        ..Default::default()
    }
}

/// The address is a pure function of the node's own. Both ends can work it out,
/// so an API that dies mid-probe leaves no allocation to reclaim — which is the
/// whole reason a probe stores nothing.
#[test]
fn a_probe_address_is_derived_not_allocated() {
    let t = tunnel(Some("fd00:66::2/128"));

    let first = probe_address(&t).unwrap();
    let second = probe_address(&t).unwrap();
    assert_eq!(first, second);
    assert_eq!(first, "fd00:66::8002/128");
}

/// It never lands on the node itself, or on the next node along. Nodes are
/// handed consecutive addresses from the bottom of the block, so an offset
/// small enough to overlap would put a probe on a neighbour's address — and the
/// route server would then send that neighbour's traffic here.
#[test]
fn a_probe_never_takes_another_nodes_address() {
    let mut taken = Vec::new();
    for n in 1..=64u16 {
        let t = tunnel(Some(&format!("fd00:66::{n:x}/128")));
        taken.push(format!("fd00:66::{n:x}/128"));
        taken.push(probe_address(&t).unwrap());
    }

    let mut sorted = taken.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), taken.len(), "two addresses collided");
}

/// A pool with no v6 block carries no probes. Falling back to IPv4 would spend
/// the scarce resource the marketplace exists to stretch, to check something a
/// v6 address checks just as well.
#[test]
fn no_v6_means_no_probe() {
    assert!(probe_address(&tunnel(None)).is_none());
    // ...and the v4 address is not quietly used instead.
    let t = tunnel(None);
    assert!(t.address4.is_some());
}

/// A malformed address produces nothing rather than a guess. This value ends up
/// in a routing table and a packet filter; a plausible-looking wrong answer is
/// worse than no answer.
#[test]
fn a_broken_address_is_not_guessed_at() {
    assert!(probe_address(&tunnel(Some("not-an-address"))).is_none());
    assert!(probe_address(&tunnel(Some(""))).is_none());
    assert!(
        probe_address(&tunnel(Some("10.66.0.2/32"))).is_none(),
        "a v4 address is not a v6 one"
    );
}

/// The very top of a block has no room above it, and says so rather than
/// wrapping round onto an address that belongs to someone else.
#[test]
fn the_top_of_a_block_has_no_probe() {
    let t = tunnel(Some("fd00:66::ffff/128"));
    assert!(probe_address(&t).is_none());
}

/// The MAC is stable and per-node: the node's filter binds an address to a MAC,
/// so a probe whose MAC changed between runs would be filtered on the second.
#[test]
fn a_probes_mac_is_stable_and_its_own() {
    assert_eq!(probe_mac(7), probe_mac(7));
    assert_ne!(probe_mac(7), probe_mac(8));
    // QEMU's OUI, so an operator reading their own bridge sees what they expect.
    assert!(probe_mac(7).starts_with("52:54:"), "{}", probe_mac(7));
}

/// A probe's gateway is the node's own, never the route server's.
///
/// The node holds its guests' gateway on the bridge so they can reach it
/// on-link, and the route server holds its own address on the same pool. Give
/// the probe the route server's address and two machines hold one address: the
/// guest's replies are delivered to the node, the route server sees nothing,
/// and a working node looks exactly like one that cannot carry traffic.
#[test]
fn a_probes_gateway_is_not_the_route_servers() {
    let t = tunnel(Some("fd00:66::2/128"));
    let gateway = probe_gateway(&t).unwrap();

    // The route server's address is the bottom of the pool; the node's gateway
    // for probes is nowhere near it.
    assert_ne!(gateway, "fd00:66::1/128");
    assert_ne!(gateway, probe_address(&t).unwrap());
    assert_eq!(gateway, "fd00:66::c002/128");
}

/// Gateways and probe addresses never collide, across every node in a pool.
#[test]
fn gateways_and_probes_share_no_addresses() {
    let mut seen = Vec::new();
    for n in 1..=64u16 {
        let t = tunnel(Some(&format!("fd00:66::{n:x}/128")));
        seen.push(probe_address(&t).unwrap());
        seen.push(probe_gateway(&t).unwrap());
        // The route server's own address, which neither may take.
        assert_ne!(probe_gateway(&t).unwrap(), "fd00:66::1/128");
    }
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "two addresses collided");
}
