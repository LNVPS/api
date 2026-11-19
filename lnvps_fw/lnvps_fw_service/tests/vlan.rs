//! 802.1Q / 802.1ad (VLAN trunk) tests. A filter hook on a trunk port sees
//! tagged frames whenever the NIC is not stripping tags in hardware, and a
//! learn hook may see VM egress tagged. The datapath must look through up to
//! two tags: a tagged packet to a protected destination is counted and
//! mitigated exactly like an untagged one, and a tagged outbound packet still
//! teaches the port learner.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test vlan`.

mod harness;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use harness::netns::{ATTACKER_V4, NetnsTopology, VM_V4};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{PROTO_TCP, PROTO_UDP};

/// 802.1Q-tagged SYNs to a mitigating VM's closed port are dropped on the
/// header behind the tag.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn vlan_tagged_closed_port_dropped() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_mitigate_prefix_v4(VM_V4, 32).expect("mitigate vm");

    let sent = tagged_syns(&h, &[100], 4444, 20);
    assert!(sent >= 15, "raw tagged frames accepted: {sent}");

    std::thread::sleep(Duration::from_millis(200));
    let c = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("VM counted behind the tag");
    assert!(c.packets >= 15, "tagged packets counted: {}", c.packets);
    assert!(
        c.dropped >= 15,
        "tagged closed-port packets dropped: {}",
        c.dropped
    );
}

/// 802.1Q-tagged SYNs to a mitigating VM's open port are passed.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn vlan_tagged_open_port_passed() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_open_port_v4(VM_V4, 8080, PROTO_TCP)
        .expect("open port");
    h.set_mitigate_prefix_v4(VM_V4, 32).expect("mitigate vm");

    let sent = tagged_syns(&h, &[100], 8080, 20);
    assert!(sent >= 15);

    std::thread::sleep(Duration::from_millis(200));
    let c = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("VM counted behind the tag");
    assert!(c.packets >= 15, "tagged packets counted: {}", c.packets);
    assert_eq!(c.dropped, 0, "open-port tagged packets must pass");
}

/// Double-tagged (802.1ad outer + 802.1Q inner) frames are looked through as
/// well.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn qinq_tagged_closed_port_dropped() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_mitigate_prefix_v4(VM_V4, 32).expect("mitigate vm");

    let sent = tagged_syns(&h, &[3000, 100], 4444, 20);
    assert!(sent >= 15);

    std::thread::sleep(Duration::from_millis(200));
    let c = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("VM counted behind two tags");
    assert!(c.packets >= 15, "QinQ packets counted: {}", c.packets);
    assert!(
        c.dropped >= 15,
        "QinQ closed-port packets dropped: {}",
        c.dropped
    );
}

/// A tagged frame that is not IP behind the tag is passed untouched (and not
/// counted): ARP over a VLAN must never be dropped.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn vlan_tagged_non_ip_is_ignored() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_mitigate_prefix_v4(VM_V4, 32).expect("mitigate vm");
    // Nothing tagged-and-IP is sent to VM_V4 here; a tagged ARP to the filter
    // is what a real trunk carries constantly. There is no VM counter to
    // check for ARP, so this asserts the negative: no dest entry appears.
    let ns = attacker_ns(&h);
    let dst_mac = NetnsTopology::mac_of(&h.topo.filter_ns, &h.topo.filter_up_if).expect("mac");
    let sent = traffic::vlan_arp_v4(
        &ns,
        &h.topo.attacker_if,
        dst_mac,
        100,
        ATTACKER_V4,
        VM_V4,
        10,
    )
    .expect("tagged arp");
    assert!(sent >= 8);
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        h.dest_counters_v4(VM_V4).expect("counters").is_none(),
        "tagged non-IP frames must not be counted"
    );
}

/// The TC learner reads through a tag on the egress side: a UDP datagram sent
/// from a VLAN sub-interface of the uplink (tag inline in the frame) still
/// teaches its source port.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn vlan_tagged_egress_is_learned() {
    if !require_root() {
        return;
    }
    let h = Harness::new().expect("harness setup");
    // A VLAN 100 sub-interface on the filter's uplink, addressed in a fresh
    // subnet; datagrams it emits leave f_up as 802.1Q-tagged frames.
    let vlan_ip = Ipv4Addr::new(10, 0, 100, 1);
    NetnsTopology::add_vlan(
        &h.topo.filter_ns,
        &h.topo.filter_up_if,
        "vl100",
        100,
        "10.0.100.1/24",
    )
    .expect("vlan sub-interface");
    let dst = SocketAddr::from((Ipv4Addr::new(10, 0, 100, 2), 5353));
    // Nothing answers ARP for 10.0.100.2, so pin its MAC: the datagram then
    // leaves f_up immediately as a tagged frame.
    NetnsTopology::add_static_neigh(
        &h.topo.filter_ns,
        "vl100",
        "10.0.100.2",
        "02:00:00:00:00:02",
    )
    .expect("static neigh");
    traffic::udp_send_from(&filter_ns(&h), 40000, dst, b"hi").expect("tagged datagram");
    std::thread::sleep(Duration::from_millis(200));
    let learned = h
        .open_port_v4(vlan_ip, 40000, PROTO_UDP)
        .expect("map read")
        .is_some();
    assert!(learned, "UDP source port behind a VLAN tag was not learned");
}

fn tagged_syns(h: &Harness, tags: &[u16], dport: u16, count: u32) -> u32 {
    let dst_mac = NetnsTopology::mac_of(&h.topo.filter_ns, &h.topo.filter_up_if).expect("mac");
    traffic::vlan_syn_flood_v4(
        &attacker_ns(h),
        &h.topo.attacker_if,
        dst_mac,
        tags,
        ATTACKER_V4,
        VM_V4,
        dport,
        count,
    )
    .expect("tagged flood")
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}

fn filter_ns(h: &Harness) -> String {
    h.topo.filter_ns_path()
}
