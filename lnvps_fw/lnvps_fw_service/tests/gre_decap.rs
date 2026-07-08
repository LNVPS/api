//! GRE decapsulation (router underlay) tests. When XDP is attached to a router
//! underlay carrying BGP-over-GRE, attack traffic to a protected VM arrives
//! *inside* a GRE tunnel. The datapath decapsulates in-XDP and filters on the
//! inner IP/port, so a mitigating VM's closed ports are dropped even though the
//! packets are GRE-encapsulated on the wire.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test gre_decap`.

mod harness;

use std::time::Duration;

use harness::netns::{ATTACKER_V4, FILTER_UP_V4, VM_V4};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::PROTO_TCP;

/// GRE-encapsulated SYNs to a mitigating VM's *closed* port are decapsulated and
/// dropped based on the inner header.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn gre_inner_closed_port_dropped() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    // VM under port-filter mitigation.
    h.set_mitigate_prefix_v4(VM_V4, 32).expect("mitigate vm");

    let sent = traffic::gre_flood_v4(
        &attacker_ns(&h),
        ATTACKER_V4,  // outer src
        FILTER_UP_V4, // outer dst (the underlay NIC XDP is attached to)
        ATTACKER_V4,  // inner src
        VM_V4,        // inner dst (the protected VM)
        4444,         // inner dst port (closed)
        20,
    )
    .expect("gre flood");
    assert!(sent >= 15, "kernel should accept the raw GRE packets");

    std::thread::sleep(Duration::from_millis(200));
    let c = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("VM counted");
    // Decap worked: the inner VM IP was counted, and the closed-port packets
    // were dropped on the inner header.
    assert!(
        c.packets >= 15,
        "inner packets counted (decap): {}",
        c.packets
    );
    assert!(c.dropped >= 15, "closed-port inner dropped: {}", c.dropped);
}

/// GRE-encapsulated SYNs to a mitigating VM's *open* port are decapsulated and
/// passed (counted, not dropped).
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn gre_inner_open_port_passed() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_open_port_v4(VM_V4, 8080, PROTO_TCP)
        .expect("open port");
    h.set_mitigate_prefix_v4(VM_V4, 32).expect("mitigate vm");

    let sent = traffic::gre_flood_v4(
        &attacker_ns(&h),
        ATTACKER_V4,
        FILTER_UP_V4,
        ATTACKER_V4,
        VM_V4,
        8080, // inner dst port (open)
        20,
    )
    .expect("gre flood");
    assert!(sent >= 15);

    std::thread::sleep(Duration::from_millis(200));
    let c = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("VM counted");
    assert!(
        c.packets >= 15,
        "inner packets counted (decap): {}",
        c.packets
    );
    assert_eq!(c.dropped, 0, "open-port inner must pass, not drop");
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
