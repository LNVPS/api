//! In-kernel per-source rate machine: the XDP datapath computes each source's
//! window rate and blocks over-rate sources on its own — **no userspace
//! control ticks are involved in the decision**. Userspace only arms the
//! config map and reads the state for display. Root-only and `#[ignore]`d;
//! run with `scripts/fw-e2e.sh --test escalation`.

mod harness;

use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;

use harness::netns::VM_V4;
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK};

const SECOND_NS: u64 = 1_000_000_000;

/// Offending sources are blocked by the kernel itself: a source exceeding the
/// per-window limit toward a SOURCE_BLOCK-escalated destination trips
/// `blocked_until` in its state entry and its packets are dropped, while a
/// low-rate source (same or different /24) is never touched. Once the flood
/// stops, the block expires after the cooldown without any userspace action.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn kernel_blocks_over_rate_source_and_releases_after_cooldown() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    // Escalated destination: port filter + source blocking enforced.
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_PORT_FILTER | DEST_MODE_SOURCE_BLOCK)
        .expect("mitigate");
    // Arm the kernel rate machine: >10 packets within a 1s window blocks the
    // source for a 1s cooldown.
    h.set_src_rate(10, SECOND_NS).expect("src rate cfg");

    let offender = Ipv4Addr::new(10, 0, 9, 1);
    let neighbour = Ipv4Addr::new(10, 0, 9, 200); // same /24, low rate
    let unrelated = Ipv4Addr::new(10, 0, 99, 5);

    // The offender bursts 50 packets (all within one window); the others send 3.
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[offender], VM_V4, 9999, 50).expect("flood");
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[neighbour, unrelated], VM_V4, 9999, 3)
        .expect("low");

    // The kernel counted and decided on its own — no control tick has run.
    assert!(
        h.src_packets_v4(offender).unwrap() >= 10,
        "offender packets counted in the kernel window"
    );
    assert!(
        h.src_blocked_v4(offender).unwrap(),
        "kernel blocked the over-rate source without userspace"
    );
    assert!(
        !h.src_blocked_v4(neighbour).unwrap(),
        "low-rate neighbour in the same /24 stays unblocked"
    );
    assert!(
        !h.src_blocked_v4(unrelated).unwrap(),
        "low-rate unrelated source stays unblocked"
    );

    // Blocked means dropped: further offender packets must not reach the VM.
    let before = h
        .dest_counters_v4(VM_V4)
        .unwrap()
        .unwrap_or_default()
        .dropped;
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[offender], VM_V4, 9999, 10)
        .expect("blocked flood");
    let after = h
        .dest_counters_v4(VM_V4)
        .unwrap()
        .unwrap_or_default()
        .dropped;
    assert!(
        after > before,
        "packets from a kernel-blocked source are dropped ({before} -> {after})"
    );

    // Flood stops: the block expires by itself after the cooldown (the last
    // over-rate packet extended it by 1s at most).
    sleep(Duration::from_millis(2200));
    assert!(
        !h.src_blocked_v4(offender).unwrap(),
        "block expires after the cooldown once the flood stops"
    );
}

/// Enforcement is gated on the destination's SOURCE_BLOCK escalation: with
/// only PORT_FILTER set, an over-rate source is *counted* (and marked blocked
/// in its state) but its packets are not source-dropped — the escalation
/// ladder still decides when source blocking engages.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn source_drops_gated_on_source_block_flag() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_PORT_FILTER)
        .expect("mitigate (no SOURCE_BLOCK)");
    h.set_src_rate(10, 60 * SECOND_NS).expect("src rate cfg");
    // Learn the target port as open so PORT_FILTER passes the traffic and any
    // drop could only come from source blocking.
    h.set_open_port_v4(VM_V4, 9999, lnvps_fw_common::PROTO_UDP)
        .expect("open port");

    let offender = Ipv4Addr::new(10, 0, 9, 1);
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[offender], VM_V4, 9999, 50).expect("flood");

    // The kernel marked it blocked in its state map…
    assert!(
        h.src_blocked_v4(offender).unwrap(),
        "over-rate source is marked blocked in the state map"
    );
    // …but without the SOURCE_BLOCK flag its packets keep flowing.
    let before = h
        .dest_counters_v4(VM_V4)
        .unwrap()
        .unwrap_or_default()
        .packets;
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[offender], VM_V4, 9999, 10).expect("more");
    let counters = h.dest_counters_v4(VM_V4).unwrap().unwrap_or_default();
    assert!(
        counters.packets >= before + 10,
        "packets still counted/passed without SOURCE_BLOCK escalation"
    );

    // Escalate: now the same source's packets are dropped.
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_PORT_FILTER | DEST_MODE_SOURCE_BLOCK)
        .expect("escalate");
    let dropped_before = h
        .dest_counters_v4(VM_V4)
        .unwrap()
        .unwrap_or_default()
        .dropped;
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[offender], VM_V4, 9999, 10)
        .expect("blocked flood");
    let dropped_after = h
        .dest_counters_v4(VM_V4)
        .unwrap()
        .unwrap_or_default()
        .dropped;
    assert!(
        dropped_after > dropped_before,
        "SOURCE_BLOCK escalation engages the kernel's block"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
