//! Increment-5 harness tests: per-source rate detection + CIDR aggregation.
//!
//! The eBPF side only counts per source; userspace computes per-source rates
//! and installs aggregated CIDR blocks. Root-only and `#[ignore]`d; run with
//! `scripts/fw-e2e.sh --test escalation`.

mod harness;

use std::net::Ipv4Addr;

use harness::netns::VM_V4;
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_service::detect::DetectionConfig;
use lnvps_fw_service::runtime::{DetectionState, RuntimeConfig};

const SECOND_NS: u64 = 1_000_000_000;

/// A distributed flood from many sources in one /24 aggregates to a single /24
/// block; a low-rate unrelated source is not blocked; the block decays after
/// its TTL once the flood stops. Uses the real `runtime::run_control`.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn cidr_escalation_aggregates_offending_v24() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_mitigate_v4(VM_V4).expect("mitigate");

    let cfg = RuntimeConfig {
        // Keep dest detection out of the way; drive DEST_STATE manually.
        detection: DetectionConfig {
            pps: u64::MAX,
            syn_pps: u64::MAX,
            bps: u64::MAX,
            exit_pct: 50,
            cooldown_ns: SECOND_NS,
        },
        src_rate_pps: 10, // a source sending >=10pps is an offender
        fanout: 4,        // 4 sources in a /24 collapse to the /24
        block_ttl_ns: SECOND_NS,
    };
    let mut state = DetectionState::default();

    // t0: seed snapshots (no traffic yet).
    h.run_control_tick(&mut state, &cfg, SECOND_NS).expect("t0");

    // Four sources in 10.0.9.0/24 flood (20 pkts ~= 20pps over the 1s window);
    // one unrelated source sends only 5 (5pps, below the offender threshold).
    let offenders: Vec<Ipv4Addr> = (1..=4).map(|i| Ipv4Addr::new(10, 0, 9, i)).collect();
    let unrelated = Ipv4Addr::new(10, 0, 99, 5);
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &offenders, VM_V4, 9999, 20).expect("flood");
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[unrelated], VM_V4, 9999, 5).expect("low");

    assert!(
        h.src_packets_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap() >= 20,
        "per-source packets should be counted"
    );

    // t1: one control tick installs the aggregated /24 block.
    h.run_control_tick(&mut state, &cfg, 2 * SECOND_NS)
        .expect("t1");

    assert!(
        h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap(),
        "offending source should be blocked"
    );
    assert!(
        h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 200)).unwrap(),
        "the whole /24 should be covered (aggregation)"
    );
    assert!(
        !h.cidr_blocked_v4(unrelated).unwrap(),
        "low-rate unrelated source must not be blocked"
    );

    // Flood stops: no new per-source deltas, so the block is not refreshed and
    // decays once its TTL (1s) elapses.
    h.run_control_tick(&mut state, &cfg, 4 * SECOND_NS)
        .expect("decay");
    assert!(
        !h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap(),
        "block should decay after TTL without refresh"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
