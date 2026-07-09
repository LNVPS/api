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

/// Per-source state machine: offending sources are blocked as individual /32s
/// (NOT aggregated into a /24 while there is trie space), a low-rate neighbour
/// in the same /24 is never caught, and a blocked source is RELEASED once its
/// rate falls below the exit threshold for the cooldown — not held for a blind
/// TTL. Uses the real `runtime::run_control`.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn per_source_blocks_slash32_and_releases_on_hysteresis() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_mitigate_v4(VM_V4).expect("mitigate");

    let quiet = DetectionConfig {
        pps: u64::MAX,
        syn_pps: u64::MAX,
        bps: u64::MAX,
        exit_pct: 50,
        cooldown_ns: SECOND_NS,
    };
    let cfg = RuntimeConfig {
        // Keep dest + prefix detection out of the way; drive DEST_STATE manually.
        detection: quiet,
        network: quiet,
        protected_v4: Vec::new(),
        protected_v6: Vec::new(),
        src_rate_pps: 10, // a source sending >=10pps trips DROPPING
        fanout: 4,
        agg_max_prefix_v4: 24,
        agg_max_prefix_v6: 48,
        src_exit_pct: 50, // exit below 5pps
        src_cooldown_ns: SECOND_NS,
        max_source_blocks: 50_000, // ample space -> /32s, no aggregation
        block_ttl_ns: SECOND_NS,
        escalate_pass_pps: 0,
        max_real_sources: 10_000,
        syn_proxy_pps: u64::MAX,
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

    // t1: one control tick moves the offenders into DROPPING and blocks each /32.
    h.run_control_tick(&mut state, &cfg, 2 * SECOND_NS)
        .expect("t1");

    for o in &offenders {
        assert!(
            h.cidr_blocked_v4(*o).unwrap(),
            "offending source {o} should be blocked as a /32"
        );
    }
    // Crucially: a non-offending neighbour in the SAME /24 must NOT be blocked
    // (no eager aggregation while there is trie space).
    assert!(
        !h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 200)).unwrap(),
        "a low-rate neighbour in the same /24 must not be caught by aggregation"
    );
    assert!(
        !h.cidr_blocked_v4(unrelated).unwrap(),
        "low-rate unrelated source must not be blocked"
    );

    // Flood stops. The source rate drops to 0; the state machine needs one tick
    // to record "below exit" and then the cooldown (1s) to elapse before it
    // returns to NORMAL and is unblocked.
    h.run_control_tick(&mut state, &cfg, 3 * SECOND_NS)
        .expect("cooldown-start");
    assert!(
        h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap(),
        "still blocked during the cooldown window"
    );
    // A second tick a full cooldown later releases the block.
    h.run_control_tick(&mut state, &cfg, 5 * SECOND_NS)
        .expect("release");
    for o in &offenders {
        assert!(
            !h.cidr_blocked_v4(*o).unwrap(),
            "source {o} released once its rate fell below exit for the cooldown"
        );
    }
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
