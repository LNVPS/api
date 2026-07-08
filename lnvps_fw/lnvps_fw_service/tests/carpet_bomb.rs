//! Prefix-level (carpet-bomb) detection: a flood spread thinly across a
//! protected prefix — where no single destination trips its own threshold —
//! flips the WHOLE prefix into mitigation via one dest-state LPM trie entry.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test carpet_bomb`.

mod harness;

use std::net::{Ipv4Addr, SocketAddr};

use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER};
use lnvps_fw_service::detect::DetectionConfig;
use lnvps_fw_service::runtime::{DetectionState, RuntimeConfig};

const SECOND_NS: u64 = 1_000_000_000;

#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn thin_carpet_bomb_flips_whole_prefix() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    // Per-dest detection effectively disabled (huge thresholds); the aggregate
    // network threshold is low, so a thin spread across the /24 trips it.
    let cfg = RuntimeConfig {
        detection: DetectionConfig {
            pps: u64::MAX,
            syn_pps: u64::MAX,
            bps: u64::MAX,
            exit_pct: 50,
            cooldown_ns: SECOND_NS,
        },
        network: DetectionConfig {
            pps: 200, // aggregate over the /24
            syn_pps: u64::MAX,
            bps: u64::MAX,
            exit_pct: 50,
            cooldown_ns: SECOND_NS,
        },
        protected_v4: vec![(24, [10, 0, 1, 0])],
        protected_v6: Vec::new(),
        src_rate_pps: u64::MAX,
        fanout: 4,
        block_ttl_ns: SECOND_NS,
        escalate_pass_pps: u64::MAX,
        max_real_sources: 10_000,
        syn_proxy_pps: u64::MAX,
    };
    let mut state = DetectionState::default();

    // t0: seed.
    h.run_control_tick(&mut state, &cfg, SECOND_NS).expect("t0");
    assert_eq!(
        h.dest_mode_v4(Ipv4Addr::new(10, 0, 1, 99)).unwrap(),
        DEST_MODE_NORMAL
    );

    // Spread ~100 pkts each to four different IPs in 10.0.1.0/24. No single
    // destination reaches the (huge) per-dest threshold, but the /24 aggregate
    // (~400 pps) exceeds the network threshold of 200.
    let attacker = attacker_ns(&h);
    for host in 2..=5u8 {
        let dst = SocketAddr::from((Ipv4Addr::new(10, 0, 1, host), 9999));
        traffic::udp_send_burst(&attacker, dst, 100).expect("burst");
    }

    // t1: aggregate detection flips the whole prefix.
    h.run_control_tick(&mut state, &cfg, 2 * SECOND_NS)
        .expect("t1");

    // An IP in the prefix that received NO traffic is still mitigated (proves
    // the prefix-wide LPM entry, not per-dest).
    assert_eq!(
        h.dest_mode_v4(Ipv4Addr::new(10, 0, 1, 99)).unwrap(),
        DEST_MODE_PORT_FILTER,
        "whole /24 should be mitigating"
    );
    // An address outside the protected prefix is unaffected.
    assert_eq!(
        h.dest_mode_v4(Ipv4Addr::new(10, 0, 2, 1)).unwrap(),
        DEST_MODE_NORMAL,
        "addresses outside the prefix must stay normal"
    );

    // Flood stops -> cooldown -> prefix returns to normal.
    h.run_control_tick(&mut state, &cfg, 3 * SECOND_NS)
        .expect("t2");
    assert_eq!(
        h.dest_mode_v4(Ipv4Addr::new(10, 0, 1, 99)).unwrap(),
        DEST_MODE_PORT_FILTER
    );
    h.run_control_tick(&mut state, &cfg, 4 * SECOND_NS)
        .expect("t3");
    assert_eq!(
        h.dest_mode_v4(Ipv4Addr::new(10, 0, 1, 99)).unwrap(),
        DEST_MODE_NORMAL,
        "prefix should return to normal after cooldown"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
