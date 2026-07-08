//! Increment-5 harness tests: per-source rate limiting + CIDR escalation.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test escalation`.

mod harness;

use std::net::Ipv4Addr;

use harness::netns::VM_V4;
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_service::cidr::EscalationConfig;
use lnvps_fw_service::runtime::DetectionState;

const SECOND_NS: u64 = 1_000_000_000;

/// A distributed flood from many sources in one /24 escalates to a CIDR-wide
/// block; an unrelated source in a different /24 is unaffected. Once the flood
/// stops, the block decays after its TTL.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn cidr_escalation_blocks_offending_v24() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    // Mitigate the destination and tighten the per-source budget so a modest
    // flood produces offenses quickly.
    h.set_mitigate_v4(VM_V4).expect("mitigate");
    h.set_src_rate_limits(10, 5).expect("src limits");

    // Four sources in 10.0.9.0/24 flood; one unrelated source in 10.0.99.0/24.
    let offenders: Vec<Ipv4Addr> = (1..=4).map(|i| Ipv4Addr::new(10, 0, 9, i)).collect();
    let unrelated = Ipv4Addr::new(10, 0, 99, 5);
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &offenders, VM_V4, 9999, 20).expect("flood");
    traffic::udp_flood_sources_v4(&attacker_ns(&h), &[unrelated], VM_V4, 9999, 20)
        .expect("flood unrelated");

    // Sanity: offenders recorded per-source drops beyond the burst.
    assert!(
        h.src_drops_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap() >= 5,
        "expected offense drops for a flooding source"
    );

    let cfg = EscalationConfig {
        min_src_drops: 5,
        min_sources: 3,
    };
    let mut state = DetectionState::default();

    // One escalation tick installs the /24 block.
    h.run_escalation_tick(&mut state, &cfg, SECOND_NS, SECOND_NS)
        .expect("escalate");

    assert!(
        h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap(),
        "offending /24 should be blocked"
    );
    assert!(
        h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 200)).unwrap(),
        "the whole /24 should be covered by the block"
    );
    assert!(
        !h.cidr_blocked_v4(unrelated).unwrap(),
        "unrelated /24 must not be blocked"
    );

    // Flood stops: subsequent ticks see no new drops, so the block is not
    // refreshed and decays once its TTL (1s) elapses.
    h.run_escalation_tick(&mut state, &cfg, SECOND_NS, 3 * SECOND_NS)
        .expect("decay tick");
    assert!(
        !h.cidr_blocked_v4(Ipv4Addr::new(10, 0, 9, 1)).unwrap(),
        "block should decay after TTL without refresh"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
