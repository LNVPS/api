//! Increment-4 harness tests: attack detection + phase-1 enforcement.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test mitigation`.

mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::netns::VM_V4;
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SYN_PROXY, PROTO_TCP};
use lnvps_fw_service::detect::DetectionConfig;
use lnvps_fw_service::runtime::{DetectionState, RuntimeConfig};

const SECOND_NS: u64 = 1_000_000_000;

/// While mitigating, traffic to a non-learned (closed) port is dropped.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn mitigation_drops_closed_ports() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_mitigate_v4(VM_V4).expect("force mitigate");

    let before = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .map(|c| c.dropped)
        .unwrap_or(0);

    let dst = SocketAddr::from((VM_V4, 9999)); // never learned
    let sent = traffic::udp_send_burst(&attacker_ns(&h), dst, 20).expect("burst");
    assert_eq!(sent, 20);

    let after = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("counters exist")
        .dropped;
    assert!(
        after >= before + 20,
        "expected >=20 drops, before={before} after={after}"
    );
}

/// While mitigating, traffic to a learned-open port still passes (a real TCP
/// handshake to the VM listener completes).
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn mitigation_allows_learned_ports() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    // Keep a listener up long enough for two connections.
    let vm_ns = vm_ns(&h);
    let listen: SocketAddr = SocketAddr::from((VM_V4, 8080));
    let acceptor = std::thread::spawn(move || {
        traffic::tcp_accept_n(&vm_ns, listen, 2, Duration::from_secs(6))
    });
    std::thread::sleep(Duration::from_millis(300));

    // First connection (learns the open port).
    assert!(
        traffic::tcp_connect(&attacker_ns(&h), listen, Duration::from_secs(2)).expect("connect1"),
        "pre-mitigation connect should succeed"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        h.open_port_v4(VM_V4, 8080, PROTO_TCP).unwrap().is_some(),
        "port 8080 should be learned"
    );

    // Now mitigate, then connect again to the learned-open port.
    h.set_mitigate_v4(VM_V4).expect("force mitigate");
    let ok =
        traffic::tcp_connect(&attacker_ns(&h), listen, Duration::from_secs(2)).expect("connect2");
    assert!(
        ok,
        "connection to learned-open port must pass under mitigation"
    );

    assert_eq!(acceptor.join().expect("acceptor").expect("accept count"), 2);
}

/// A flood flips the destination to Mitigate; once it stops, the cooldown
/// returns it to Normal. Uses the real `runtime::run_detection` with injected
/// timestamps for determinism.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn detection_flip_and_cooldown() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    let det = DetectionConfig {
        pps: 100,
        syn_pps: u64::MAX, // don't trip on SYNs
        bps: u64::MAX,     // don't trip on bytes
        exit_pct: 50,
        cooldown_ns: SECOND_NS,
    };
    let cfg = RuntimeConfig {
        detection: det,
        network: DetectionConfig {
            pps: u64::MAX,
            syn_pps: u64::MAX,
            bps: u64::MAX,
            exit_pct: 50,
            cooldown_ns: SECOND_NS,
        },
        protected_v4: Vec::new(),
        protected_v6: Vec::new(),
        manual_v4: Vec::new(),
        manual_v6: Vec::new(),
        src_rate_pps: u64::MAX, // don't block sources in this test
        src_cooldown_ns: SECOND_NS,
        escalate_pass_pps: u64::MAX,
        syn_proxy_pps: u64::MAX,
    };
    let mut state = DetectionState::default();

    // t0 (=1s): seed snapshots. A non-zero base avoids the `last_sample_ns==0`
    // first-run sentinel colliding with a real timestamp of 0.
    h.run_control_tick(&mut state, &cfg, SECOND_NS)
        .expect("tick t0");
    assert_eq!(h.dest_mode_v4(VM_V4).unwrap(), DEST_MODE_NORMAL);

    // Flood ~500 packets, then sample one second later -> ~500 pps > 100.
    let dst = SocketAddr::from((VM_V4, 9999));
    let sent = traffic::udp_send_burst(&attacker_ns(&h), dst, 500).expect("flood");
    assert!(sent >= 400, "sent only {sent}");
    h.run_control_tick(&mut state, &cfg, 2 * SECOND_NS)
        .expect("tick t1");
    assert_eq!(
        h.dest_mode_v4(VM_V4).unwrap(),
        DEST_MODE_PORT_FILTER,
        "flood should trigger mitigation"
    );

    // Flood stops. Sample at t2 (starts cooldown) and t3 (cooldown elapsed).
    h.run_control_tick(&mut state, &cfg, 3 * SECOND_NS)
        .expect("tick t2");
    assert_eq!(h.dest_mode_v4(VM_V4).unwrap(), DEST_MODE_PORT_FILTER);
    h.run_control_tick(&mut state, &cfg, 4 * SECOND_NS)
        .expect("tick t3");
    assert_eq!(
        h.dest_mode_v4(VM_V4).unwrap(),
        DEST_MODE_NORMAL,
        "cooldown should return dest to normal"
    );
}

/// Regression: a manual operator override (e.g. force SYN_PROXY) must survive
/// the auto-detection state machine. Both write the same dest-state LPM key;
/// before the fix, an unrelated volumetric flood flipped the dest to
/// PORT_FILTER and clobbered the operator's SYN_PROXY flag (the SYN-proxy then
/// silently never engaged), and a mitigation-exit deleted the override outright.
/// The manual flags must be a floor: OR'd into auto flags while mitigating and
/// restored (not removed) on exit.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn manual_override_survives_auto_detection() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    let det = DetectionConfig {
        pps: 100,
        syn_pps: u64::MAX, // a pure-pps flood; auto never adds SYN_PROXY itself
        bps: u64::MAX,
        exit_pct: 50,
        cooldown_ns: SECOND_NS,
    };
    let cfg = RuntimeConfig {
        detection: det,
        network: DetectionConfig {
            pps: u64::MAX,
            syn_pps: u64::MAX,
            bps: u64::MAX,
            exit_pct: 50,
            cooldown_ns: SECOND_NS,
        },
        protected_v4: Vec::new(),
        protected_v6: Vec::new(),
        // Operator forces SYN_PROXY on the VM's /32 (as POST /mitigations does).
        manual_v4: vec![(32, VM_V4.octets(), DEST_MODE_SYN_PROXY)],
        manual_v6: Vec::new(),
        src_rate_pps: u64::MAX,
        src_cooldown_ns: SECOND_NS,
        escalate_pass_pps: u64::MAX,
        syn_proxy_pps: u64::MAX,
    };
    let mut state = DetectionState::default();

    // t0: seed snapshots.
    h.run_control_tick(&mut state, &cfg, SECOND_NS)
        .expect("tick t0");

    // A volumetric (non-SYN) flood trips per-dest detection.
    let dst = SocketAddr::from((VM_V4, 9999));
    let sent = traffic::udp_send_burst(&attacker_ns(&h), dst, 500).expect("flood");
    assert!(sent >= 400, "sent only {sent}");
    h.run_control_tick(&mut state, &cfg, 2 * SECOND_NS)
        .expect("tick t1");
    // Auto adds PORT_FILTER, but the manual SYN_PROXY floor must remain set.
    let mode = h.dest_mode_v4(VM_V4).unwrap();
    assert_eq!(
        mode,
        DEST_MODE_PORT_FILTER | DEST_MODE_SYN_PROXY,
        "auto-detection must OR onto (not replace) the manual SYN_PROXY override"
    );

    // Flood stops: cooldown then exit. The manual floor must be restored, not
    // wiped, when auto-mitigation clears.
    h.run_control_tick(&mut state, &cfg, 3 * SECOND_NS)
        .expect("tick t2");
    h.run_control_tick(&mut state, &cfg, 4 * SECOND_NS)
        .expect("tick t3");
    assert_eq!(
        h.dest_mode_v4(VM_V4).unwrap(),
        DEST_MODE_SYN_PROXY,
        "mitigation-exit must restore the manual override, not delete it"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}

fn vm_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.vm_ns)
}
