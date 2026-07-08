//! Increment-4 harness tests: attack detection + phase-1 enforcement.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test mitigation`.

mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::netns::{ATTACKER_V4, VM_V4};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{
    DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, PROTO_TCP, PROTO_UDP,
};
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
        src_rate_pps: u64::MAX, // don't block sources in this test
        fanout: 4,
        block_ttl_ns: SECOND_NS,
        escalate_pass_pps: u64::MAX,
        max_real_sources: 10_000,
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

/// A CIDR-blocked source is only dropped when the SOURCE_BLOCK flag is set, not
/// with PORT_FILTER alone — protection flags are independent and source blocking
/// is only enabled when userspace decides it's warranted.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn source_block_only_when_flag_set() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    // Learn an open UDP port so the port filter would PASS this traffic; then
    // any drop we observe is attributable to source blocking, not the port gate.
    traffic::udp_send_from(
        &vm_ns(&h),
        7000,
        SocketAddr::from((ATTACKER_V4, 9999)),
        b"learn",
    )
    .expect("learn port");
    std::thread::sleep(Duration::from_millis(200));
    assert!(h.open_port_v4(VM_V4, 7000, PROTO_UDP).unwrap().is_some());

    // Block the attacker's source and mitigate the dest with only PORT_FILTER.
    h.block_cidr_v4(ATTACKER_V4, 32).expect("block cidr");
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_PORT_FILTER)
        .expect("port filter only");

    let open = SocketAddr::from((VM_V4, 7000));
    let before = h
        .dest_counters_v4(VM_V4)
        .unwrap()
        .map(|c| c.dropped)
        .unwrap_or(0);
    traffic::udp_send_burst(&attacker_ns(&h), open, 10).expect("send lvl1");
    let mid = h.dest_counters_v4(VM_V4).unwrap().unwrap().dropped;
    assert_eq!(
        mid - before,
        0,
        "at PORT_FILTER a blocked source to an open port must pass"
    );

    // Add the SOURCE_BLOCK flag: now the blocked source is dropped even though
    // the port filter would have passed it (flags are independent).
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_PORT_FILTER | DEST_MODE_SOURCE_BLOCK)
        .expect("port filter + source block");
    traffic::udp_send_burst(&attacker_ns(&h), open, 10).expect("send lvl4");
    let after = h.dest_counters_v4(VM_V4).unwrap().unwrap().dropped;
    assert!(
        after - mid >= 10,
        "at SOURCE_BLOCK the blocked source must be dropped (delta={})",
        after - mid
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}

fn vm_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.vm_ns)
}
