//! Increment-2 smoke tests exercising the increment-1 datapath through the
//! virtualized-network harness.
//!
//! These require root and are `#[ignore]`d; run them with:
//!
//! ```sh
//! scripts/fw-e2e.sh          # builds the ebpf object, then runs as root
//! ```
//!
//! or manually: `sudo -E cargo test -p lnvps_fw_service --test smoke -- --ignored`.

mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::netns::{ATTACKER_V4, VM_V4};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::PacketLimits;

/// The XDP program attaches cleanly to a veth uplink in SKB mode.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn prog_attaches_on_veth() {
    if !require_root() {
        return;
    }
    let _h = Harness::new().expect("harness setup");
}

/// UDP traffic to the VM address is counted by the per-destination counters.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn dest_counters_increment() {
    if !require_root() {
        return;
    }
    let h = Harness::new().expect("harness setup");

    let dst = SocketAddr::from((VM_V4, 9999));
    for _ in 0..5 {
        traffic::udp_send(&attacker_ns(&h), dst, b"ping").expect("udp send");
    }

    let counters = h
        .dest_counters_v4(VM_V4)
        .expect("read counters")
        .expect("counters exist for VM_V4");
    assert!(counters.packets >= 5, "packets={}", counters.packets);
    assert!(counters.udp_packets >= 5, "udp={}", counters.udp_packets);
}

/// A UDP datagram to a learned/open port is forwarded through the filter to a
/// real listening socket in the vm namespace.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn udp_delivered_to_vm_listener() {
    if !require_root() {
        return;
    }
    let h = Harness::new().expect("harness setup");

    let vm_ns = vm_ns(&h);
    let bind: SocketAddr = SocketAddr::from((VM_V4, 7777));
    let recv =
        std::thread::spawn(move || traffic::udp_recv_once(&vm_ns, bind, Duration::from_secs(3)));

    // Give the listener a moment to bind before sending.
    std::thread::sleep(Duration::from_millis(300));
    traffic::udp_send(&attacker_ns(&h), bind, b"hello-vm").expect("udp send");

    let got = recv.join().expect("recv thread").expect("recv result");
    assert_eq!(got.as_deref(), Some(&b"hello-vm"[..]));
}

/// Over-rate SYNs to a destination are dropped by the per-dest SYN limiter.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn syn_rate_limit_drops_over_rate() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    // Tighten the limiter so a small burst trips it: 5-token burst, 10/s.
    h.set_syn_limits_v4(
        VM_V4,
        PacketLimits {
            limit: 10,
            burst: 5,
        },
    )
    .expect("set syn limits");

    let sent =
        traffic::syn_flood_v4(&attacker_ns(&h), ATTACKER_V4, VM_V4, 80, 50).expect("syn flood");
    assert!(sent >= 40, "kernel accepted only {sent} packets");

    let counters = h
        .dest_counters_v4(VM_V4)
        .expect("read counters")
        .expect("counters exist for VM_V4");
    assert!(
        counters.syn_packets >= 40,
        "syn_packets={}",
        counters.syn_packets
    );
    assert!(
        counters.dropped >= 1,
        "expected drops, dropped={}",
        counters.dropped
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}

fn vm_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.vm_ns)
}
