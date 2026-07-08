//! Increment-3 harness tests: passive egress port learning via the TC
//! classifier, plus TTL-based GC of learned entries.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test learning`.

mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::netns::{ATTACKER_V4, VM_V4};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{PROTO_TCP, PROTO_UDP};

/// A VM-side TCP listener's SYN-ACK teaches the egress learner that the port
/// is open.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn tcp_open_port_learned() {
    if !require_root() {
        return;
    }
    let h = Harness::new().expect("harness setup");

    let vm_ns = vm_ns(&h);
    let listen: SocketAddr = SocketAddr::from((VM_V4, 8080));
    let acceptor = std::thread::spawn(move || {
        traffic::tcp_listen_accept(&vm_ns, listen, Duration::from_secs(3))
    });

    std::thread::sleep(Duration::from_millis(300));
    let connected = traffic::tcp_connect(&attacker_ns(&h), listen, Duration::from_secs(2))
        .expect("connect call");
    assert!(connected, "attacker could not connect to vm listener");
    assert!(acceptor.join().expect("acceptor thread").expect("accept"));

    // Give the SYN-ACK a beat to traverse the egress hook.
    std::thread::sleep(Duration::from_millis(200));
    let learned = h
        .open_port_v4(VM_V4, 8080, PROTO_TCP)
        .expect("map read")
        .is_some();
    assert!(learned, "TCP port 8080 was not learned as open");
}

/// Outbound UDP from a VM source port is learned as a UDP service.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn udp_service_learned() {
    if !require_root() {
        return;
    }
    let h = Harness::new().expect("harness setup");

    // The VM emits UDP from source port 5353 toward the attacker; nobody needs
    // to be listening on the far side for the egress learner to observe it.
    let dst: SocketAddr = SocketAddr::from((ATTACKER_V4, 9999));
    traffic::udp_send_from(&vm_ns(&h), 5353, dst, b"announce").expect("udp send");

    std::thread::sleep(Duration::from_millis(200));
    let learned = h
        .open_port_v4(VM_V4, 5353, PROTO_UDP)
        .expect("map read")
        .is_some();
    assert!(learned, "UDP port 5353 was not learned");
}

/// The userspace GC removes learned entries older than the TTL.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn ttl_expiry_removes_entry() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");

    traffic::udp_send_from(
        &vm_ns(&h),
        4242,
        SocketAddr::from((ATTACKER_V4, 9999)),
        b"x",
    )
    .expect("udp send");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        h.open_port_v4(VM_V4, 4242, PROTO_UDP).unwrap().is_some(),
        "entry should be learned before GC"
    );

    // A GC pass with a very large TTL keeps the fresh entry.
    let removed = h.gc_open_ports_v4(60 * 1_000_000_000).expect("gc");
    assert_eq!(removed, 0, "fresh entry must survive a long-TTL sweep");
    assert!(h.open_port_v4(VM_V4, 4242, PROTO_UDP).unwrap().is_some());

    // A zero-TTL sweep expires everything learned so far.
    std::thread::sleep(Duration::from_millis(5));
    let removed = h.gc_open_ports_v4(0).expect("gc");
    assert!(removed >= 1, "zero-TTL sweep should remove the entry");
    assert!(
        h.open_port_v4(VM_V4, 4242, PROTO_UDP).unwrap().is_none(),
        "entry should be gone after zero-TTL GC"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}

fn vm_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.vm_ns)
}
