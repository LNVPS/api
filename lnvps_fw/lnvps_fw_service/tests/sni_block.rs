//! TLS-SNI egress blocking on the VM-facing TC hook.
//!
//! Spam/botnet C2 traffic (the `emailmanager.pro` agent installed on rented
//! VMs) cannot be stopped at the IP layer (the C2 sits behind a CDN) nor by
//! DNS (a root-controlled guest brings its own resolver). The ClientHello SNI
//! is the one field the guest cannot change without breaking certificate
//! validation at the far end, so these tests pin the datapath's behaviour on
//! it: a blocked server name is shot and counted, everything else is untouched.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test sni_block`.

mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::netns::{ATTACKER_V4, ATTACKER_V6, VM_V4};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::PROTO_UDP;

/// The C2 name under test (an operator blocklist entry).
const BLOCKED: &str = "emailmanager.pro";
/// A name that is not on the blocklist.
const ALLOWED: &str = "lnvps.net";

/// Drive one guest TLS connection through the filter: the attacker namespace
/// accepts on `port` and reads, while the VM connects and sends `payload`.
/// Returns the bytes that survived the datapath.
fn send_through_filter(h: &Harness, port: u16, payload: Vec<u8>) -> Vec<u8> {
    let listen: SocketAddr = SocketAddr::from((ATTACKER_V4, port));
    let ns = attacker_ns(h);
    let reader =
        std::thread::spawn(move || traffic::tcp_accept_read(&ns, listen, Duration::from_secs(3)));
    // Let the listener bind before the guest dials it.
    std::thread::sleep(Duration::from_millis(300));
    let connected = traffic::tcp_connect_send(&vm_ns(h), listen, &payload, Duration::from_secs(2))
        .expect("send");
    assert!(
        connected,
        "TCP handshake must complete: the SNI filter only drops the ClientHello"
    );
    reader.join().expect("reader thread").expect("read")
}

/// A ClientHello naming a blocked server is dropped in the datapath, and the
/// drop is counted against that hostname (the abuse workflow's confirmation
/// that a freshly-added block is biting).
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn blocked_client_hello_dropped_and_counted() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_sni_blocks(&[443], &[BLOCKED])
        .expect("install blocklist");
    assert_eq!(h.sni_drops(BLOCKED).unwrap(), 0, "no drops before traffic");

    let got = send_through_filter(&h, 443, traffic::client_hello(BLOCKED));
    assert!(
        got.is_empty(),
        "blocked ClientHello reached the far side: {got:02x?}"
    );
    assert!(
        h.sni_drops(BLOCKED).unwrap() >= 1,
        "drop counter did not increment (retransmits may push it above 1)"
    );
    // Only the matching name is counted.
    assert_eq!(h.sni_drops(ALLOWED).unwrap(), 0);
}

/// A ClientHello for any other server name passes through untouched.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn unblocked_client_hello_passes() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_sni_blocks(&[443], &[BLOCKED])
        .expect("install blocklist");

    let hello = traffic::client_hello(ALLOWED);
    let got = send_through_filter(&h, 443, hello.clone());
    assert_eq!(got, hello, "unblocked ClientHello must arrive verbatim");
    assert_eq!(h.sni_drops(BLOCKED).unwrap(), 0, "nothing blocked");
}

/// Traffic that is not an inspected ClientHello is never touched: non-TLS
/// payload on an inspection port, and a genuinely-blocked ClientHello on a port
/// that is not configured for inspection.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn non_tls_and_uninspected_ports_pass() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_sni_blocks(&[443], &[BLOCKED])
        .expect("install blocklist");

    // Plain payload on :443 — first byte is not a TLS handshake record.
    let plain = b"GET / HTTP/1.1\r\nHost: emailmanager.pro\r\n\r\n".to_vec();
    assert_eq!(
        send_through_filter(&h, 443, plain.clone()),
        plain,
        "non-TLS payload on an inspection port must pass"
    );

    // The same blocked ClientHello on a port that is not inspected.
    let hello = traffic::client_hello(BLOCKED);
    assert_eq!(
        send_through_filter(&h, 8443, hello.clone()),
        hello,
        "port 8443 is not configured for inspection"
    );
    assert_eq!(h.sni_drops(BLOCKED).unwrap(), 0, "nothing blocked");
}

/// The IPv6 datapath enforces the same blocklist (its own parse path).
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn blocked_client_hello_dropped_over_ipv6() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_sni_blocks(&[443], &[BLOCKED])
        .expect("install blocklist");

    let listen: SocketAddr = SocketAddr::from((ATTACKER_V6, 443));
    let ns = attacker_ns(&h);
    let reader =
        std::thread::spawn(move || traffic::tcp_accept_read(&ns, listen, Duration::from_secs(3)));
    std::thread::sleep(Duration::from_millis(300));
    let connected = traffic::tcp_connect_send(
        &vm_ns(&h),
        listen,
        &traffic::client_hello(BLOCKED),
        Duration::from_secs(2),
    )
    .expect("send");
    assert!(connected, "IPv6 TCP handshake must complete");
    let got = reader.join().expect("reader thread").expect("read");

    assert!(got.is_empty(), "blocked ClientHello passed over IPv6");
    assert!(h.sni_drops(BLOCKED).unwrap() >= 1, "drop not counted");
}

/// Regression: passive port learning still runs on the same hook with the SNI
/// blocklist installed (the block is an added verdict, not a replacement).
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn port_learning_survives_sni_blocking() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_sni_blocks(&[443], &[BLOCKED])
        .expect("install blocklist");

    traffic::udp_send_from(
        &vm_ns(&h),
        5353,
        SocketAddr::from((ATTACKER_V4, 9999)),
        b"announce",
    )
    .expect("udp send");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        h.open_port_v4(VM_V4, 5353, PROTO_UDP)
            .expect("map read")
            .is_some(),
        "UDP port 5353 was not learned with the SNI blocklist active"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}

fn vm_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.vm_ns)
}
