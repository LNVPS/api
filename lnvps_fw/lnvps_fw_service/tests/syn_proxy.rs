//! SYN-proxy / SYN-cookie datapath tests. Under the SYN_PROXY flag, TCP SYNs to
//! an open port are answered with a stateless SYN-cookie SYN-ACK (crafted in
//! XDP and XDP_TX'd back); a real client that completes the handshake is marked
//! verified, while spoofed sources that never ACK are not.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test syn_proxy`.

mod harness;

use std::net::SocketAddr;
use std::time::Duration;

use harness::netns::{ATTACKER_V4, ATTACKER_V6, VM_V4, VM_V6};
use harness::traffic;
use harness::{Harness, require_root};
use lnvps_fw_common::{DEST_MODE_SYN_PROXY, PROTO_TCP};

/// A real client's TCP handshake completes through the XDP SYN-cookie (the
/// client kernel only accepts the SYN-ACK if the checksums and cookie are
/// correct), and the source is then marked verified.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn syn_proxy_verifies_real_client() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_open_port_v4(VM_V4, 8080, PROTO_TCP)
        .expect("seed open port");
    h.set_cookie_secret(0x1234_5678).expect("set secret");
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_SYN_PROXY)
        .expect("set syn-proxy flag");

    let dst = SocketAddr::from((VM_V4, 8080));
    let connected =
        traffic::tcp_connect(&attacker_ns(&h), dst, Duration::from_secs(2)).expect("connect call");
    assert!(
        connected,
        "the SYN-cookie handshake should complete (SYN-ACK accepted by client)"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        h.is_verified_v4(ATTACKER_V4).unwrap(),
        "client should be verified after echoing the cookie in its ACK"
    );
}

/// Spoofed sources that send SYNs but never complete the handshake are never
/// verified (they receive a cookie SYN-ACK sent to nowhere).
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn syn_proxy_spoofed_not_verified() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_open_port_v4(VM_V4, 8080, PROTO_TCP)
        .expect("seed open port");
    h.set_cookie_secret(0x1234_5678).expect("set secret");
    h.set_dest_flags_v4(VM_V4, 32, DEST_MODE_SYN_PROXY)
        .expect("set syn-proxy flag");

    let spoofed = std::net::Ipv4Addr::new(10, 0, 0, 77);
    let sent =
        traffic::syn_flood_v4(&attacker_ns(&h), spoofed, VM_V4, 8080, 10).expect("syn flood");
    assert!(sent >= 5, "raw SYNs should be sent");

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !h.is_verified_v4(spoofed).unwrap(),
        "a source that never completes the handshake must not be verified"
    );
}

/// IPv6 counterpart: a real client completes the IPv6 SYN-cookie handshake
/// (exercising the 40-byte header rewrite + pseudo-header TCP checksum) and is
/// then marked verified.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn syn_proxy_v6_verifies_real_client() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_open_port_v6(VM_V6, 8080, PROTO_TCP)
        .expect("seed open port");
    h.set_cookie_secret(0x1234_5678).expect("set secret");
    h.set_dest_flags_v6(VM_V6, 128, DEST_MODE_SYN_PROXY)
        .expect("set syn-proxy flag");

    let dst = SocketAddr::from((VM_V6, 8080));
    let connected =
        traffic::tcp_connect(&attacker_ns(&h), dst, Duration::from_secs(2)).expect("connect call");
    assert!(
        connected,
        "the IPv6 SYN-cookie handshake should complete (SYN-ACK accepted)"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        h.is_verified_v6(ATTACKER_V6).unwrap(),
        "client should be verified after echoing the cookie in its ACK"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
