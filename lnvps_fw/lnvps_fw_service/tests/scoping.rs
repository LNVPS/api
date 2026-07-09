//! Destination-scoping tests. With scoping enabled, XDP only counts/mitigates
//! traffic to protected prefixes and passes everything else untouched (so a
//! forwarding router never touches transit traffic it doesn't own). An empty
//! protected set (scoping off) keeps the single-NIC host "protect everything"
//! behavior, covered by the other suites.
//!
//! Root-only and `#[ignore]`d; run with `scripts/fw-e2e.sh --test scoping`.

mod harness;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use harness::netns::VM_V4;
use harness::traffic;
use harness::{Harness, require_root};

/// A destination outside the protected set is passed and NOT counted, even if a
/// mitigation flag is (stale-ly) set on it.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn unprotected_destination_is_passed_and_uncounted() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_scoped(true).expect("enable scoping");
    // Protect an unrelated prefix that does NOT cover VM_V4 (10.0.1.2).
    h.set_protected_v4(Ipv4Addr::new(203, 0, 113, 0), 24)
        .expect("protect prefix");
    // Even with a mitigation flag on VM_V4, it must be ignored (out of scope).
    h.set_mitigate_v4(VM_V4).expect("force mitigate");

    let dst = SocketAddr::from((VM_V4, 9999)); // closed port
    let sent = traffic::udp_send_burst(&attacker_ns(&h), dst, 20).expect("burst");
    assert_eq!(sent, 20);

    std::thread::sleep(Duration::from_millis(150));
    assert!(
        h.dest_counters_v4(VM_V4).expect("counters").is_none(),
        "out-of-scope destination must not be counted or dropped"
    );
}

/// A destination inside the protected set is still counted and mitigated.
#[test]
#[ignore = "requires root / CAP_NET_ADMIN"]
fn protected_destination_is_still_mitigated() {
    if !require_root() {
        return;
    }
    let mut h = Harness::new().expect("harness setup");
    h.set_scoped(true).expect("enable scoping");
    // VM_V4 is 10.0.1.2 -> protect 10.0.1.0/24.
    h.set_protected_v4(Ipv4Addr::new(10, 0, 1, 0), 24)
        .expect("protect prefix");
    h.set_mitigate_v4(VM_V4).expect("force mitigate");

    let dst = SocketAddr::from((VM_V4, 9999)); // closed port
    let sent = traffic::udp_send_burst(&attacker_ns(&h), dst, 20).expect("burst");
    assert_eq!(sent, 20);

    std::thread::sleep(Duration::from_millis(150));
    let dropped = h
        .dest_counters_v4(VM_V4)
        .expect("counters")
        .expect("in-scope destination is counted")
        .dropped;
    assert!(
        dropped >= 20,
        "in-scope closed-port traffic dropped: {dropped}"
    );
}

fn attacker_ns(h: &Harness) -> String {
    format!("/var/run/netns/{}", h.topo.attacker_ns)
}
