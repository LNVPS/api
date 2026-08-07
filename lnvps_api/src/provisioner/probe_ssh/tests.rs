//! Measuring a guest, and the arithmetic behind the numbers.

use super::*;

/// A fresh keypair per probe. A long-lived key that opened a shell on every
/// operator's node would be the most valuable secret LNVPS holds.
#[test]
fn every_probe_gets_its_own_key() {
    let a = ProbeKey::generate().unwrap();
    let b = ProbeKey::generate().unwrap();

    assert_ne!(a.private_pem, b.private_pem);
    assert_ne!(a.public_openssh, b.public_openssh);
    assert!(
        a.public_openssh.starts_with("ssh-ed25519 "),
        "{}",
        a.public_openssh
    );
    assert!(a.private_pem.contains("OPENSSH PRIVATE KEY"));
}

/// The key the guest is given is the key we log in with. They are written into
/// cloud-init and used by the SSH client separately, so a pair that did not
/// match would look exactly like a node that will not accept logins.
#[test]
fn the_pair_matches() {
    let key = ProbeKey::generate().unwrap();

    let private = russh::keys::decode_secret_key(&key.private_pem, None)
        .expect("the client must be able to load what we generated");
    assert_eq!(
        private.public_key().to_openssh().unwrap(),
        key.public_openssh,
        "the guest would authorise a key we do not hold"
    );
}

/// The private half never reaches a log line, because a probe that failed would
/// otherwise print a key authorised on somebody's machine into our logs.
#[test]
fn a_probe_key_does_not_print_itself() {
    let key = ProbeKey::generate().unwrap();
    let shown = format!("{key:?}");

    assert!(!shown.contains("PRIVATE KEY"), "{shown}");
    assert!(!shown.contains(&key.private_pem));
    assert!(shown.contains(&key.public_openssh));
}

/// Rates are timed rather than parsed out of `dd`, whose output varies with
/// version and locale — a parser returning zero on an unfamiliar line would
/// report healthy nodes as broken.
#[test]
fn a_rate_is_megabytes_per_second() {
    assert_eq!(rate_mb_s(256, Duration::from_secs(1)), 256);
    assert_eq!(rate_mb_s(256, Duration::from_secs(2)), 128);
    assert_eq!(rate_mb_s(100, Duration::from_millis(500)), 200);
}

/// A measurement that took no measurable time reports zero rather than dividing
/// by it. Nothing real is that fast, so this is a broken clock — and a panic
/// here would take out the sweep that runs the probe.
#[test]
fn an_instant_transfer_does_not_divide_by_zero() {
    assert_eq!(rate_mb_s(256, Duration::ZERO), 0);
}

/// The login window is long on purpose: a slow node is a finding to record, and
/// a tight limit would turn "this node is slow" into "this node did not
/// answer", which is less useful and more alarming.
#[test]
fn the_login_window_measures_rather_than_fails() {
    assert!(
        LOGIN_TIMEOUT >= Duration::from_secs(120),
        "a probe must be able to report a slow node as slow"
    );
}

/// A node that never answers is reported as that, with the last thing that went
/// wrong — not as a timeout with no cause, which tells an operator nothing.
#[tokio::test]
async fn a_node_that_never_answers_says_why() {
    let key = ProbeKey::generate().unwrap();
    // Loopback and a port nothing listens on: refused immediately, so the test
    // measures the reporting rather than a TCP timeout.
    let started = Instant::now() - (LOGIN_TIMEOUT - Duration::from_millis(200));

    let Err(err) = wait_for_login("127.0.0.1", 1, "probe", &key, started).await else {
        panic!("nothing is listening on that port");
    };

    assert!(err.to_string().contains("could not log in"), "{err}");
}
