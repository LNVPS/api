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

    let Err(err) = wait_for_login("127.0.0.1", 1, "probe", &key, Duration::from_millis(600)).await
    else {
        panic!("nothing is listening on that port");
    };

    assert!(err.to_string().contains("could not log in"), "{err}");
}

/// The memory test writes a fixed share of what the guest reports. tmpfs
/// defaults to half of RAM and the guest still has to run, so asking for all of
/// it would fail on a healthy node.
#[test]
fn the_memory_test_leaves_the_guest_room_to_run() {
    // 2 GB guest.
    assert_eq!(touch_mb(2 * 1024 * 1024), 921);
    assert!(touch_mb(2 * 1024 * 1024) < 1024, "under half of RAM");
    // A tiny guest still writes something rather than nothing.
    assert!(touch_mb(512 * 1024) > 0);
}

/// The memory is written *and* released in one command, so a probe that loses
/// its connection halfway does not leave the guest's RAM full.
#[test]
fn the_memory_test_cleans_up_in_the_same_breath() {
    let cmd = touch_command(921);

    assert!(
        cmd.contains("/dev/shm/"),
        "tmpfs is RAM; a file on disk is not"
    );
    assert!(cmd.contains("count=921"));
    assert!(cmd.contains("rm -f"), "{cmd}");
}

/// The write is synced. Without it a node with a slow disk and plenty of RAM
/// reports a gigabyte a second, which is the exact node this is meant to catch.
#[test]
fn the_disk_write_is_not_measuring_the_page_cache() {
    assert!(
        write_command(256).contains("conv=fdatasync"),
        "{}",
        write_command(256)
    );
    assert!(
        READ_COMMAND.contains("rm -f"),
        "a probe must not leave files behind"
    );
}

/// What the guest reports is parsed strictly: a number that failed to parse
/// would otherwise become a memory figure nobody can explain.
#[test]
fn memory_is_read_or_reported_as_unreadable() {
    assert_eq!(parse_mem_total(" 2048000 \n").unwrap(), 2_048_000);
    let err = parse_mem_total("MemTotal: lots").unwrap_err();
    assert!(err.to_string().contains("lots"), "{err}");
}

/// The login deadline does not include provisioning.
///
/// Building the VM includes fetching an OS image the node has never seen and
/// cloning a disk — minutes on a cold node. A deadline measured from the request
/// spends its whole budget there and then reports a healthy guest as
/// unreachable, which is the worst possible answer: it condemns the node for
/// being new.
#[tokio::test]
async fn a_slow_build_does_not_eat_the_login_window() {
    let key = ProbeKey::generate().unwrap();
    // A window that starts when the guest does, not when the request did: the
    // caller has already spent longer than the whole budget on provisioning.
    let began = Instant::now();
    let _ = wait_for_login("127.0.0.1", 1, "probe", &key, Duration::from_millis(600)).await;

    assert!(
        began.elapsed() >= Duration::from_millis(500),
        "the probe gave up without waiting for the guest at all"
    );
}

/// A probe is bounded end to end, and by more than the sum of the parts it
/// already bounds.
///
/// The worker runs jobs one at a time, so a probe that hangs stops `CheckVms`,
/// `CheckSubscriptions`, provisioning and everything else in the deployment —
/// on the say-so of third-party hardware that controls both ends of the
/// connection. The margin over the login window matters too: a slow node has to
/// come back as a slow measurement, which is the finding, rather than as a
/// timeout with no numbers in it.
#[test]
fn a_probe_cannot_run_forever() {
    assert!(
        PROBE_TIMEOUT > LOGIN_TIMEOUT,
        "a node that logs in at the last moment would be cut off before it was measured"
    );
    assert!(
        PROBE_TIMEOUT >= Duration::from_secs(600),
        "a probe must have room to build a VM on a cold node"
    );
}
