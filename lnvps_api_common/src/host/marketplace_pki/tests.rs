//! What LNVPS trusts when it dials a node.

use tempfile::TempDir;

use super::*;

fn config(dir: &TempDir) -> MarketplaceLibvirtConfig {
    let ca = dir.path().join("ca.pem");
    let cert = dir.path().join("client.pem");
    let key = dir.path().join("client.key");
    fs::write(&ca, b"lnvps-ca").unwrap();
    fs::write(&cert, b"lnvps-client").unwrap();
    fs::write(&key, b"lnvps-client-key").unwrap();

    MarketplaceLibvirtConfig {
        ca_cert: ca,
        client_cert: cert,
        client_key: key,
        pki_dir: dir.path().join("pki"),
    }
}

/// Each node is verified against its own certificate. One CA for the fleet
/// would mean any node's certificate satisfies a connection to any other —
/// which is precisely the substitution the certificate exists to prevent.
#[test]
fn a_node_is_its_own_trust_anchor() {
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);

    let one = materialise(&cfg, 1, "node-one-cert").unwrap();
    let two = materialise(&cfg, 2, "node-two-cert").unwrap();

    assert_ne!(one, two);
    let anchor_one = fs::read_to_string(one.join("cacert.pem")).unwrap();
    let anchor_two = fs::read_to_string(two.join("cacert.pem")).unwrap();
    assert!(anchor_one.contains("node-one-cert"));
    assert!(
        !anchor_one.contains("node-two-cert"),
        "one node must not be able to answer for another"
    );
    assert!(anchor_two.contains("node-two-cert"));
    // LNVPS's own CA rides along: libvirt's client validates the certificate it
    // presents against this same file.
    assert!(anchor_one.contains("lnvps-ca"), "{anchor_one}");
}

/// LNVPS's own client credentials land beside it, because libvirt reads all of
/// them from one directory.
#[test]
fn lnvps_credentials_are_placed_for_libvirt() {
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);

    let path = materialise(&cfg, 7, "node-cert").unwrap();
    assert_eq!(
        fs::read_to_string(path.join("clientcert.pem")).unwrap(),
        "lnvps-client"
    );
    assert_eq!(
        fs::read_to_string(path.join("clientkey.pem")).unwrap(),
        "lnvps-client-key"
    );
}

/// The client key is owner-only. A key any process on the API host can read is
/// one that drives every marketplace node in the fleet.
#[test]
#[cfg(unix)]
fn the_client_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);
    let path = materialise(&cfg, 3, "node-cert").unwrap();

    let mode = fs::metadata(path.join("clientkey.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

/// Re-presenting the same certificate rewrites nothing. Nodes do this on every
/// poll, so the common case has to be cheap and has to leave a running
/// connection's files alone.
#[test]
fn an_unchanged_certificate_is_a_no_op() {
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);
    let path = materialise(&cfg, 4, "node-cert").unwrap();

    let before = fs::metadata(path.join("cacert.pem"))
        .unwrap()
        .modified()
        .unwrap();
    materialise(&cfg, 4, "node-cert").unwrap();
    let after = fs::metadata(path.join("cacert.pem"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(before, after);
}

/// A node that regenerated its identity is re-anchored, or it stays unreachable
/// for good — a node restored from backup is the ordinary case, not the exotic
/// one.
#[test]
fn a_rotated_certificate_replaces_the_old_one() {
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);

    materialise(&cfg, 5, "old-cert").unwrap();
    let path = materialise(&cfg, 5, "new-cert").unwrap();
    let anchor = fs::read_to_string(path.join("cacert.pem")).unwrap();
    assert!(anchor.contains("new-cert"));
    assert!(
        !anchor.contains("old-cert"),
        "the old anchor must not linger"
    );
}

/// Missing client credentials fail loudly at the point of use. Falling back to
/// an unverified connection would put hypervisor control on an address the
/// node's own guests can reach.
#[test]
fn missing_credentials_are_an_error() {
    let dir = TempDir::new().unwrap();
    let mut cfg = config(&dir);
    cfg.client_cert = dir.path().join("absent.pem");
    // The CA is read first; point the missing file at the one under test.

    let err = materialise(&cfg, 6, "node-cert").unwrap_err();
    assert!(err.to_string().contains("absent.pem"), "{err}");
}

/// The URI names the node's own credential directory and verifies. `no_verify`
/// would make the whole certificate exchange decorative.
#[test]
fn the_uri_verifies_against_the_node() {
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);
    let path = node_pki_path(&cfg, 8);

    let uri = connection_uri("10.66.0.2", &path);
    assert!(
        uri.starts_with("qemu+tls://10.66.0.2:16514/system?"),
        "{uri}"
    );
    assert!(uri.contains("pkipath="), "{uri}");
    assert!(uri.ends_with("/8"), "{uri}");
    assert!(!uri.contains("no_verify"), "{uri}");
}
