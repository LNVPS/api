//! What the node's libvirtd must and must not be.
//!
//! These assertions are about somebody else's hardware: the operator's own
//! libvirt has to survive us, and the listener we open has to be one their
//! guests cannot use.

use std::net::{IpAddr, Ipv4Addr};

/// The DN the node is told to accept. Written out here rather than imported,
/// because the node holds no opinion about it: LNVPS states it in the document,
/// and a constant on this side would be a second opinion to disagree with.
const A_DN: &str = "CN=lnvps-marketplace";

use tempfile::TempDir;

use super::*;

fn paths(dir: &TempDir) -> Paths {
    let mut p = Paths::new(dir.path());
    // The unit and systemctl are the two things a test must not reach for real.
    p.unit_dir = dir.path().join("systemd");
    p.systemctl = PathBuf::from("/bin/true");
    p
}

fn params() -> Params {
    Params {
        listen: IpAddr::V4(Ipv4Addr::new(10, 66, 0, 2)),
        ca_pem: "-----BEGIN CERTIFICATE-----\nlnvps-ca\n-----END CERTIFICATE-----\n".to_string(),
        allowed_dn: A_DN.to_string(),
    }
}

/// libvirtd binds the tunnel address and nothing else. The machine's other
/// interfaces are the operator's LAN and their uplink, and a wildcard bind
/// would put a hypervisor control socket on both.
#[test]
fn it_listens_only_on_the_tunnel() {
    let dir = TempDir::new().unwrap();
    let conf = render_libvirtd_conf(&params(), &paths(&dir));

    assert!(conf.contains(r#"listen_addr = "10.66.0.2""#), "{conf}");
    assert!(!conf.contains("0.0.0.0"), "{conf}");
    assert!(
        conf.contains("listen_tcp = 0"),
        "no unauthenticated listener"
    );
    assert!(conf.contains("listen_tls = 1"));
}

/// Only LNVPS's client DN is accepted. The guest bridge shares a namespace with
/// the tunnel interface, so a customer VM can address this listener; the packet
/// filter drops that today, and this is what makes that filter's failure
/// survivable rather than total.
#[test]
fn only_lnvps_may_connect() {
    let dir = TempDir::new().unwrap();
    let conf = render_libvirtd_conf(&params(), &paths(&dir));

    assert!(
        conf.contains(&format!(r#"tls_allowed_dn_list = ["{A_DN}"]"#)),
        "{conf}"
    );
}

/// The unit's two namespace lines are the whole reason this instance exists:
/// the network one puts guest taps on the guest bridge, and the mount one keeps
/// this instance's state out of the operator's libvirt.
#[test]
fn the_unit_isolates_both_namespaces() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);
    let unit = render_unit(&p);

    assert!(
        unit.contains("NetworkNamespacePath=/run/netns/lnvps"),
        "{unit}"
    );
    assert!(unit.contains("PrivateMounts=yes"), "{unit}");
    for path in ["/var/lib/libvirt", "/etc/libvirt", "/run/libvirt"] {
        assert!(
            unit.contains(&format!(":{path}")),
            "{path} must be private: two system libvirtds sharing it contend \
             over domain state and sockets\n{unit}"
        );
    }
}

/// libvirtd is given both CAs, because it validates its own certificate against
/// the same file it validates clients with — with only LNVPS's CA it refuses to
/// start at all.
#[test]
fn the_trust_file_carries_both_cas() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);
    let id = generate_identity(params().listen).unwrap();
    apply(&p, &params(), &id).unwrap();

    let trust = fs::read_to_string(p.trust()).unwrap();
    assert!(
        trust.contains(id.ca_pem.trim()),
        "the node's own CA is missing"
    );
    assert!(
        trust.contains(params().ca_pem.trim()),
        "LNVPS's CA is missing"
    );
    assert!(
        render_libvirtd_conf(&params(), &p).contains(&p.trust().display().to_string()),
        "libvirtd must be pointed at the bundle, not at one CA"
    );
}

/// The pid file lives inside the private tree. libvirtd's default is
/// `/run/libvirtd.pid`, which is in `/run` — a directory this instance does not
/// replace — so leaving it alone means the operator's libvirtd holds the lock
/// and ours refuses to start.
#[test]
fn the_pid_file_cannot_collide_with_the_operators() {
    let dir = TempDir::new().unwrap();
    let unit = render_unit(&paths(&dir));

    assert!(unit.contains("--pid-file /run/libvirt/"), "{unit}");
    assert!(
        unit.contains("BindPaths=") && unit.contains(":/run/libvirt"),
        "the pid file's directory must be one of the private ones\n{unit}"
    );
}

/// A failed start waits before retrying. Without it systemd spends all five
/// attempts in under a second and the operator is left with a rate-limited unit
/// whose final message says nothing about the cause.
#[test]
fn a_failed_start_backs_off() {
    let dir = TempDir::new().unwrap();
    assert!(render_unit(&paths(&dir)).contains("RestartSec="));
}

/// Logs are written directly. `virtlogd` is reached through a socket in
/// `/run/libvirt`, which this instance replaces, so depending on it would mean
/// running a second helper daemon inside the same sandbox.
#[test]
fn it_does_not_need_virtlogd() {
    assert!(render_qemu_conf().contains(r#"stdio_handler = "file""#));
}

/// Applying twice changes nothing the second time. A libvirtd restarted on
/// every poll is one that drops LNVPS's connection on every poll.
#[test]
fn applying_an_unchanged_config_is_a_no_op() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);
    let id = generate_identity(params().listen).unwrap();

    assert!(apply(&p, &params(), &id).unwrap(), "first run writes");
    assert!(!apply(&p, &params(), &id).unwrap(), "second run must not");
}

/// A changed CA is a change: LNVPS rotating its client CA has to reach the node,
/// or the next connection is refused by a node nobody told.
#[test]
fn a_rotated_ca_is_applied() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);
    let id = generate_identity(params().listen).unwrap();
    apply(&p, &params(), &id).unwrap();

    let mut rotated = params();
    rotated.ca_pem = "-----BEGIN CERTIFICATE-----\nnew-ca\n-----END CERTIFICATE-----\n".to_string();
    assert!(apply(&p, &rotated, &id).unwrap());
    assert_eq!(fs::read_to_string(p.ca()).unwrap(), rotated.ca_pem);
}

/// The identity persists across restarts, because LNVPS pins the certificate:
/// regenerating one every start would make the node unreachable until it was
/// re-registered.
#[test]
fn an_identity_survives_a_restart() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);
    let listen = params().listen;

    let first = load_or_generate_identity(&p, listen).unwrap();
    let second = load_or_generate_identity(&p, listen).unwrap();
    assert_eq!(first.cert_pem, second.cert_pem);
    assert_eq!(
        first.ca_pem, second.ca_pem,
        "LNVPS pins the CA, not the leaf"
    );
}

/// A moved tunnel address means a new certificate. libvirt's client refuses a
/// certificate that does not name the address it dialled, so keeping the old one
/// would leave the node silently unreachable.
#[test]
fn a_moved_address_regenerates_the_identity() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);

    let first = load_or_generate_identity(&p, params().listen).unwrap();
    let moved = load_or_generate_identity(&p, IpAddr::V4(Ipv4Addr::new(10, 66, 0, 9))).unwrap();
    assert_ne!(first.cert_pem, moved.cert_pem);
}

fn der_of(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

/// basicConstraints CA:TRUE with pathLen 0, as DER.
const CA_TRUE: [u8; 8] = [0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00];

/// The node roots its own chain: a CA LNVPS registers, and a leaf libvirtd
/// serves. It cannot be one certificate doing both — libvirt refuses to serve a
/// CA certificate ("basic constraints show a CA, but we need one for a server"),
/// and LNVPS needs a root to verify a chain against.
#[test]
fn the_node_roots_its_own_chain() {
    let id = generate_identity(params().listen).unwrap();

    assert!(
        der_of(&id.ca_pem).windows(8).any(|w| w == CA_TRUE),
        "what LNVPS registers must be a CA"
    );
    assert!(
        !der_of(&id.cert_pem).windows(8).any(|w| w == CA_TRUE),
        "what libvirtd serves must not be a CA, or gnutls refuses to start"
    );
    assert_ne!(id.ca_pem, id.cert_pem);
}

/// The private key is owner-only. The machine has users the operator has given
/// accounts to, and this key is what authenticates their node's hypervisor.
#[test]
#[cfg(unix)]
fn the_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let p = paths(&dir);
    load_or_generate_identity(&p, params().listen).unwrap();

    let mode = fs::metadata(p.key()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "key mode {mode:o}");
}

/// A failing systemctl is reported rather than swallowed: a node that believes
/// it is serving VMs while its libvirtd is dead is one LNVPS keeps placing
/// customers on.
#[test]
fn a_failing_systemctl_is_an_error() {
    let dir = TempDir::new().unwrap();
    let mut p = paths(&dir);
    p.systemctl = PathBuf::from("/bin/false");

    assert!(ensure_running(&p, true).is_err());
    assert!(!is_running(&p));
}

/// The happy path runs the commands and says nothing.
#[test]
fn a_working_systemctl_is_quiet() {
    let dir = TempDir::new().unwrap();
    let p = paths(&dir);

    ensure_running(&p, true).unwrap();
    ensure_running(&p, false).unwrap();
    assert!(is_running(&p), "/bin/true reports active");
}

/// A daemon that cannot find systemctl says so, rather than reporting a node
/// that is fine.
#[test]
fn a_missing_systemctl_is_an_error() {
    let dir = TempDir::new().unwrap();
    let mut p = paths(&dir);
    p.systemctl = dir.path().join("no-such-systemctl");

    assert!(ensure_running(&p, false).is_err());
    assert!(!is_running(&p));
}

/// The identity never prints its key, because a daemon that logs its own state
/// on error would otherwise put it in the operator's journal.
#[test]
fn the_identity_does_not_print_its_key() {
    let id = generate_identity(params().listen).unwrap();
    let shown = format!("{id:?}");

    assert!(!shown.contains("PRIVATE KEY"), "{shown}");
    assert!(!shown.contains(&id.key_pem), "{shown}");
    assert!(shown.contains("cert_pem"));
}

/// Paths default to the machine's real locations; a test that never asserted
/// this could pass while the daemon wrote its unit into a temp directory.
#[test]
fn defaults_point_at_the_machine() {
    let p = Paths::new(Path::new("/var/lib/lnvps-node"));

    assert_eq!(p.unit_dir, PathBuf::from("/etc/systemd/system"));
    assert_eq!(p.systemctl, PathBuf::from("/usr/bin/systemctl"));
    assert_eq!(p.netns_root, PathBuf::from("/run/netns"));
    assert_eq!(p.netns_name, "lnvps");
    assert!(p.conf().starts_with("/var/lib/lnvps-node/libvirt"));
    assert_eq!(p.unit().file_name().unwrap(), UNIT);
}

/// The reported state carries the certificate, so a node that regenerated its
/// identity can be re-pinned by LNVPS instead of by a support ticket.
#[test]
fn the_reported_state_carries_the_certificate() {
    let state = LibvirtState {
        configured: true,
        running: true,
        listen: Some("10.66.0.2:16514".to_string()),
        cert_pem: Some("-----BEGIN CERTIFICATE-----".to_string()),
    };

    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(serde_json::from_str::<LibvirtState>(&json).unwrap(), state);
}
