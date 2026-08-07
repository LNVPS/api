//! The libvirtd LNVPS drives, and nothing of the operator's.
//!
//! LNVPS manages VMs on a marketplace node by talking to libvirt directly over
//! the tunnel. That requires a libvirtd on the node, and *which* libvirtd it is
//! turns out to be the whole design:
//!
//! - **It runs in the data plane network namespace.** A domain's tap device is
//!   created in the namespace of the libvirtd that starts it, and the guest
//!   bridge only exists inside [`crate::netns::NAMESPACE`]. A libvirtd in the
//!   machine's namespace would build VMs with nowhere to plug them in.
//! - **It is a second instance, not the machine's.** Moving the operator's
//!   libvirtd into our namespace would take the networking off every VM they
//!   already run, and would put their domains inside the connection LNVPS
//!   drives. An operator listing spare capacity on a box they already use is
//!   most of the marketplace pitch, so their libvirt is left alone.
//! - **It gets a private mount namespace too.** Two system libvirtds sharing
//!   `/var/lib/libvirt` is not a supported arrangement and not a subtle failure
//!   either: they contend over domain state, storage pool definitions and their
//!   sockets. Bind-mounting our own directories over libvirt's paths gives the
//!   second instance a complete, separate world at the cost of four lines in a
//!   unit file.
//! - **It logs to files rather than through `virtlogd`.** `virtlogd` is reached
//!   through a socket in `/run/libvirt`, which is one of the paths we replace,
//!   so the host's socket-activated one is not visible. `stdio_handler = "file"`
//!   removes the dependency instead of running a second helper daemon inside the
//!   same sandbox — one fewer moving part on hardware we do not own.
//!
//! Access is TLS with a client certificate. The guest bridge and the tunnel
//! interface share a namespace, so a customer VM can address the node's tunnel
//! endpoint; the packet filter drops that today, but a listener there means one
//! filter regression would otherwise hand a guest control of the node and every
//! other customer on it. A certificate means that regression costs nothing.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use log::info;
use serde::{Deserialize, Serialize};

use crate::netns;

/// The port libvirt uses for TLS, fleet-wide.
///
/// Not configurable per node for the same reason the control port is not: this
/// listener exists only inside the tunnel, and an operator who moves it makes
/// their own node unreachable, which is self-correcting.
pub const TLS_PORT: u16 = 16514;

/// The systemd unit the daemon owns.
pub const UNIT: &str = "lnvps-libvirtd.service";

const DEFAULT_UNIT_DIR: &str = "/etc/systemd/system";
const DEFAULT_SYSTEMCTL: &str = "/usr/bin/systemctl";
const DEFAULT_LIBVIRTD: &str = "/usr/sbin/libvirtd";

/// The directories this instance keeps its own copies of, each bind-mounted
/// over libvirt's usual path.
///
/// One list, used both to create them and to render the unit that mounts them.
/// Two lists would be a mount of a directory nobody made, which systemd reports
/// as a unit that will not start and nothing else.
const PRIVATE_DIRS: [(&str, &str); 4] = [
    ("lib", "/var/lib/libvirt"),
    ("etc", "/etc/libvirt"),
    ("run", "/run/libvirt"),
    ("cache", "/var/cache/libvirt"),
];

/// Where the instance's TLS material lives, relative to its root.
const PKI_DIR: &str = "pki";
const SERVER_CERT: &str = "server-cert.pem";
const SERVER_KEY: &str = "server-key.pem";
/// LNVPS's CA, which decides who may connect.
const CLIENT_CA: &str = "client-ca.pem";
/// Both CAs in one file, which is what libvirtd is given.
const TRUST_BUNDLE: &str = "trust.pem";
/// The node's own CA, which LNVPS registers and verifies the server against.
const NODE_CA: &str = "node-ca.pem";
/// Recorded beside the certificate so the address it names can be checked
/// without parsing X.509.
const SERVER_ADDR: &str = "server-addr";
const CONF: &str = "libvirtd.conf";

/// Where this instance writes its pid file.
///
/// Inside the private `/run/libvirt`, and stated explicitly, because libvirtd's
/// default is `/run/libvirtd.pid` — which is in `/run`, a directory this
/// instance does *not* replace. Two system libvirtds then contend for one lock
/// file and the second refuses to start with "resource temporarily
/// unavailable", naming a path neither of them appears to configure.
const PID_FILE: &str = "/run/libvirt/lnvps-libvirtd.pid";
const QEMU_CONF: &str = "etc/qemu.conf";

/// Where the second instance keeps the state the first one keeps in
/// `/var/lib/libvirt`, `/etc/libvirt` and friends.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Root of this instance's private world, under the node's state dir.
    pub root: PathBuf,
    /// Where the unit file is written.
    pub unit_dir: PathBuf,
    /// `systemctl`, overridable so the plumbing can be tested without root.
    pub systemctl: PathBuf,
    /// The libvirt daemon binary. Named rather than assumed so a machine that
    /// ships it elsewhere — or a harness running a stand-in — does not need the
    /// unit rewritten by hand.
    pub libvirtd: PathBuf,
    /// Where namespaces are pinned; matches [`crate::netns`].
    pub netns_root: PathBuf,
    /// Which namespace the instance runs in. Carried rather than assumed so a
    /// harness can stand a whole node up beside a real one without either
    /// taking the other's guests.
    pub netns_name: String,
}

impl Paths {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("libvirt"),
            unit_dir: PathBuf::from(DEFAULT_UNIT_DIR),
            systemctl: PathBuf::from(DEFAULT_SYSTEMCTL),
            libvirtd: PathBuf::from(DEFAULT_LIBVIRTD),
            netns_root: PathBuf::from(netns::NETNS_DIR),
            netns_name: netns::NAMESPACE.to_string(),
        }
    }

    fn conf(&self) -> PathBuf {
        self.root.join(CONF)
    }

    fn pki(&self) -> PathBuf {
        self.root.join(PKI_DIR)
    }

    fn cert(&self) -> PathBuf {
        self.pki().join(SERVER_CERT)
    }

    fn key(&self) -> PathBuf {
        self.pki().join(SERVER_KEY)
    }

    /// LNVPS's CA: the issuer whose client certificates are accepted.
    fn ca(&self) -> PathBuf {
        self.pki().join(CLIENT_CA)
    }

    /// What libvirtd is actually given as its `ca_file`.
    ///
    /// Both CAs, because libvirtd validates *its own* certificate against this
    /// file as well as its clients': with only LNVPS's CA in it, the daemon
    /// refuses to start with "our own certificate failed validation ... the
    /// certificate hasn't got a known issuer".
    ///
    /// The cost is stated plainly: a client certificate issued by the node's own
    /// CA would also pass this check. `tls_allowed_dn_list` still admits only
    /// LNVPS's DN, and the node's CA key lives on the node — anything holding it
    /// already owns the machine it would be impersonating a client to.
    fn trust(&self) -> PathBuf {
        self.pki().join(TRUST_BUNDLE)
    }

    /// This node's own CA, registered with LNVPS.
    fn node_ca(&self) -> PathBuf {
        self.pki().join(NODE_CA)
    }

    fn unit(&self) -> PathBuf {
        self.unit_dir.join(UNIT)
    }
}

/// What LNVPS tells the node its libvirtd should look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// The node's own tunnel address. libvirtd binds this and nothing else: not
    /// `0.0.0.0`, because the machine's other interfaces are the operator's LAN
    /// and their uplink.
    pub listen: IpAddr,
    /// LNVPS's CA, in PEM. Delivered in the node's data-plane document rather
    /// than compiled in: it is public, the document is already authenticated,
    /// and a compiled-in copy would strand every deployed node on rotation.
    pub ca_pem: String,
    /// The only client DN allowed to connect.
    pub allowed_dn: String,
}

/// The instance's TLS identity: a tiny CA of the node's own, and the server
/// certificate it signs.
///
/// Two certificates rather than one self-signed, CA-capable certificate, which
/// is what this was until libvirt refused it: *"basic constraints show a CA, but
/// we need one for a server"*. libvirt verifies a chain rather than pinning a
/// hash, so LNVPS needs a root to anchor on — and gnutls will not accept a root
/// as the leaf that is served. The node therefore roots its own one-certificate
/// chain: the CA is what LNVPS registers and trusts, the leaf is what libvirtd
/// presents, and LNVPS still runs no CA of its own for node identities, which
/// would be a key to hold and a rotation to run across the fleet.
#[derive(Clone)]
pub struct Identity {
    /// What LNVPS registers and verifies against.
    pub ca_pem: String,
    /// What libvirtd presents. Signed by the CA above.
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for Identity {
    /// The private key never reaches a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("ca_pem", &self.ca_pem)
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
}

/// What the node reports about its libvirtd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibvirtState {
    /// Whether the configuration on disk matches what LNVPS asked for.
    pub configured: bool,
    /// Whether systemd reports the unit as running.
    pub running: bool,
    /// Where it is listening, for an operator reading their own node's status.
    pub listen: Option<String>,
    /// The certificate LNVPS should trust for this node, so a node that
    /// regenerates its identity can be re-pinned without a support ticket.
    pub cert_pem: Option<String>,
}

/// Load the instance's identity, generating one if it does not cover `listen`.
///
/// Regenerated when the address changes, because a certificate that does not
/// name the address it is served on is one libvirt's client refuses — and a
/// node whose tunnel address moved would otherwise be silently unreachable.
pub fn load_or_generate_identity(paths: &Paths, listen: IpAddr) -> Result<Identity> {
    if let Ok(cert_pem) = fs::read_to_string(paths.cert())
        && let Ok(key_pem) = fs::read_to_string(paths.key())
        && let Ok(ca_pem) = fs::read_to_string(paths.node_ca())
        && stored_address(paths) == Some(listen)
    {
        return Ok(Identity {
            ca_pem,
            cert_pem,
            key_pem,
        });
    }

    let identity = generate_identity(listen)?;
    let dir = paths.pki();
    fs::create_dir_all(&dir).context("libvirt pki directory")?;
    write_private(&paths.key(), identity.key_pem.as_bytes())?;
    fs::write(paths.cert(), identity.cert_pem.as_bytes()).context("libvirt server certificate")?;
    fs::write(paths.node_ca(), identity.ca_pem.as_bytes()).context("libvirt node CA")?;
    fs::write(dir.join(SERVER_ADDR), listen.to_string()).context("libvirt server address")?;
    info!("generated a libvirt server identity for {listen}");
    Ok(identity)
}

/// Generate this node's CA and the server certificate it signs.
///
/// Two certificates, because libvirt refuses to serve a CA certificate as a
/// leaf: *"basic constraints show a CA, but we need one for a server"*. LNVPS
/// needs a root to verify a chain against, gnutls will not let that root also
/// be what is served, so the node roots its own one-certificate chain.
pub fn generate_identity(listen: IpAddr) -> Result<Identity> {
    let mut ca_params = rcgen::CertificateParams::new(vec![])
        .map_err(|e| anyhow::anyhow!("CA parameters rejected: {e}"))?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("lnvps-node {listen}"));
    let ca_key =
        rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("CA key generation failed: {e}"))?;
    let ca = ca_params
        .self_signed(&ca_key)
        .map_err(|e| anyhow::anyhow!("Self-signing the CA failed: {e}"))?;

    // The address goes in a SAN: libvirt's client checks the address it dialled
    // against the certificate it was served.
    let mut params = rcgen::CertificateParams::new(vec![listen.to_string()])
        .map_err(|e| anyhow::anyhow!("Certificate parameters rejected: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, listen.to_string());
    params.use_authority_key_identifier_extension = true;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key =
        rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;
    let cert = params
        .signed_by(&key, &ca, &ca_key)
        .map_err(|e| anyhow::anyhow!("Signing the server certificate failed: {e}"))?;

    Ok(Identity {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// The address the stored identity was generated for.
///
/// Recorded next to the certificate rather than read back out of it: parsing
/// X.509 to answer a question we already knew the answer to when we wrote the
/// file is a parser's worth of failure modes for nothing.
fn stored_address(paths: &Paths) -> Option<IpAddr> {
    fs::read_to_string(paths.pki().join(SERVER_ADDR))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// libvirtd's configuration for this instance.
///
/// TLS only: the unix socket stays inside the sandbox for local debugging, and
/// there is no TCP listener without a certificate, because the address it binds
/// is one the node's own guests can reach.
pub fn render_libvirtd_conf(params: &Params, paths: &Paths) -> String {
    format!(
        r#"# Managed by lnvps-node. Local edits are overwritten.
listen_tls = 1
listen_tcp = 0
listen_addr = "{listen}"
tls_port = "{port}"

key_file = "{key}"
cert_file = "{cert}"
ca_file = "{ca}"

# Only LNVPS's client certificate may drive this instance. A certificate signed
# by the same CA for anything else is still refused.
tls_allowed_dn_list = ["{dn}"]

# This instance's socket is private to its mount namespace; the operator's
# libvirtd keeps /run/libvirt to itself.
unix_sock_group = "root"
unix_sock_rw_perms = "0700"
"#,
        listen = params.listen,
        port = TLS_PORT,
        key = paths.key().display(),
        cert = paths.cert().display(),
        ca = paths.trust().display(),
        dn = params.allowed_dn,
    )
}

/// qemu driver configuration for this instance.
pub fn render_qemu_conf() -> String {
    r#"# Managed by lnvps-node. Local edits are overwritten.
# virtlogd is reached through a socket in /run/libvirt, which this instance
# replaces with its own directory, so the host's socket-activated one is not
# visible here. Writing logs directly removes the dependency rather than running
# a second helper daemon inside the same sandbox.
stdio_handler = "file"
"#
    .to_string()
}

/// The systemd unit.
///
/// The two namespace lines are the feature: the network one puts guest taps on
/// the guest bridge, and the mount one keeps this instance's state out of the
/// operator's libvirt.
pub fn render_unit(paths: &Paths) -> String {
    let root = paths.root.display();
    format!(
        r#"# Managed by lnvps-node. Local edits are overwritten.
[Unit]
Description=libvirt daemon for LNVPS marketplace guests
After=network.target

[Service]
Type=notify
ExecStart={libvirtd} --listen --config {root}/{conf} --pid-file {pid}
Restart=on-failure
# A failure here is usually a machine problem — a busy pid file, a namespace
# that has not been built yet — and none of those clear inside a second. Without
# a delay systemd burns its five attempts immediately and leaves the operator a
# rate-limited unit whose last message is "start request repeated too quickly",
# which says nothing about what went wrong.
RestartSec=5

# Guest taps are created in the namespace of the libvirtd that starts the
# domain, and the guest bridge only exists in this one.
NetworkNamespacePath={netns}

# A private view of libvirt's state, so this instance and the operator's do not
# contend over domain state, storage pools or sockets.
PrivateMounts=yes
{binds}
[Install]
WantedBy=multi-user.target
"#,
        libvirtd = paths.libvirtd.display(),
        conf = CONF,
        pid = PID_FILE,
        netns = netns::path(&paths.netns_root, &paths.netns_name).display(),
        binds = PRIVATE_DIRS
            .iter()
            .map(|(name, at)| format!("BindPaths={root}/{name}:{at}\n"))
            .collect::<String>(),
    )
}

/// Write everything this instance needs, returning whether anything changed.
///
/// Idempotent, and reports change rather than restarting unconditionally: a
/// libvirtd restarted on every poll is one that drops LNVPS's connection every
/// poll, and customer VMs keep running across a restart only because nothing
/// asked them not to.
pub fn apply(paths: &Paths, params: &Params, identity: &Identity) -> Result<bool> {
    for dir in PRIVATE_DIRS
        .iter()
        .map(|(name, _)| *name)
        .chain(std::iter::once(PKI_DIR))
    {
        fs::create_dir_all(paths.root.join(dir))
            .with_context(|| format!("libvirt {dir} directory"))?;
    }

    let mut changed = false;
    changed |= write_if_changed(&paths.cert(), identity.cert_pem.as_bytes())?;
    changed |= write_if_changed(&paths.node_ca(), identity.ca_pem.as_bytes())?;
    changed |= write_private_if_changed(&paths.key(), identity.key_pem.as_bytes())?;
    changed |= write_if_changed(&paths.ca(), params.ca_pem.as_bytes())?;
    changed |= write_if_changed(
        &paths.trust(),
        format!("{}\n{}", identity.ca_pem.trim(), params.ca_pem.trim()).as_bytes(),
    )?;
    changed |= write_if_changed(
        &paths.conf(),
        render_libvirtd_conf(params, paths).as_bytes(),
    )?;
    changed |= write_if_changed(&paths.root.join(QEMU_CONF), render_qemu_conf().as_bytes())?;
    changed |= write_if_changed(&paths.unit(), render_unit(paths).as_bytes())?;
    Ok(changed)
}

/// Make sure the unit is enabled and running, restarting it if `changed`.
pub fn ensure_running(paths: &Paths, changed: bool) -> Result<()> {
    if changed {
        systemctl(paths, &["daemon-reload"])?;
    }
    systemctl(paths, &["enable", "--now", UNIT])?;
    if changed {
        systemctl(paths, &["restart", UNIT])?;
    }
    Ok(())
}

/// Whether systemd considers the unit running.
pub fn is_running(paths: &Paths) -> bool {
    Command::new(&paths.systemctl)
        .args(["is-active", "--quiet", UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn systemctl(paths: &Paths, args: &[&str]) -> Result<()> {
    let out = Command::new(&paths.systemctl)
        .args(args)
        .output()
        .with_context(|| format!("running {} {args:?}", paths.systemctl.display()))?;
    if !out.status.success() {
        bail!(
            "systemctl {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<bool> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

fn write_private_if_changed(path: &Path, contents: &[u8]) -> Result<bool> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }
    write_private(path, contents)?;
    Ok(true)
}

/// Write a file only its owner can read. The key authenticates this node's
/// libvirtd, and the machine has users the operator has given accounts to.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
