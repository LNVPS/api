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

/// The DN LNVPS's client certificate carries.
///
/// libvirtd is told to accept this and nothing else, so a certificate signed by
/// the same CA for some other purpose still cannot drive the node.
pub const LNVPS_CLIENT_DN: &str = "CN=lnvps-marketplace";

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
    /// Where namespaces are pinned; matches [`crate::netns`].
    pub netns_root: PathBuf,
}

impl Paths {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("libvirt"),
            unit_dir: PathBuf::from("/etc/systemd/system"),
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            netns_root: PathBuf::from(netns::NETNS_DIR),
        }
    }

    fn conf(&self) -> PathBuf {
        self.root.join("libvirtd.conf")
    }

    fn cert(&self) -> PathBuf {
        self.root.join("pki/server-cert.pem")
    }

    fn key(&self) -> PathBuf {
        self.root.join("pki/server-key.pem")
    }

    fn ca(&self) -> PathBuf {
        self.root.join("pki/ca-cert.pem")
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

/// The instance's TLS identity: what libvirtd presents to LNVPS.
///
/// Self-signed, and marked as a CA so LNVPS can use the certificate itself as
/// the trust anchor for this one node. libvirt verifies a chain rather than
/// pinning a hash, so the registered certificate has to be usable as a root —
/// the alternative is running a CA that signs every node's server certificate,
/// which is a key to hold and a rotation to run for no additional guarantee.
#[derive(Clone)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for Identity {
    /// The private key never reaches a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
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
        && stored_address(paths) == Some(listen)
    {
        return Ok(Identity { cert_pem, key_pem });
    }

    let identity = generate_identity(listen)?;
    let dir = paths.root.join("pki");
    fs::create_dir_all(&dir).context("libvirt pki directory")?;
    write_private(&paths.key(), identity.key_pem.as_bytes())?;
    fs::write(paths.cert(), identity.cert_pem.as_bytes()).context("libvirt server certificate")?;
    fs::write(dir.join("server-addr"), listen.to_string()).context("libvirt server address")?;
    info!("generated a libvirt server identity for {listen}");
    Ok(identity)
}

/// Generate a self-signed CA-capable certificate naming `listen`.
pub fn generate_identity(listen: IpAddr) -> Result<Identity> {
    let mut params = rcgen::CertificateParams::new(vec![listen.to_string()])
        .map_err(|e| anyhow::anyhow!("Certificate parameters rejected: {e}"))?;
    // Its own trust anchor: LNVPS pins this certificate as the CA for this node.
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, listen.to_string());

    let key =
        rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| anyhow::anyhow!("Self-signing failed: {e}"))?;

    Ok(Identity {
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
    fs::read_to_string(paths.root.join("pki/server-addr"))
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
        ca = paths.ca().display(),
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
ExecStart=/usr/sbin/libvirtd --listen --config {root}/libvirtd.conf
Restart=on-failure

# Guest taps are created in the namespace of the libvirtd that starts the
# domain, and the guest bridge only exists in this one.
NetworkNamespacePath={netns}

# A private view of libvirt's state, so this instance and the operator's do not
# contend over domain state, storage pools or sockets.
PrivateMounts=yes
BindPaths={root}/lib:/var/lib/libvirt
BindPaths={root}/etc:/etc/libvirt
BindPaths={root}/run:/run/libvirt
BindPaths={root}/cache:/var/cache/libvirt

[Install]
WantedBy=multi-user.target
"#,
        netns = netns::path(&paths.netns_root, netns::NAMESPACE).display(),
    )
}

/// Write everything this instance needs, returning whether anything changed.
///
/// Idempotent, and reports change rather than restarting unconditionally: a
/// libvirtd restarted on every poll is one that drops LNVPS's connection every
/// poll, and customer VMs keep running across a restart only because nothing
/// asked them not to.
pub fn apply(paths: &Paths, params: &Params, identity: &Identity) -> Result<bool> {
    for dir in ["lib", "etc", "run", "cache", "pki"] {
        fs::create_dir_all(paths.root.join(dir))
            .with_context(|| format!("libvirt {dir} directory"))?;
    }

    let mut changed = false;
    changed |= write_if_changed(&paths.cert(), identity.cert_pem.as_bytes())?;
    changed |= write_private_if_changed(&paths.key(), identity.key_pem.as_bytes())?;
    changed |= write_if_changed(&paths.ca(), params.ca_pem.as_bytes())?;
    changed |= write_if_changed(
        &paths.conf(),
        render_libvirtd_conf(params, paths).as_bytes(),
    )?;
    changed |= write_if_changed(
        &paths.root.join("etc/qemu.conf"),
        render_qemu_conf().as_bytes(),
    )?;
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
