//! The trust material LNVPS needs to drive one marketplace node's libvirtd.
//!
//! libvirt's client reads its credentials from a directory (`pkipath`), not
//! from memory, so connecting to a node means having four files on disk. Three
//! of them are LNVPS's and identical for every node; the fourth is the node's
//! own certificate, used as the CA the connection is verified against.
//!
//! That per-node CA is the point. A single CA covering the fleet would mean any
//! node's certificate satisfies a connection to any other node — and the thing
//! being prevented is exactly that: something else answering on a node's tunnel
//! address and reporting that a customer's VM is fine when it is not.
//!
//! The directory is a cache, not a record. The node presents its certificate on
//! every poll, so a deployment that loses this directory — a fresh container, a
//! moved volume — repairs itself within one poll interval, rather than needing
//! somebody to notice and act.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::config::MarketplaceLibvirtConfig;

/// The directory holding one node's credentials.
pub fn node_pki_path(cfg: &MarketplaceLibvirtConfig, node_id: u64) -> PathBuf {
    cfg.pki_dir.join(node_id.to_string())
}

/// Write one node's credential directory, from the certificate it registered.
///
/// Idempotent: called whenever a node presents its certificate, which is every
/// poll, so this runs far more often than anything changes.
pub fn materialise(
    cfg: &MarketplaceLibvirtConfig,
    node_id: u64,
    node_cert_pem: &str,
) -> Result<PathBuf> {
    let dir = node_pki_path(cfg, node_id);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // The node's CA anchors this node and no other. libvirt verifies a chain,
    // so it has to be a certificate rather than the fingerprint the control API
    // pins.
    //
    // LNVPS's own CA is in the same file because libvirt's client validates the
    // certificate *it presents* against this file as well as the one it is
    // served: with only the node's CA in it, every connection fails with "our
    // own certificate failed validation ... hasn't got a known issuer" — an
    // error that names the client's certificate and says nothing about the node.
    // The node's daemon has the mirror image of this, for the same reason.
    let lnvps_ca = fs::read_to_string(&cfg.ca_cert)
        .with_context(|| format!("reading {}", cfg.ca_cert.display()))?;
    let bundle = format!("{}\n{}", node_cert_pem.trim(), lnvps_ca.trim());
    write_if_changed(&dir.join("cacert.pem"), bundle.as_bytes())?;

    copy_if_changed(&cfg.client_cert, &dir.join("clientcert.pem"))?;
    copy_private_if_changed(&cfg.client_key, &dir.join("clientkey.pem"))?;
    Ok(dir)
}

/// The connection URI for a node's libvirtd.
///
/// `pkipath` rather than libvirt's global `~/.pki/libvirt`, because the CA
/// differs per node and a global one would let any node's certificate answer
/// for any other. `no_verify` never appears: the whole purpose of the
/// certificate is that the machine answering is the node LNVPS registered.
pub fn connection_uri(address: &str, pki_dir: &Path) -> String {
    format!(
        "qemu+tls://{address}:{port}/system?pkipath={path}",
        port = crate::node_control::LIBVIRT_TLS_PORT,
        path = pki_dir.display(),
    )
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<bool> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(false);
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

fn copy_if_changed(from: &Path, to: &Path) -> Result<bool> {
    let contents = fs::read(from).with_context(|| format!("reading {}", from.display()))?;
    write_if_changed(to, &contents)
}

/// Copy a private key, owner-only. A key readable by anything else on the API
/// host is one that can drive every marketplace node in the fleet.
fn copy_private_if_changed(from: &Path, to: &Path) -> Result<bool> {
    let contents = fs::read(from).with_context(|| format!("reading {}", from.display()))?;
    if !write_if_changed(to, &contents)? {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(to, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", to.display()))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
