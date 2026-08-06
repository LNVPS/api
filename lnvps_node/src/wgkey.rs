//! The node's WireGuard keypair.
//!
//! Generated here and kept here: LNVPS is told the public half and never sees
//! the private one. That is the whole reason a node presents a key rather than
//! being issued one — an operator's machine that LNVPS could impersonate would
//! make the tunnel's authentication decorative.
//!
//! The key is generated in-process rather than by shelling out to `wg genkey`,
//! so a node with a broken or missing `wg` fails when it tries to *configure*
//! the interface, with that error, instead of failing here with a confusing
//! one — and so the tests do not need a fake for key generation.
//!
//! These few lines duplicate `lnvps_api_common::wireguard` rather than
//! depending on it: that crate pulls in the database, axum and the payment
//! stack, none of which belong on somebody else's hardware.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::TryRngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// A node's WireGuard identity.
pub struct NodeKey {
    secret: StaticSecret,
    /// True when this run created the key, so the caller can say so once rather
    /// than logging it on every start.
    pub generated: bool,
}

impl std::fmt::Debug for NodeKey {
    /// Hand-written: the derived form would print the private key, and this
    /// type travels through anyhow errors and log lines.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeKey(<redacted>)")
    }
}

impl NodeKey {
    /// The public half, base64, as WireGuard writes keys.
    pub fn public_base64(&self) -> String {
        STANDARD.encode(PublicKey::from(&self.secret).as_bytes())
    }

    /// The public half as raw bytes, which is how LNVPS stores it.
    pub fn public_bytes(&self) -> [u8; 32] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    /// The private half, base64.
    ///
    /// Only for handing to `wg` through a file; it is deliberately not
    /// reachable from `Debug` or `Display`.
    pub fn private_base64(&self) -> String {
        STANDARD.encode(self.secret.to_bytes())
    }
}

/// Where the key lives inside the state directory.
pub fn key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("tunnel.key")
}

/// Load the node's key, generating one on first use.
///
/// A regenerated key is not fatal: LNVPS re-pins a node that presents a new one
/// rather than refusing it, because a machine restored from backup that can
/// never be reached again is worse than a re-pin. The caller still warns, since
/// the tunnel stays down until the new key has been presented.
pub fn load_or_generate(state_dir: &Path) -> Result<NodeKey> {
    let path = key_path(state_dir);
    if path.exists() {
        crate::credential::check_permissions(&path)?;
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Cannot read tunnel key {}", path.display()))?;
        return parse(&contents, &path);
    }

    fs::create_dir_all(state_dir)
        .with_context(|| format!("Cannot create state directory {}", state_dir.display()))?;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow::anyhow!("No system randomness available for a tunnel key: {e}"))?;
    let secret = StaticSecret::from(bytes);
    write_secret(&path, &STANDARD.encode(secret.to_bytes()))?;
    Ok(NodeKey {
        secret,
        generated: true,
    })
}

/// Parse a stored key.
pub fn parse(contents: &str, path: &Path) -> Result<NodeKey> {
    let raw = STANDARD
        .decode(contents.trim())
        .with_context(|| format!("Tunnel key {} is not base64", path.display()))?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "Tunnel key {} is {} bytes; a WireGuard key is 32",
            path.display(),
            raw.len()
        )
    })?;
    Ok(NodeKey {
        secret: StaticSecret::from(bytes),
        generated: false,
    })
}

/// Write `contents` to `path` readable only by its owner.
///
/// The mode is set **before** the key is written, not after: a key that is
/// world-readable for even the moment between the two is a key that a process
/// watching the directory has already read.
#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Cannot write tunnel key {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

/// Non-Unix hosts have no mode bits. Nodes are Linux-only; this exists so the
/// crate still builds on a developer's other machine.
#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("Cannot write tunnel key {}", path.display()))
}

/// Write the private key to a file `wg` can read, inside the state directory.
///
/// `wg set` takes the key as a **path**, never as an argument, because an
/// argument is visible in `ps` to every user on the machine — and a marketplace
/// node usually has more than one login.
pub fn write_private_key_file(state_dir: &Path, key: &NodeKey) -> Result<PathBuf> {
    let path = state_dir.join("tunnel.key.wg");
    write_secret(&path, &key.private_base64())?;
    Ok(path)
}

/// Reject a server key that is not a WireGuard key, before it reaches `wg`.
pub fn parse_public_key(value: &str) -> Result<String> {
    // LNVPS sends hex; `wg` speaks base64. Converting here keeps the wire
    // format consistent with the rest of the node API, where keys are hex.
    let raw = hex::decode(value.trim())
        .with_context(|| format!("Server public key {value} is not hex"))?;
    if raw.len() != 32 {
        bail!(
            "Server public key is {} bytes; a WireGuard key is 32",
            raw.len()
        );
    }
    Ok(STANDARD.encode(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key generated here must be the one that comes back, and the public
    /// half must be derived from it rather than stored beside it — a stored
    /// copy is free to disagree with the key it claims to describe.
    #[test]
    fn a_key_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_generate(dir.path()).unwrap();
        assert!(first.generated);

        let second = load_or_generate(dir.path()).unwrap();
        assert!(!second.generated, "a second start generated a new key");
        assert_eq!(first.public_base64(), second.public_base64());
        assert_eq!(first.private_base64(), second.private_base64());
        assert_eq!(first.public_bytes(), second.public_bytes());
    }

    /// The key is written owner-only from the moment it exists: a marketplace
    /// node usually has more than one login on it.
    #[cfg(unix)]
    #[test]
    fn a_generated_key_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        load_or_generate(dir.path()).unwrap();
        let mode = fs::metadata(key_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "mode {:04o}", mode & 0o7777);
    }

    /// A key file that is readable by everyone is refused rather than used: the
    /// tunnel it authenticates is the node's whole security boundary.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        load_or_generate(dir.path()).unwrap();
        fs::set_permissions(key_path(dir.path()), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_generate(dir.path()).is_err());
    }

    /// The key must not reach a log line or an anyhow error, both of which
    /// this type travels through.
    #[test]
    fn the_key_is_never_printed() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_generate(dir.path()).unwrap();
        let printed = format!("{key:?}");
        assert!(!printed.contains(&key.private_base64()), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
    }

    /// A state directory that cannot hold a key, and a key file that cannot be
    /// read, are reported against the path rather than as a bare io error — the
    /// operator has to know which file to fix.
    #[test]
    fn an_unusable_state_directory_is_reported_with_its_path() {
        let dir = tempfile::tempdir().unwrap();

        // A file where the state directory should be.
        let as_file = dir.path().join("state");
        fs::write(&as_file, "").unwrap();
        let err = load_or_generate(&as_file).unwrap_err();
        assert!(format!("{err:#}").contains("state"), "{err:#}");

        // A directory where the key file should be: it exists, so it is read,
        // and reading it fails.
        let state = dir.path().join("other");
        fs::create_dir_all(key_path(&state)).unwrap();
        let err = load_or_generate(&state).unwrap_err();
        assert!(format!("{err:#}").contains("tunnel.key"), "{err:#}");
    }

    /// Anything that is not 32 bytes of base64 is not a WireGuard key, and
    /// saying so here beats a handshake that never completes.
    #[test]
    fn a_malformed_key_is_refused() {
        let path = Path::new("/tmp/tunnel.key");
        assert!(parse("not base64!", path).is_err());
        assert!(parse(&STANDARD.encode([1u8; 16]), path).is_err());
        assert!(parse(&STANDARD.encode([1u8; 32]), path).is_ok());
    }

    /// The server's key arrives as hex and reaches `wg` as base64; a value that
    /// is neither is refused before it is written into a command.
    #[test]
    fn a_server_key_is_converted_and_checked() {
        assert_eq!(
            parse_public_key(&hex::encode([0xab; 32])).unwrap(),
            STANDARD.encode([0xab; 32])
        );
        assert!(parse_public_key("nonsense").is_err());
        assert!(parse_public_key(&hex::encode([0xab; 16])).is_err());
    }

    /// `wg set` takes a path, never an argument: an argument is visible in `ps`
    /// to every user on the machine.
    #[cfg(unix)]
    #[test]
    fn the_key_file_handed_to_wg_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = load_or_generate(dir.path()).unwrap();
        let path = write_private_key_file(dir.path(), &key).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), key.private_base64());
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode {:04o}", mode & 0o7777);

        // A key file that cannot be written is named, not swallowed: `wg` would
        // otherwise fail later with a path the operator never chose.
        let blocked = tempfile::tempdir().unwrap();
        fs::create_dir_all(blocked.path().join("tunnel.key.wg")).unwrap();
        let err = write_private_key_file(blocked.path(), &key).unwrap_err();
        assert!(format!("{err:#}").contains("tunnel.key.wg"), "{err:#}");
    }
}
