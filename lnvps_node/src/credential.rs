//! The node's credential: the token LNVPS issued for this machine.
//!
//! A node authenticates as itself, never as its operator. The token carries the
//! node's own id and its own revocation counter, so a compromised machine costs
//! the operator that node and nothing else — not their account, not their other
//! nodes.
//!
//! There is deliberately no nostr-key option. The node signs nothing: inbound
//! control requests are verified against LNVPS's key (see
//! [`crate::control_auth`]), and outbound calls carry this token. A second
//! credential kind that authenticates nothing would just be a way to
//! misconfigure a node.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Where the node's token lives.
///
/// Always a file path, never an inline value: a config file gets copied into
/// issue reports and configuration management, and a token pasted into it leaks
/// with the first person who asks for the config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialConfig {
    /// Path to the file holding the token, as issued at registration.
    pub file: PathBuf,
}

/// The node's token, ready to authenticate requests to LNVPS.
pub struct Credential {
    token: String,
}

impl std::fmt::Debug for Credential {
    /// Hand-written: the derived form would print the token, and this type ends
    /// up inside anyhow errors and log lines.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

impl Credential {
    /// Load the token named by `config`.
    pub fn load(config: &CredentialConfig) -> Result<Self> {
        let contents = fs::read_to_string(&config.file)
            .with_context(|| format!("Cannot read credential file {}", config.file.display()))?;
        Self::parse(&contents, &config.file)
    }

    /// Load and check that the file is not readable by other users.
    ///
    /// Separate from [`load`](Self::load) so the parsing tests do not need to
    /// create files with specific modes, and so a caller that has already
    /// checked the path does not check twice.
    pub fn load_checked(config: &CredentialConfig) -> Result<Self> {
        check_permissions(&config.file)?;
        Self::load(config)
    }

    /// Parse file contents as a node token.
    ///
    /// Surrounding whitespace is trimmed: every editor and `echo` leaves a
    /// trailing newline, and a token that fails for that reason is a miserable
    /// first-run experience.
    pub fn parse(contents: &str, path: &Path) -> Result<Self> {
        let token = contents.trim();
        if token.is_empty() {
            bail!("Credential file {} is empty", path.display());
        }
        // A JWT has three dot-separated parts. Checking the shape here turns a
        // pasted-wrong-thing into a clear message at startup, rather than a 401
        // from the API that looks like a revoked node.
        if token.split('.').count() != 3 {
            bail!(
                "Credential file {} does not contain a node token (expected three dot-separated \
                 parts, as issued when the node was registered)",
                path.display()
            );
        }
        Ok(Credential {
            token: token.to_string(),
        })
    }

    /// The `Authorization` header value for a call to LNVPS.
    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

/// Refuse a credential file that other users on the machine can read.
///
/// A marketplace node is somebody else's hardware, often with more than one
/// login on it. A key readable by every account is a key that authenticates any
/// of them as the operator, so this is a hard failure rather than a warning —
/// a warning at boot is a warning nobody reads.
#[cfg(unix)]
pub fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("Cannot stat credential file {}", path.display()))?
        .permissions()
        .mode();

    // Group and other bits: read, write or execute for anyone but the owner.
    if mode & 0o077 != 0 {
        bail!(
            "Credential file {} is accessible by other users (mode {:04o}); run: chmod 600 {}",
            path.display(),
            mode & 0o7777,
            path.display()
        );
    }
    Ok(())
}

/// Non-Unix hosts have no mode bits to check. Nodes are Linux-only, so this
/// exists to keep the crate building on a developer's other machine.
#[cfg(not(unix))]
pub fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of what registration hands back.
    const TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuaWQiOjd9.c2ln";

    fn path() -> PathBuf {
        PathBuf::from("/etc/lnvps-node/token")
    }

    #[test]
    fn a_token_becomes_a_bearer_header() {
        let cred = Credential::parse(TOKEN, &path()).unwrap();
        assert_eq!(cred.authorization_header(), format!("Bearer {TOKEN}"));
    }

    /// Every editor and `echo` leaves a trailing newline; a first run that
    /// fails on one is a bad first run.
    #[test]
    fn surrounding_whitespace_is_ignored() {
        let padded = format!("  {TOKEN}\n\n");
        assert_eq!(
            Credential::parse(&padded, &path())
                .unwrap()
                .authorization_header(),
            format!("Bearer {TOKEN}")
        );
    }

    #[test]
    fn an_empty_file_is_rejected() {
        let err = Credential::parse("  \n ", &path()).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    /// Pasting the wrong thing into the token file is the likeliest
    /// misconfiguration. Caught at startup with a message that names what was
    /// expected, rather than surfacing later as a 401 that looks exactly like a
    /// revoked node.
    #[test]
    fn something_that_is_not_a_token_is_rejected() {
        for wrong in [
            "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laq",
            "just-a-string",
            "two.parts",
            "four.parts.here.now",
        ] {
            let err = Credential::parse(wrong, &path()).unwrap_err().to_string();
            assert!(
                err.contains("does not contain a node token"),
                "{wrong}: {err}"
            );
        }
    }

    /// The token must never reach a log line or an error report.
    #[test]
    fn debug_output_never_contains_the_token() {
        let cred = Credential::parse(TOKEN, &path()).unwrap();
        let rendered = format!("{cred:?}");
        assert!(
            !rendered.contains(TOKEN),
            "token leaked into Debug: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }

    #[cfg(unix)]
    mod unix_permissions {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn file_with_mode(mode: u32) -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("token");
            fs::write(&path, TOKEN).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            (dir, path)
        }

        #[test]
        fn an_owner_only_file_is_accepted() {
            let (_dir, path) = file_with_mode(0o600);
            check_permissions(&path).unwrap();
        }

        /// A node runs on somebody else's hardware, often with other logins on
        /// it. Each of these modes hands the node's token to another account on
        /// the box, and with it the ability to act as this node.
        #[test]
        fn a_file_others_can_reach_is_rejected() {
            for mode in [0o640, 0o604, 0o644, 0o660, 0o606, 0o666, 0o601, 0o610] {
                let (_dir, path) = file_with_mode(mode);
                let err = check_permissions(&path).unwrap_err().to_string();
                assert!(
                    err.contains("accessible by other users"),
                    "mode {mode:04o} must be rejected, got: {err}"
                );
                // The message has to say how to fix it.
                assert!(err.contains("chmod 600"), "mode {mode:04o}: {err}");
            }
        }

        #[test]
        fn load_checked_refuses_before_reading_the_secret() {
            let (_dir, path) = file_with_mode(0o644);
            let config = CredentialConfig { file: path };
            assert!(Credential::load_checked(&config).is_err());
            // ...but the same file with sane permissions loads.
            fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                Credential::load_checked(&config)
                    .unwrap()
                    .authorization_header(),
                format!("Bearer {TOKEN}")
            );
        }

        #[test]
        fn a_missing_file_names_the_path() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("absent");
            let err = check_permissions(&path).unwrap_err().to_string();
            assert!(err.contains("absent"), "got: {err}");
        }
    }
}
