//! How a node proves who it is to the LNVPS API.
//!
//! A node authenticates as a **normal consumer account** — the operator's own
//! account — using the two schemes the API already accepts, so there is no
//! node-specific auth path to keep secure separately:
//!
//! - `Authorization: Nostr <base64 event>` — a NIP-98 event signed per request.
//! - `Authorization: Bearer <jwt>` — a long-lived session token, for installs
//!   where holding a nostr key on the machine is not wanted.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use nostr::prelude::*;
use serde::{Deserialize, Serialize};

/// Which authentication scheme a node's secret is for.
///
/// Named explicitly in config rather than sniffed from the file's contents: a
/// token that happened to start with `nsec1` would otherwise be parsed as a
/// key, and the failure would surface as a confusing signature error rather
/// than "you configured the wrong kind".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    /// A nostr secret key (`nsec1...` bech32, or 64 hex characters).
    NostrKey,
    /// A long-lived session token issued by the API.
    SessionToken,
}

/// Where a node's secret lives.
///
/// The secret is always a file path, never an inline value: a config file gets
/// copied into issue reports and configuration management, and a key pasted
/// into it leaks with the first person who asks for the config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CredentialConfig {
    /// Which scheme the file's contents are for.
    pub kind: CredentialKind,
    /// Path to the file holding the secret.
    pub file: PathBuf,
}

/// A loaded secret, ready to authenticate requests.
pub enum Credential {
    /// Signs a fresh NIP-98 event per request.
    NostrKey(Box<Keys>),
    /// Presented unchanged on every request.
    SessionToken(String),
}

impl std::fmt::Debug for Credential {
    /// Deliberately hand-written: the derived form would print the secret key
    /// and the session token, and this type ends up inside anyhow errors and
    /// log lines.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::NostrKey(keys) => f
                .debug_struct("NostrKey")
                .field("pubkey", &keys.public_key().to_hex())
                .finish(),
            Credential::SessionToken(_) => f.write_str("SessionToken(<redacted>)"),
        }
    }
}

impl Credential {
    /// Load the secret named by `config`.
    pub fn load(config: &CredentialConfig) -> Result<Self> {
        let contents = fs::read_to_string(&config.file)
            .with_context(|| format!("Cannot read credential file {}", config.file.display()))?;
        Self::parse(config.kind, &contents, &config.file)
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

    /// Parse file contents as `kind`.
    ///
    /// Surrounding whitespace is trimmed: every editor and `echo` leaves a
    /// trailing newline, and a key that fails to parse for that reason is a
    /// miserable first-run experience.
    pub fn parse(kind: CredentialKind, contents: &str, path: &Path) -> Result<Self> {
        let secret = contents.trim();
        if secret.is_empty() {
            bail!("Credential file {} is empty", path.display());
        }

        match kind {
            CredentialKind::NostrKey => {
                let key = SecretKey::from_bech32(secret)
                    .or_else(|_| SecretKey::from_hex(secret))
                    .with_context(|| {
                        format!(
                            "Credential file {} is not a nostr secret key (expected nsec1... or 64 hex characters)",
                            path.display()
                        )
                    })?;
                Ok(Credential::NostrKey(Box::new(Keys::new(key))))
            }
            CredentialKind::SessionToken => Ok(Credential::SessionToken(secret.to_string())),
        }
    }

    /// The node's public identity, when it has one.
    ///
    /// A session token identifies an account to the server, but the node cannot
    /// derive a public key from it, so there is nothing to show the operator.
    pub fn public_key(&self) -> Option<String> {
        match self {
            Credential::NostrKey(keys) => Some(keys.public_key().to_hex()),
            Credential::SessionToken(_) => None,
        }
    }

    /// Build the `Authorization` header value for one request.
    ///
    /// NIP-98 events are signed per call and bound to the URL and method, so
    /// this takes both rather than being cached.
    pub fn authorization_header(&self, url: &str, method: &str) -> Result<String> {
        match self {
            Credential::NostrKey(keys) => {
                let event = EventBuilder::new(Kind::HttpAuth, "")
                    .tag(Tag::custom(
                        TagKind::Custom(std::borrow::Cow::Borrowed("u")),
                        vec![url.to_string()],
                    ))
                    .tag(Tag::custom(
                        TagKind::Custom(std::borrow::Cow::Borrowed("method")),
                        vec![method.to_uppercase()],
                    ))
                    .sign_with_keys(keys)
                    .context("Failed to sign NIP-98 event")?;
                Ok(format!("Nostr {}", BASE64.encode(event.as_json())))
            }
            Credential::SessionToken(token) => Ok(format!("Bearer {token}")),
        }
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

    /// A key whose bech32 and hex forms are both known, so the test can prove
    /// the two encodings load to the same identity.
    const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const HEX: &str = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";

    fn path() -> PathBuf {
        PathBuf::from("/etc/lnvps-node/credential")
    }

    #[test]
    fn a_key_loads_from_either_encoding() {
        let from_bech32 = Credential::parse(CredentialKind::NostrKey, NSEC, &path()).unwrap();
        let from_hex = Credential::parse(CredentialKind::NostrKey, HEX, &path()).unwrap();
        assert_eq!(from_bech32.public_key(), from_hex.public_key());
        assert!(from_bech32.public_key().is_some());
    }

    /// Every editor and `echo` leaves a trailing newline; a first run that
    /// fails on one is a bad first run.
    #[test]
    fn surrounding_whitespace_is_ignored() {
        let padded = format!("  {NSEC}\n\n");
        let trimmed = Credential::parse(CredentialKind::NostrKey, &padded, &path()).unwrap();
        let plain = Credential::parse(CredentialKind::NostrKey, NSEC, &path()).unwrap();
        assert_eq!(trimmed.public_key(), plain.public_key());

        let token = Credential::parse(CredentialKind::SessionToken, " abc.def\n", &path()).unwrap();
        assert_eq!(
            token.authorization_header("u", "GET").unwrap(),
            "Bearer abc.def"
        );
    }

    #[test]
    fn an_empty_file_is_rejected() {
        for kind in [CredentialKind::NostrKey, CredentialKind::SessionToken] {
            let err = Credential::parse(kind, "  \n ", &path()).unwrap_err();
            assert!(err.to_string().contains("empty"), "got: {err}");
        }
    }

    /// The wrong file in the key slot must say so, rather than failing later
    /// with an opaque signature error.
    #[test]
    fn a_session_token_in_the_key_slot_is_rejected() {
        let err =
            Credential::parse(CredentialKind::NostrKey, "eyJhbGciOi.token", &path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a nostr secret key"), "got: {msg}");
    }

    #[test]
    fn nip98_headers_are_bound_to_url_and_method() {
        let cred = Credential::parse(CredentialKind::NostrKey, NSEC, &path()).unwrap();
        let header = cred
            .authorization_header("https://api.lnvps.net/api/v1/node", "post")
            .unwrap();

        let encoded = header.strip_prefix("Nostr ").expect("Nostr scheme");
        let json = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        let event: Event = serde_json::from_str(&json).unwrap();

        // A server that trusts the signature is trusting these two tags to
        // stop the event being replayed against a different endpoint.
        event.verify().expect("signature must verify");
        assert_eq!(event.kind, Kind::HttpAuth);
        let tag = |name: &str| {
            event
                .tags
                .iter()
                .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
                .map(|t| t.as_slice()[1].clone())
        };
        assert_eq!(
            tag("u").as_deref(),
            Some("https://api.lnvps.net/api/v1/node")
        );
        // Lowercased in the call above: the tag must still be canonical.
        assert_eq!(tag("method").as_deref(), Some("POST"));
    }

    /// Two requests must not reuse one event, or a captured header could be
    /// replayed. Freshness comes from `created_at` plus a new event id.
    #[test]
    fn every_request_signs_a_fresh_event() {
        let cred = Credential::parse(CredentialKind::NostrKey, NSEC, &path()).unwrap();
        let one = cred
            .authorization_header("https://api.lnvps.net/x", "GET")
            .unwrap();
        let two = cred
            .authorization_header("https://api.lnvps.net/x", "GET")
            .unwrap();
        assert_ne!(one, two, "each request must sign its own event");
    }

    #[test]
    fn session_tokens_are_presented_as_bearer() {
        let cred = Credential::parse(CredentialKind::SessionToken, "abc.def.ghi", &path()).unwrap();
        assert_eq!(
            cred.authorization_header("https://api.lnvps.net/x", "GET")
                .unwrap(),
            "Bearer abc.def.ghi"
        );
        // Nothing to show an operator: the node cannot derive one from a token.
        assert_eq!(cred.public_key(), None);
    }

    /// The secret must not reach a log line or an error report.
    #[test]
    fn debug_output_never_contains_the_secret() {
        let key = Credential::parse(CredentialKind::NostrKey, NSEC, &path()).unwrap();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(NSEC));
        assert!(!rendered.contains(HEX));
        assert!(rendered.contains(&key.public_key().unwrap()));

        let token = Credential::parse(CredentialKind::SessionToken, "s3cret.jwt", &path()).unwrap();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("s3cret"), "got: {rendered}");
    }

    #[cfg(unix)]
    mod permissions {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn file_with_mode(mode: u32) -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("credential");
            fs::write(&path, NSEC).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            (dir, path)
        }

        #[test]
        fn an_owner_only_file_is_accepted() {
            for mode in [0o600, 0o400] {
                let (_dir, path) = file_with_mode(mode);
                check_permissions(&path).unwrap();
            }
        }

        /// A node runs on somebody else's hardware, often with other logins on
        /// it. Each of these modes hands the operator's identity to another
        /// account on the box.
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
            let config = CredentialConfig {
                kind: CredentialKind::NostrKey,
                file: path,
            };
            assert!(Credential::load_checked(&config).is_err());
            // ...but the same file with sane permissions loads.
            fs::set_permissions(&config.file, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                Credential::load_checked(&config)
                    .unwrap()
                    .public_key()
                    .is_some()
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
