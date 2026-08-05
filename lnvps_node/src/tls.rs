//! The node's TLS identity, pinned by LNVPS at registration.
//!
//! Control traffic already runs inside WireGuard, so this is not about
//! confidentiality on the wire. It closes a different gap: NIP-98 authenticates
//! requests *to* the node, but nothing authenticates the node's *responses*.
//! Without server authentication, anything that can answer on the tunnel
//! address — a guest on the same machine that grabbed the IP, a
//! misconfiguration on the route server — could report that a VM started when
//! it did not, or return another node's state.
//!
//! There is no CA involved. The node generates a self-signed certificate, LNVPS
//! records its fingerprint at registration, and every later call checks the
//! presented certificate against that pin. A public CA would add a third party
//! able to issue a certificate for a name we already control out-of-band, which
//! is strictly worse.
//!
//! The pair is **persisted**: the fingerprint is registered once, so minting a
//! new certificate on every restart would break the pin and make the node
//! unreachable.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A loaded or freshly-generated TLS identity.
pub struct NodeTls {
    /// PEM certificate chain, for the listener.
    pub cert_pem: Vec<u8>,
    /// PEM private key, for the listener.
    pub key_pem: Vec<u8>,
    /// Hex SHA-256 of the DER certificate — the value LNVPS pins. Same value
    /// as `openssl x509 -noout -fingerprint -sha256`, without the colons.
    pub fingerprint: String,
    /// True when this certificate is new, so the fingerprint LNVPS has on file
    /// is stale and must be re-registered before it can reach the node again.
    pub generated: bool,
}

impl std::fmt::Debug for NodeTls {
    /// Hand-written: a derived one would print the private key, and this type
    /// ends up in error contexts and log lines. The fingerprint is public by
    /// design — it is the value LNVPS pins — so it is safe to show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeTls")
            .field("fingerprint", &self.fingerprint)
            .field("generated", &self.generated)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Certificate path within the state directory.
pub fn cert_path(state_dir: &Path) -> PathBuf {
    state_dir.join("tls/node.crt")
}

/// Private key path within the state directory.
pub fn key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("tls/node.key")
}

/// Load the persisted identity, generating one if there is none.
///
/// `tunnel_ip` is added as a subject alternative name when known. It is
/// optional because the identity is generated at first start, before the node
/// is paired and has a tunnel address.
pub fn load_or_generate(state_dir: &Path, tunnel_ip: Option<IpAddr>) -> Result<NodeTls> {
    let (cert_p, key_p) = (cert_path(state_dir), key_path(state_dir));

    match (fs::read(&cert_p), fs::read(&key_p)) {
        (Ok(cert_pem), Ok(key_pem)) if !cert_pem.is_empty() && !key_pem.is_empty() => {
            // A certificate that cannot be parsed is a hard failure, not a
            // reason to mint a new one: silently regenerating would change the
            // fingerprint LNVPS pinned, and the node would go unreachable with
            // no indication of why.
            let der = pem_to_der(&cert_pem).with_context(|| {
                format!(
                    "Certificate {} is unreadable; refusing to replace it, because a new one \
                     would not match the fingerprint registered with LNVPS. Delete it and \
                     re-register the node if that is what you intend.",
                    cert_p.display()
                )
            })?;
            Ok(NodeTls {
                fingerprint: fingerprint_sha256(&der),
                cert_pem,
                key_pem,
                generated: false,
            })
        }
        _ => {
            let tls = generate(tunnel_ip)?;
            persist(state_dir, &tls.cert_pem, &tls.key_pem)?;
            Ok(tls)
        }
    }
}

/// Generate a fresh self-signed identity covering `localhost` and, when known,
/// the tunnel address.
pub fn generate(tunnel_ip: Option<IpAddr>) -> Result<NodeTls> {
    let mut sans = vec!["localhost".to_string()];
    if let Some(ip) = tunnel_ip {
        sans.push(ip.to_string());
    }
    let cert = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| anyhow::anyhow!("Self-signed certificate generation failed: {e}"))?;

    Ok(NodeTls {
        fingerprint: fingerprint_sha256(cert.cert.der()),
        cert_pem: cert.cert.pem().into_bytes(),
        key_pem: cert.key_pair.serialize_pem().into_bytes(),
        generated: true,
    })
}

/// Write the pair, with the private key owner-only inside an owner-only
/// directory. The key authenticates this node to LNVPS for the life of the pin.
fn persist(state_dir: &Path, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
    let dir = state_dir.join("tls");

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("Cannot create {}", dir.display()))?;
        fs::write(cert_path(state_dir), cert_pem)?;
        let mut key = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(key_path(state_dir))
            .with_context(|| format!("Cannot write {}", key_path(state_dir).display()))?;
        key.write_all(key_pem)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(&dir)?;
        fs::write(cert_path(state_dir), cert_pem)?;
        fs::write(key_path(state_dir), key_pem)?;
    }
    Ok(())
}

/// Hex SHA-256 of a DER certificate.
pub fn fingerprint_sha256(der: &[u8]) -> String {
    use nostr::hashes::{Hash, sha256};
    sha256::Hash::hash(der).to_string()
}

/// Extract the first certificate's DER bytes from a PEM document.
///
/// Hand-rolled rather than pulling in a PEM crate for twenty lines, but strict:
/// anything that is not a well-formed CERTIFICATE block is an error, because
/// the result decides the fingerprint LNVPS pins.
pub fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let text = std::str::from_utf8(pem).context("Certificate is not valid UTF-8")?;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";

    let start = text.find(begin).context("No BEGIN CERTIFICATE marker")?;
    let body_start = start + begin.len();
    let body_end = text[body_start..]
        .find(end)
        .context("No END CERTIFICATE marker")?
        + body_start;

    let body: String = text[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        bail!("Certificate block is empty");
    }
    BASE64
        .decode(body)
        .context("Certificate body is not valid base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn an_identity_is_generated_on_first_start() {
        let dir = tmp();
        let tls = load_or_generate(dir.path(), None).unwrap();

        assert!(tls.generated, "first start must mint a certificate");
        assert!(!tls.fingerprint.is_empty());
        assert!(cert_path(dir.path()).exists());
        assert!(key_path(dir.path()).exists());
        // A fingerprint is a hex SHA-256: 64 characters.
        assert_eq!(tls.fingerprint.len(), 64);
        assert!(tls.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The pin is registered once. A certificate minted afresh on every restart
    /// would stop matching it, and the node would silently become unreachable.
    #[test]
    fn the_identity_survives_a_restart() {
        let dir = tmp();
        let first = load_or_generate(dir.path(), None).unwrap();
        let second = load_or_generate(dir.path(), None).unwrap();

        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.cert_pem, second.cert_pem);
        assert!(
            !second.generated,
            "a reload must not report itself as newly generated, or the daemon \
             would re-register a pin that has not changed"
        );
    }

    /// Two nodes must not share an identity, or a pin would authenticate the
    /// wrong machine.
    #[test]
    fn every_node_gets_its_own_identity() {
        let (a, b) = (tmp(), tmp());
        let one = load_or_generate(a.path(), None).unwrap();
        let two = load_or_generate(b.path(), None).unwrap();
        assert_ne!(one.fingerprint, two.fingerprint);
    }

    #[test]
    fn the_fingerprint_is_of_the_certificate_that_was_persisted() {
        let dir = tmp();
        let tls = load_or_generate(dir.path(), None).unwrap();

        // Recompute from what is on disk, the way LNVPS will from what is
        // presented on the wire.
        let on_disk = fs::read(cert_path(dir.path())).unwrap();
        let der = pem_to_der(&on_disk).unwrap();
        assert_eq!(fingerprint_sha256(&der), tls.fingerprint);
    }

    /// Regenerating silently would change the pin and make the node
    /// unreachable, with nothing in the logs explaining it.
    #[test]
    fn a_corrupt_certificate_is_a_loud_failure() {
        let dir = tmp();
        load_or_generate(dir.path(), None).unwrap();
        fs::write(cert_path(dir.path()), b"not a certificate").unwrap();

        let err = load_or_generate(dir.path(), None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unreadable"), "got: {msg}");
        assert!(
            msg.contains("re-register"),
            "the message must say what to do: {msg}"
        );
    }

    #[test]
    fn the_tunnel_address_becomes_a_subject_alt_name() {
        let ip: IpAddr = "10.66.0.1".parse().unwrap();
        let tls = generate(Some(ip)).unwrap();
        let der = pem_to_der(&tls.cert_pem).unwrap();

        // The IP appears in the SAN extension as four raw bytes.
        let octets = match ip {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => unreachable!(),
        };
        assert!(
            der.windows(4).any(|w| w == octets),
            "certificate must cover the tunnel address"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp();
        load_or_generate(dir.path(), None).unwrap();

        let key_mode = fs::metadata(key_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            key_mode & 0o077,
            0,
            "key is reachable by other users: {:04o}",
            key_mode & 0o7777
        );

        let dir_mode = fs::metadata(dir.path().join("tls"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            dir_mode & 0o077,
            0,
            "tls directory is reachable by other users: {:04o}",
            dir_mode & 0o7777
        );
    }

    #[test]
    fn pem_parsing_rejects_anything_malformed() {
        for (input, expected) in [
            (&b"garbage"[..], "No BEGIN CERTIFICATE"),
            (
                &b"-----BEGIN CERTIFICATE-----\nQUJD\n"[..],
                "No END CERTIFICATE",
            ),
            (
                &b"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----"[..],
                "block is empty",
            ),
            (
                &b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"[..],
                "not valid base64",
            ),
        ] {
            let err = pem_to_der(input).unwrap_err().to_string();
            assert!(err.contains(expected), "{input:?}: got {err}");
        }
    }

    /// Line endings vary with whatever wrote the file; the fingerprint must not.
    #[test]
    fn pem_parsing_ignores_line_endings_and_padding() {
        let der = pem_to_der(&generate(None).unwrap().cert_pem).unwrap();
        let base64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&der)
        };

        for doc in [
            format!("-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----\n"),
            format!("-----BEGIN CERTIFICATE-----\r\n{base64}\r\n-----END CERTIFICATE-----\r\n"),
            format!("\n\n-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----\n\n\n"),
        ] {
            assert_eq!(pem_to_der(doc.as_bytes()).unwrap(), der);
        }
    }

    /// Known-answer check against the published SHA-256 of the empty string, so
    /// the fingerprint is a real SHA-256 and not some other digest.
    /// The private key must not reach a log line or an error report.
    #[test]
    fn debug_output_never_contains_the_private_key() {
        let tls = generate(None).unwrap();
        let rendered = format!("{tls:?}");
        let key = String::from_utf8(tls.key_pem.clone()).unwrap();
        let body: String = key
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        assert!(!body.is_empty());
        assert!(
            !rendered.contains(&body),
            "key leaked into Debug: {rendered}"
        );
        assert!(rendered.contains(&tls.fingerprint));
    }

    #[test]
    fn fingerprints_are_sha256() {
        assert_eq!(
            fingerprint_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
