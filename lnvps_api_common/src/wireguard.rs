//! WireGuard key material.
//!
//! LNVPS generates the keys for the interfaces it configures on route servers,
//! rather than an admin pasting in the output of `wg genkey` from a machine
//! they configured by hand. A pool that only records somebody else's key can
//! describe an interface but never create one, which makes provisioning a new
//! route server a manual job with a database entry bolted on afterwards.
//!
//! Peers are the other way round: a node generates its own keypair and presents
//! only the public half, so the private key of a machine LNVPS does not own
//! never exists here.

use anyhow::{Result, bail};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand::TryRngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// A generated interface keypair.
///
/// The private half is base64 because that is the form `wg` reads and writes,
/// and it is what gets stored (encrypted) and pushed to the router. The public
/// half is raw bytes because that is what the database column holds — text
/// would compare case-insensitively under the schema's collation, while base64
/// is case-sensitive.
pub struct WireguardKeypair {
    pub private_key: String,
    pub public_key: Vec<u8>,
}

/// Generate an interface keypair.
///
/// Uses the OS random source directly and fails rather than falling back:
/// silently generating a weak key would produce an interface that looks
/// configured and is not.
pub fn generate_wireguard_keypair() -> Result<WireguardKeypair> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow::anyhow!("No system randomness available for a WireGuard key: {e}"))?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok(WireguardKeypair {
        private_key: BASE64_STANDARD.encode(secret.to_bytes()),
        public_key: public.as_bytes().to_vec(),
    })
}

/// Derive the public key for a stored private key.
///
/// Used to check that what is stored still agrees with what the router serves,
/// and to re-derive after an import. The public key is a function of the
/// private one, so a mismatch is a corrupted or swapped record, not a
/// difference of opinion.
pub fn wireguard_public_key(private_key: &str) -> Result<Vec<u8>> {
    let bytes = BASE64_STANDARD
        .decode(private_key.trim())
        .map_err(|_| anyhow::anyhow!("A WireGuard private key must be base64"))?;
    if bytes.len() != 32 {
        bail!(
            "A WireGuard private key is 32 bytes, got {} — this is not a wg key",
            bytes.len()
        );
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&bytes);
    let secret = StaticSecret::from(fixed);
    Ok(PublicKey::from(&secret).as_bytes().to_vec())
}

/// Render a raw 32-byte key in the base64 form `wg` expects on the wire.
pub fn wireguard_key_to_base64(key: &[u8]) -> String {
    BASE64_STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated key must be a real x25519 keypair in the form `wg` accepts:
    /// 32 bytes, base64, and with the public half derivable from the private
    /// one — which is what lets the stored pair be checked against the router.
    #[test]
    fn a_generated_keypair_is_a_wireguard_keypair() {
        let pair = generate_wireguard_keypair().unwrap();

        let private = BASE64_STANDARD.decode(&pair.private_key).unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(pair.public_key.len(), 32);
        assert_eq!(
            wireguard_public_key(&pair.private_key).unwrap(),
            pair.public_key,
            "the stored public key is not the one this private key produces"
        );
    }

    /// Two pools must not end up sharing an interface key: a peer's handshake
    /// would then be accepted by the wrong route server.
    #[test]
    fn generated_keys_are_not_repeated() {
        let a = generate_wireguard_keypair().unwrap();
        let b = generate_wireguard_keypair().unwrap();
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }

    /// x25519 clamps the private key, so the bytes `wg` stores are not always
    /// the bytes handed in. Round-tripping through the derived public key is
    /// what proves the stored pair agrees with itself.
    #[test]
    fn a_clamped_key_still_round_trips() {
        let raw = [0xffu8; 32];
        let secret = StaticSecret::from(raw);
        let stored = BASE64_STANDARD.encode(secret.to_bytes());
        assert_eq!(
            wireguard_public_key(&stored).unwrap(),
            PublicKey::from(&secret).as_bytes().to_vec()
        );
    }

    /// A key of the wrong length or shape is refused here rather than being
    /// pushed to a router that would reject it with no useful message.
    #[test]
    fn a_malformed_private_key_is_refused() {
        for key in ["not base64!!", "c2hvcnQ="] {
            assert!(wireguard_public_key(key).is_err(), "accepted {key}");
        }
    }

    /// Whitespace around a pasted key is a copy-paste artefact, not a
    /// different key.
    #[test]
    fn surrounding_whitespace_is_ignored() {
        let pair = generate_wireguard_keypair().unwrap();
        let padded = format!("  {}\n", pair.private_key);
        assert_eq!(wireguard_public_key(&padded).unwrap(), pair.public_key);
    }

    #[test]
    fn keys_render_in_the_form_wg_expects() {
        let pair = generate_wireguard_keypair().unwrap();
        assert_eq!(
            wireguard_key_to_base64(&pair.public_key),
            BASE64_STANDARD.encode(&pair.public_key)
        );
        // `wg` public keys are 44 characters of base64 with one pad byte.
        assert_eq!(wireguard_key_to_base64(&pair.public_key).len(), 44);
    }
}
