//! Deriving a WireGuard public key from a private one.
//!
//! Here rather than in `lnvps_api_common`, which has the same function: that
//! crate pulls in the database, axum and the payment stack, and none of those
//! belong on a machine whose job is to forward packets.
//!
//! Uses the same WireGuard library the kernel calls go through, so a key this
//! accepts is a key the interface will accept.

use anyhow::{Context, Result};
use defguard_wireguard_rs::key::Key;
use std::str::FromStr;

/// The public half of `private_key`, base64, as WireGuard states keys.
///
/// Used to tell an interface that is already carrying the right key from one
/// that is not, without ever reading the private half back out of the kernel.
pub fn wireguard_public_key_base64(private_key: &str) -> Result<String> {
    Ok(Key::from_str(private_key.trim())
        .context("Not a WireGuard key")?
        .public_key()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_pair_derives() {
        // Generated with `wg genkey | tee /dev/stderr | wg pubkey`.
        let private = "iM7g0lLIF3P7WGZTF8Zgs+A2ZUGZQIS+eEIVN8U9RVo=";
        let public = wireguard_public_key_base64(private).unwrap();
        assert_eq!(public.len(), 44, "a wg key is 32 bytes, base64: {public}");
        // Deriving is a function, not a fresh keypair: the same private half
        // must always give the same public one, or an interface would look
        // drifted on every apply and be rekeyed forever.
        assert_eq!(public, wireguard_public_key_base64(private).unwrap());
    }

    #[test]
    fn something_that_is_not_a_key_is_refused() {
        assert!(wireguard_public_key_base64("hello").is_err());
        assert!(wireguard_public_key_base64("").is_err());
    }
}
