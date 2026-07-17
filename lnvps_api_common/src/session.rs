//! Stateless session tokens issued after a successful external (OAuth/OIDC)
//! login.
//!
//! These are standard compact HS256 JWTs signed with a server-side secret. They
//! let external-account users authenticate to the same API surface that Nostr
//! users reach via NIP-98, without the API having to hold a Nostr key on their
//! behalf. The token carries the user's synthetic identity (`sub` = hex-encoded
//! 32-byte `oauth_pubkey`) plus their numeric `uid`, so request handling stays
//! stateless (no per-request DB/IdP round-trip just to authenticate).

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Process-wide session signing secret, initialised once at startup from
/// settings via [`init_session_secret`]. When unset, session (`Bearer`) auth is
/// disabled and only Nostr (NIP-98) auth is accepted.
static SESSION_SECRET: OnceLock<Vec<u8>> = OnceLock::new();

/// Default session lifetime (30 days) if the caller does not specify one.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 60 * 60 * 24 * 30;

/// Install the session signing secret. Idempotent — the first non-empty secret
/// wins; subsequent calls are ignored. Returns `true` if this call installed it.
pub fn init_session_secret(secret: impl Into<Vec<u8>>) -> bool {
    let secret = secret.into();
    if secret.is_empty() {
        return false;
    }
    SESSION_SECRET.set(secret).is_ok()
}

/// Whether session (`Bearer` JWT) authentication is enabled.
pub fn session_auth_enabled() -> bool {
    SESSION_SECRET.get().is_some()
}

/// Claims carried by a session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Subject: lowercase hex of the user's 32-byte identity (`oauth_pubkey`).
    pub sub: String,
    /// Numeric user id (fast path so handlers can skip a lookup).
    pub uid: u64,
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
}

impl SessionClaims {
    /// The 32-byte identity this token authenticates, decoded from `sub`.
    pub fn pubkey(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.sub)?;
        if bytes.len() != 32 {
            bail!("Invalid session subject length");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign(signing_input: &[u8], secret: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input);
    BASE64_URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Issue a signed session token for `(pubkey, uid)` valid for `ttl_secs`.
///
/// Returns an error if no session secret has been configured.
pub fn issue_session_token(pubkey: &[u8; 32], uid: u64, ttl_secs: u64) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;

    let iat = now_secs();
    let claims = SessionClaims {
        sub: hex::encode(pubkey),
        uid,
        iat,
        exp: iat + ttl_secs,
    };

    // Fixed HS256 header.
    let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{payload}");
    let sig = sign(signing_input.as_bytes(), secret);
    Ok(format!("{signing_input}.{sig}"))
}

/// Verify a session token and return its claims. Checks signature (constant-time
/// via HMAC verify) and expiry. Errors if session auth is disabled, the token is
/// malformed, the signature is invalid, or it has expired.
pub fn verify_session_token(token: &str) -> Result<SessionClaims> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;

    let mut parts = token.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let payload_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    if header_b64.is_empty()
        || payload_b64.is_empty()
        || sig_b64.is_empty()
        || parts.next().is_some()
    {
        bail!("Malformed session token");
    }

    // Verify signature over "<header>.<payload>".
    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected_sig = BASE64_URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&expected_sig)
        .map_err(|_| anyhow::anyhow!("Invalid session signature"))?;

    let claims: SessionClaims =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())?)?;

    if now_secs() >= claims.exp {
        bail!("Session token expired");
    }
    Ok(claims)
}

/// Claims for a short-lived OAuth CSRF `state` value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateClaims {
    /// Provider tag this login flow was started for.
    prov: String,
    /// Random nonce (hex).
    nonce: String,
    /// Optional per-request post-login redirect URL, validated against the
    /// server allowlist at login time. Round-tripped through the signed state
    /// so the client cannot tamper with it. Omitted when the login used the
    /// configured default redirect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect: Option<String>,
    /// Expiry (unix seconds).
    exp: u64,
}

/// Default CSRF `state` lifetime (10 minutes) — long enough to complete a login.
pub const DEFAULT_STATE_TTL_SECS: u64 = 600;

/// Issue a signed, short-lived CSRF `state` value binding an OAuth login flow to
/// a specific provider. Verified on the callback via [`verify_state_token`].
///
/// `redirect` optionally carries a validated per-request post-login redirect URL
/// (see the OAuth login handler); pass `None` to use the configured default.
pub fn issue_state_token(
    provider: &str,
    nonce: &str,
    redirect: Option<&str>,
    ttl_secs: u64,
) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;
    let claims = StateClaims {
        prov: provider.to_string(),
        nonce: nonce.to_string(),
        redirect: redirect.map(|s| s.to_string()),
        exp: now_secs() + ttl_secs,
    };
    let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let sig = sign(payload.as_bytes(), secret);
    Ok(format!("{payload}.{sig}"))
}

/// Verify a CSRF `state` value and return the provider tag it was issued for,
/// along with the optional per-request redirect URL it carried.
pub fn verify_state_token(token: &str) -> Result<(String, Option<String>)> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;
    let mut parts = token.split('.');
    let payload_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    if payload_b64.is_empty() || sig_b64.is_empty() || parts.next().is_some() {
        bail!("Malformed state token");
    }
    let expected_sig = BASE64_URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&expected_sig)
        .map_err(|_| anyhow::anyhow!("Invalid state signature"))?;
    let claims: StateClaims =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())?)?;
    if now_secs() >= claims.exp {
        bail!("State token expired");
    }
    Ok((claims.prov, claims.redirect))
}

/// Claims wrapping an opaque, server-owned challenge state (e.g. a serialised
/// WebAuthn registration/authentication ceremony) so it can round-trip through
/// the client without server-side storage. The `payload` is signed, so the
/// client cannot tamper with the challenge; `purpose` prevents a token minted
/// for one ceremony being replayed into another.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeClaims {
    /// Ceremony tag, e.g. `webauthn-reg` / `webauthn-auth`.
    purpose: String,
    /// Opaque serialised ceremony state (JSON).
    payload: String,
    /// Expiry (unix seconds).
    exp: u64,
}

/// Default challenge lifetime (5 minutes) — a WebAuthn ceremony round-trip.
pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 300;

/// Issue a signed, short-lived token wrapping an opaque ceremony `payload` under
/// a `purpose` tag. The client echoes it back on the finish step; the server
/// recovers the exact state via [`verify_challenge_token`]. Tamper-proof
/// (HS256), so it is safe to hand server-owned challenge state to the client.
pub fn issue_challenge_token(purpose: &str, payload: &str, ttl_secs: u64) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;
    let claims = ChallengeClaims {
        purpose: purpose.to_string(),
        payload: payload.to_string(),
        exp: now_secs() + ttl_secs,
    };
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let sig = sign(payload_b64.as_bytes(), secret);
    Ok(format!("{payload_b64}.{sig}"))
}

/// Verify a challenge token, assert its `purpose` matches, check expiry, and
/// return the wrapped ceremony `payload`.
pub fn verify_challenge_token(purpose: &str, token: &str) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;
    let mut parts = token.split('.');
    let payload_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    if payload_b64.is_empty() || sig_b64.is_empty() || parts.next().is_some() {
        bail!("Malformed challenge token");
    }
    let expected_sig = BASE64_URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&expected_sig)
        .map_err(|_| anyhow::anyhow!("Invalid challenge signature"))?;
    let claims: ChallengeClaims =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())?)?;
    if claims.purpose != purpose {
        bail!("Challenge purpose mismatch");
    }
    if now_secs() >= claims.exp {
        bail!("Challenge token expired");
    }
    Ok(claims.payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_token_roundtrip() {
        init_session_secret(b"unit-test-secret".to_vec());
        let token =
            issue_challenge_token("webauthn-reg", "{\"k\":1}", DEFAULT_CHALLENGE_TTL_SECS).unwrap();
        assert_eq!(
            verify_challenge_token("webauthn-reg", &token).unwrap(),
            "{\"k\":1}"
        );
        // Wrong purpose is rejected.
        assert!(verify_challenge_token("webauthn-auth", &token).is_err());
    }

    #[test]
    fn state_token_roundtrip() {
        init_session_secret(b"unit-test-secret".to_vec());

        // Without a per-request redirect.
        let token = issue_state_token("google", "abc123", None, DEFAULT_STATE_TTL_SECS).unwrap();
        assert_eq!(
            verify_state_token(&token).unwrap(),
            ("google".to_string(), None)
        );

        // With a per-request redirect that must round-trip intact.
        let token = issue_state_token(
            "github",
            "abc123",
            Some("http://localhost:3000/oauth/complete"),
            DEFAULT_STATE_TTL_SECS,
        )
        .unwrap();
        assert_eq!(
            verify_state_token(&token).unwrap(),
            (
                "github".to_string(),
                Some("http://localhost:3000/oauth/complete".to_string())
            )
        );
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        // OnceLock is process-global; set once for the whole test binary.
        init_session_secret(b"unit-test-secret".to_vec());
        assert!(session_auth_enabled());

        let pk = [7u8; 32];
        let token = issue_session_token(&pk, 42, DEFAULT_SESSION_TTL_SECS).unwrap();
        let claims = verify_session_token(&token).unwrap();
        assert_eq!(claims.uid, 42);
        assert_eq!(claims.pubkey().unwrap(), pk);
    }

    #[test]
    fn rejects_tampered_token() {
        init_session_secret(b"unit-test-secret".to_vec());
        let token = issue_session_token(&[1u8; 32], 1, DEFAULT_SESSION_TTL_SECS).unwrap();
        // Flip a character in the payload segment.
        let mut segs: Vec<&str> = token.split('.').collect();
        let bad_payload = format!("{}x", segs[1]);
        segs[1] = &bad_payload;
        let tampered = segs.join(".");
        assert!(verify_session_token(&tampered).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        init_session_secret(b"unit-test-secret".to_vec());
        // ttl 0 => exp == iat == now, and verify checks `now >= exp`.
        let token = issue_session_token(&[2u8; 32], 5, 0).unwrap();
        assert!(verify_session_token(&token).is_err());
    }
}
