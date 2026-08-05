//! Stateless session tokens issued after a successful external (OAuth/OIDC)
//! login.
//!
//! These are standard compact HS256 JWTs signed with a server-side secret. They
//! let external-account users authenticate to the same API surface that Nostr
//! users reach via NIP-98, without the API having to hold a Nostr key on their
//! behalf. The token carries the user's synthetic identity (`sub` = hex-encoded
//! 32-byte `oauth_pubkey`) plus their numeric `uid`, so request handling stays
//! stateless (no per-request DB/IdP round-trip just to authenticate).

use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::single_use::SingleUseGuard;

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
    /// The account's `session_version` at issue time.
    ///
    /// Compared against the stored value on every request; bumping the column
    /// invalidates every token issued before the bump. This is the only way to
    /// revoke a stateless JWT ahead of its expiry. Defaults to 0 so tokens
    /// issued before this claim existed still parse (they are then only valid
    /// while the account remains at version 0).
    #[serde(default)]
    pub ver: u32,
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
    /// Token type. Absent on user tokens (including every one issued before
    /// node tokens existed); [`NODE_TOKEN_TYP`] on a node token.
    ///
    /// Both types are HS256 over the same secret, so without this the only
    /// thing stopping a node token being presented as a user session is that
    /// `sub` and `uid` happen to be required fields. That is an accident of
    /// serde, not a decision, and it would evaporate the day someone gives
    /// them defaults. This makes the separation explicit and testable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
}

/// The `typ` claim marking a token as a node token rather than a user session.
pub const NODE_TOKEN_TYP: &str = "node";

/// Claims carried by a node token.
///
/// A node is not a user: it has no account, cannot be billed, and must not
/// reach any endpoint that authenticates a person. It carries its own numeric
/// id and its own revocation counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeClaims {
    /// Always [`NODE_TOKEN_TYP`].
    pub typ: String,
    /// The marketplace node this token authenticates.
    pub nid: u64,
    /// The node's `token_version` at issue time. Bumping that column revokes
    /// every token issued for **this node** and nothing else — unlike a user's
    /// `session_version`, which would take out their other nodes and their web
    /// sessions with it.
    pub ver: u32,
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
}

/// Node token lifetime.
///
/// Long by design. A node is unattended hardware in somebody else's building:
/// expiry buys almost nothing against an attacker who has the token and will
/// use it immediately, while a short one guarantees an eventual fleet-wide
/// outage as tokens lapse with nobody watching. Revocation is the real control
/// here, and it is immediate and per-node via `token_version`.
pub const NODE_TOKEN_TTL_SECS: u64 = 60 * 60 * 24 * 365 * 10;

/// Issue a token authenticating one marketplace node.
pub fn issue_node_token(node_id: u64, token_version: u32, ttl_secs: u64) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;

    let iat = now_secs();
    let claims = NodeClaims {
        typ: NODE_TOKEN_TYP.to_string(),
        nid: node_id,
        ver: token_version,
        iat,
        exp: iat + ttl_secs,
    };
    let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{payload}");
    let sig = sign(signing_input.as_bytes(), secret);
    Ok(format!("{signing_input}.{sig}"))
}

/// Verify a node token. The caller must still check `ver` against the node's
/// current `token_version`, which is what makes revocation work.
pub fn verify_node_token(token: &str) -> Result<NodeClaims> {
    let claims: NodeClaims = verify_jwt(token)?;
    // A user session must not be usable as a node.
    if claims.typ != NODE_TOKEN_TYP {
        bail!("Not a node token");
    }
    if now_secs() >= claims.exp {
        bail!("Node token expired");
    }
    Ok(claims)
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
pub fn issue_session_token(
    pubkey: &[u8; 32],
    uid: u64,
    session_version: u32,
    ttl_secs: u64,
) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;

    let iat = now_secs();
    let claims = SessionClaims {
        sub: hex::encode(pubkey),
        uid,
        ver: session_version,
        iat,
        exp: iat + ttl_secs,
        typ: None,
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

    // A node token must not authenticate as a person.
    if claims.typ.as_deref() == Some(NODE_TOKEN_TYP) {
        bail!("Node tokens cannot be used as a session");
    }

    if now_secs() >= claims.exp {
        bail!("Session token expired");
    }
    Ok(claims)
}

/// Signature and structural verification shared by every token type, so the
/// two verifiers cannot drift apart on how a token is checked.
fn verify_jwt<T: serde::de::DeserializeOwned>(token: &str) -> Result<T> {
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
        bail!("Malformed token");
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected_sig = BASE64_URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&expected_sig)
        .map_err(|_| anyhow::anyhow!("Invalid token signature"))?;

    Ok(serde_json::from_slice(
        &BASE64_URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())?,
    )?)
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

/// Claims for a short-lived, path-scoped, single-use websocket/HTML auth ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TicketClaims {
    /// Lowercase hex of the 32-byte identity this ticket authenticates.
    sub: String,
    /// Exact request path the ticket is valid for.
    path: String,
    /// Unique id, for single-use enforcement.
    jti: String,
    /// Expiry (unix seconds).
    exp: u64,
}

/// Default ticket lifetime. Deliberately tiny: a ticket only has to survive the
/// round trip from "mint" to "open the websocket".
pub const DEFAULT_TICKET_TTL_SECS: u64 = 30;

/// Hard cap on tracked ticket ids.
const MAX_TRACKED_TICKETS: usize = 100_000;

/// Consumed ticket ids.
static CONSUMED_TICKETS: LazyLock<SingleUseGuard<String>> = LazyLock::new(|| {
    SingleUseGuard::new(
        "auth ticket",
        Duration::from_secs(DEFAULT_TICKET_TTL_SECS * 4),
        MAX_TRACKED_TICKETS,
    )
});

/// Mint a single-use ticket authenticating `pubkey` for exactly `path`.
///
/// Browsers cannot set an `Authorization` header on a WebSocket handshake (or
/// on a plain navigation to an HTML invoice), so those endpoints have to take
/// their credential from the query string — where it lands in access logs,
/// proxy logs and browser history. A ticket makes that exposure inert: it is
/// good for one use, for one path, for [`DEFAULT_TICKET_TTL_SECS`] seconds, and
/// unlike a NIP-98 event it is not a reusable artifact signed by the user's
/// identity key.
pub fn issue_ticket(pubkey: &[u8; 32], path: &str, ttl_secs: u64) -> Result<String> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;
    let claims = TicketClaims {
        sub: hex::encode(pubkey),
        path: path.to_string(),
        jti: hex::encode(rand::random::<[u8; 16]>()),
        exp: now_secs() + ttl_secs,
    };
    let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let sig = sign(payload.as_bytes(), secret);
    Ok(format!("{payload}.{sig}"))
}

/// Verify and burn a ticket, returning the identity it authenticates.
///
/// Fails if the signature is bad, the ticket was minted for a different path,
/// it has expired, or it has already been used.
pub fn consume_ticket(token: &str, path: &str) -> Result<[u8; 32]> {
    let secret = SESSION_SECRET
        .get()
        .ok_or_else(|| anyhow::anyhow!("Session auth not configured"))?;

    let mut parts = token.split('.');
    let payload_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    if payload_b64.is_empty() || sig_b64.is_empty() || parts.next().is_some() {
        bail!("Malformed ticket");
    }

    let expected_sig = BASE64_URL_SAFE_NO_PAD.decode(sig_b64.as_bytes())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&expected_sig)
        .map_err(|_| anyhow::anyhow!("Invalid ticket signature"))?;

    let claims: TicketClaims =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())?)?;

    if claims.path != path {
        bail!("Ticket was not issued for this path");
    }
    if now_secs() >= claims.exp {
        bail!("Ticket expired");
    }

    // Burn last, so an invalid ticket cannot consume a valid one's id.
    CONSUMED_TICKETS
        .consume(claims.jti.clone())
        .map_err(|_| anyhow::anyhow!("Ticket has already been used"))?;

    let bytes = hex::decode(&claims.sub)?;
    if bytes.len() != 32 {
        bail!("Invalid ticket subject length");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
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
    /// Unique token id, used to enforce single use. Defaults to empty for
    /// tokens minted before this field existed; those are simply not
    /// replay-protected (they expire within minutes anyway).
    #[serde(default)]
    jti: String,
    /// Expiry (unix seconds).
    exp: u64,
}

/// Hard cap on tracked challenge ids.
const MAX_TRACKED_CHALLENGES: usize = 100_000;

/// Consumed challenge token ids.
///
/// A WebAuthn ceremony's state lives entirely in the signed token, so without
/// this a captured `login/finish` request body could be resubmitted for the
/// whole challenge TTL to mint additional sessions. The authenticator's
/// signature counter is not a defence: most passkeys report a constant 0.
static CONSUMED_CHALLENGES: LazyLock<SingleUseGuard<String>> = LazyLock::new(|| {
    SingleUseGuard::new(
        "WebAuthn challenge",
        Duration::from_secs(DEFAULT_CHALLENGE_TTL_SECS * 2),
        MAX_TRACKED_CHALLENGES,
    )
});

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
        jti: hex::encode(rand::random::<[u8; 16]>()),
        exp: now_secs() + ttl_secs,
    };
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let sig = sign(payload_b64.as_bytes(), secret);
    Ok(format!("{payload_b64}.{sig}"))
}

/// Verify a challenge token, assert its `purpose` matches, check expiry, mark it
/// as used, and return the wrapped ceremony `payload`.
///
/// **Single use.** A ceremony's state is carried entirely by the token, so a
/// captured finish-step request could otherwise be replayed for the token's
/// whole TTL. The consume step runs last, after the signature, purpose and
/// expiry are known good, so an invalid token cannot burn a valid one's id.
pub fn consume_challenge_token(purpose: &str, token: &str) -> Result<String> {
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
    if !claims.jti.is_empty() {
        CONSUMED_CHALLENGES
            .consume(claims.jti.clone())
            .map_err(|_| anyhow::anyhow!("Challenge token has already been used"))?;
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
            consume_challenge_token("webauthn-reg", &token).unwrap(),
            "{\"k\":1}"
        );

        // Wrong purpose is rejected (on a fresh token, since the one above is
        // now spent).
        let other =
            issue_challenge_token("webauthn-reg", "{\"k\":1}", DEFAULT_CHALLENGE_TTL_SECS).unwrap();
        assert!(consume_challenge_token("webauthn-auth", &other).is_err());
    }

    /// Regression (F-11): the WebAuthn ceremony state lived entirely in the
    /// signed challenge token with nothing marking it as spent, so a captured
    /// `login/finish` body could be replayed for the whole 5 minute TTL to mint
    /// extra sessions. The signature counter is no defence — most passkeys
    /// report a constant 0.
    #[test]
    fn challenge_token_is_single_use() {
        init_session_secret(b"unit-test-secret".to_vec());
        let token = issue_challenge_token("webauthn-auth", "{\"c\":1}", DEFAULT_CHALLENGE_TTL_SECS)
            .unwrap();

        assert!(
            consume_challenge_token("webauthn-auth", &token).is_ok(),
            "first use must succeed"
        );
        assert!(
            consume_challenge_token("webauthn-auth", &token).is_err(),
            "replaying a challenge token must be rejected"
        );
    }

    /// Two separate ceremonies must not collide — each token carries its own id.
    #[test]
    fn challenge_tokens_are_independent() {
        init_session_secret(b"unit-test-secret".to_vec());
        let a = issue_challenge_token("webauthn-auth", "{\"c\":1}", DEFAULT_CHALLENGE_TTL_SECS)
            .unwrap();
        let b = issue_challenge_token("webauthn-auth", "{\"c\":1}", DEFAULT_CHALLENGE_TTL_SECS)
            .unwrap();

        assert_ne!(a, b, "identical payloads must still yield distinct tokens");
        assert!(consume_challenge_token("webauthn-auth", &a).is_ok());
        assert!(
            consume_challenge_token("webauthn-auth", &b).is_ok(),
            "consuming one ceremony must not invalidate another"
        );
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
        let token = issue_session_token(&pk, 42, 0, DEFAULT_SESSION_TTL_SECS).unwrap();
        let claims = verify_session_token(&token).unwrap();
        assert_eq!(claims.uid, 42);
        assert_eq!(claims.pubkey().unwrap(), pk);
    }

    /// Regression (F-10): a session JWT was valid for its full 30 day life with
    /// no way to revoke it. The token now carries the account's
    /// `session_version`, which the auth extractor compares against the stored
    /// value — bumping the column invalidates every outstanding token.
    #[test]
    fn session_token_carries_the_session_version() {
        init_session_secret(b"unit-test-secret".to_vec());

        let pk = [9u8; 32];
        let token = issue_session_token(&pk, 7, 3, DEFAULT_SESSION_TTL_SECS).unwrap();
        let claims = verify_session_token(&token).unwrap();

        assert_eq!(
            claims.ver, 3,
            "the issuing version must round-trip so it can be compared on use"
        );

        // The version is inside the signed payload, so an attacker cannot edit
        // it to dodge a revocation.
        let mut segs: Vec<&str> = token.split('.').collect();
        let forged_payload = BASE64_URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&SessionClaims { ver: 999, ..claims }).unwrap());
        segs[1] = &forged_payload;
        assert!(
            verify_session_token(&segs.join(".")).is_err(),
            "editing the version must invalidate the signature"
        );
    }

    /// A ticket authenticates one identity, for one path, once.
    #[test]
    fn ticket_is_path_scoped_and_single_use() {
        init_session_secret(b"unit-test-secret".to_vec());
        let pk = [3u8; 32];

        let ticket = issue_ticket(&pk, "/api/v1/vm/7/console", DEFAULT_TICKET_TTL_SECS).unwrap();

        // Wrong path is refused (and must not burn the ticket).
        assert!(consume_ticket(&ticket, "/api/v1/vm/8/console").is_err());

        // Correct path yields the identity...
        assert_eq!(consume_ticket(&ticket, "/api/v1/vm/7/console").unwrap(), pk);
        // ...exactly once.
        assert!(
            consume_ticket(&ticket, "/api/v1/vm/7/console").is_err(),
            "a leaked ticket must be useless after its first use"
        );
    }

    /// An expired ticket is refused even on the right path.
    #[test]
    fn ticket_expires() {
        init_session_secret(b"unit-test-secret".to_vec());
        let ticket = issue_ticket(&[4u8; 32], "/api/v1/vm/1/console", 0).unwrap();
        assert!(consume_ticket(&ticket, "/api/v1/vm/1/console").is_err());
    }

    /// A ticket is signed, so the path and subject cannot be edited.
    #[test]
    fn ticket_cannot_be_retargeted() {
        init_session_secret(b"unit-test-secret".to_vec());
        let ticket = issue_ticket(&[5u8; 32], "/api/v1/vm/1/console", 60).unwrap();

        let (payload, sig) = ticket.split_once('.').unwrap();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        // Point it at someone else's VM and at a different identity.
        claims["path"] = serde_json::json!("/api/v1/vm/999/console");
        claims["sub"] = serde_json::json!(hex::encode([6u8; 32]));
        let forged = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());

        assert!(
            consume_ticket(&format!("{forged}.{sig}"), "/api/v1/vm/999/console").is_err(),
            "a retargeted ticket must fail signature verification"
        );
    }

    /// Tokens minted before the `ver` claim existed still parse, defaulting to
    /// version 0 (so they remain valid only while the account is at version 0).
    #[test]
    fn session_token_without_version_defaults_to_zero() {
        init_session_secret(b"unit-test-secret".to_vec());

        // Hand-build a payload with no `ver` field, as the old issuer produced.
        let iat = now_secs();
        let legacy = serde_json::json!({
            "sub": hex::encode([1u8; 32]),
            "uid": 5,
            "iat": iat,
            "exp": iat + 600,
        });
        let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&legacy).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = sign(signing_input.as_bytes(), SESSION_SECRET.get().unwrap());

        let claims = verify_session_token(&format!("{signing_input}.{sig}")).unwrap();
        assert_eq!(claims.ver, 0);
        assert_eq!(claims.uid, 5);
    }

    #[test]
    fn rejects_tampered_token() {
        init_session_secret(b"unit-test-secret".to_vec());
        let token = issue_session_token(&[1u8; 32], 1, 0, DEFAULT_SESSION_TTL_SECS).unwrap();
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
        let token = issue_session_token(&[2u8; 32], 5, 0, 0).unwrap();
        assert!(verify_session_token(&token).is_err());
    }
}

#[cfg(test)]
mod node_token_tests {
    use super::*;

    /// The session secret is process-wide and set once, so these tests share
    /// whatever the rest of the suite installed.
    fn secret() {
        init_session_secret(b"test-secret-for-node-tokens".to_vec());
    }

    #[test]
    fn a_node_token_authenticates_its_node() {
        secret();
        let token = issue_node_token(7, 3, 3600).unwrap();
        let claims = verify_node_token(&token).unwrap();

        assert_eq!(claims.nid, 7);
        assert_eq!(claims.ver, 3);
        assert_eq!(claims.typ, NODE_TOKEN_TYP);
    }

    /// Both token types are HS256 over the same secret. Nothing but the `typ`
    /// claim stops one being presented as the other, so both directions are
    /// checked explicitly rather than left to serde's field requirements.
    #[test]
    fn a_node_token_cannot_be_used_as_a_user_session() {
        secret();
        let node_token = issue_node_token(7, 0, 3600).unwrap();

        verify_session_token(&node_token)
            .expect_err("a node token authenticated as a user account");
    }

    /// The test above passes today only because `SessionClaims` happens to
    /// require `sub` — serde rejects the node token before the `typ` check runs.
    /// That is an accident of field requirements, and it disappears the moment
    /// anyone gives those fields defaults or a node token grows a `sub`. This
    /// exercises the guard itself, with a properly signed token that carries
    /// both the user fields and `typ: node`.
    #[test]
    fn the_type_claim_is_what_separates_the_two_token_kinds() {
        secret();
        let secret_bytes = SESSION_SECRET.get().unwrap();

        let claims = serde_json::json!({
            "sub": hex::encode([4u8; 32]),
            "uid": 42,
            "ver": 0,
            "iat": now_secs(),
            "exp": now_secs() + 3600,
            "typ": NODE_TOKEN_TYP,
        });
        let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let token = format!(
            "{signing_input}.{}",
            sign(signing_input.as_bytes(), secret_bytes)
        );

        // It deserialises cleanly as a user session, so only the typ check can
        // stop it.
        let err = verify_session_token(&token)
            .expect_err("a node token carrying user fields authenticated as that user");
        assert!(
            format!("{err}").contains("Node tokens cannot be used as a session"),
            "rejected for the wrong reason: {err}"
        );
    }

    #[test]
    fn a_user_session_cannot_be_used_as_a_node() {
        secret();
        let user_token = issue_session_token(&[4u8; 32], 42, 0, 3600).unwrap();

        let err =
            verify_node_token(&user_token).expect_err("a user session authenticated as a node");
        // Missing `typ` fails to deserialise as NodeClaims, which is also a
        // rejection — assert only that it did not succeed with a node identity.
        assert!(!format!("{err}").is_empty());
    }

    /// Mirror of the check above, for the other direction. A user session is
    /// rejected today only because it has no `nid` for `NodeClaims` to
    /// deserialise — serde, not a decision. This signs a token that parses
    /// cleanly as node claims but is marked as a user token, so the `typ` check
    /// is the only thing that can refuse it.
    #[test]
    fn a_token_marked_as_a_user_cannot_authenticate_as_a_node() {
        secret();
        let secret_bytes = SESSION_SECRET.get().unwrap();

        let claims = serde_json::json!({
            "typ": "user",
            "nid": 7,
            "ver": 0,
            "iat": now_secs(),
            "exp": now_secs() + 3600,
        });
        let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let token = format!(
            "{signing_input}.{}",
            sign(signing_input.as_bytes(), secret_bytes)
        );

        let err = verify_node_token(&token)
            .expect_err("a token marked as a user session authenticated as a node");
        assert!(
            format!("{err}").contains("Not a node token"),
            "rejected for the wrong reason: {err}"
        );
    }

    #[test]
    fn a_tampered_node_token_is_rejected() {
        secret();
        let token = issue_node_token(7, 0, 3600).unwrap();

        // Swap the node id in the payload and re-encode, leaving the signature.
        let parts: Vec<&str> = token.split('.').collect();
        let payload = BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let mut claims: NodeClaims = serde_json::from_slice(&payload).unwrap();
        claims.nid = 8;
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            parts[2]
        );

        let err = verify_node_token(&forged).expect_err("a node claimed to be a different node");
        assert!(format!("{err}").contains("signature"), "{err}");
    }

    #[test]
    fn an_expired_node_token_is_rejected() {
        secret();
        let token = issue_node_token(7, 0, 0).unwrap();
        let err = verify_node_token(&token).expect_err("an expired token was accepted");
        assert!(format!("{err}").contains("expired"), "{err}");
    }

    /// Expiry is not the revocation mechanism — `token_version` is — so the
    /// default lifetime is deliberately long. A short one would guarantee an
    /// eventual fleet-wide outage as tokens lapse on unattended hardware.
    #[test]
    fn the_default_node_token_lifetime_is_long() {
        assert!(
            NODE_TOKEN_TTL_SECS >= 60 * 60 * 24 * 365,
            "a node token that lapses within a year takes the node offline with nobody watching"
        );
    }
}
