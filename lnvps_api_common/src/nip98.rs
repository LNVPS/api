use anyhow::bail;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, Uri, request::Parts},
};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::debug;
use nostr::{Event, JsonUtil, Kind, PublicKey, Timestamp};

use crate::session::{SessionClaims, verify_session_token};

/// How a request authenticated.
pub enum AuthKind {
    /// NIP-98 signed Nostr HTTP-auth event. `pubkey` is a real Nostr key.
    Nostr(Event),
    /// Session JWT issued after an external (OAuth/OIDC) login. The identity is
    /// a synthetic `oauth_pubkey`, NOT a real Nostr key.
    Session(SessionClaims),
}

/// Request authentication.
///
/// Despite the historical name, this now accepts **two** schemes:
/// - `Authorization: Nostr <base64-event>` — NIP-98 (native Nostr accounts)
/// - `Authorization: Bearer <jwt>` — a session token issued after OAuth login
///
/// Handlers should use [`Nip98Auth::pubkey`] to get the 32-byte identity
/// (works for both schemes) rather than reaching for the underlying event.
pub struct Nip98Auth {
    /// The concrete auth scheme and its payload.
    pub kind: AuthKind,
    /// Resolved 32-byte identity: a real Nostr key for [`AuthKind::Nostr`], or a
    /// synthetic `oauth_pubkey` for [`AuthKind::Session`].
    pubkey: [u8; 32],
}

impl Nip98Auth {
    /// The 32-byte identity that authenticated this request. This is the value
    /// used as the `users.pubkey` primary identity for both Nostr and OAuth
    /// accounts.
    pub fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }

    /// The real Nostr public key, if this request used NIP-98. Returns `None`
    /// for OAuth session auth (whose identity is not a usable Nostr key).
    pub fn nostr_pubkey(&self) -> Option<PublicKey> {
        match &self.kind {
            AuthKind::Nostr(ev) => Some(ev.pubkey),
            AuthKind::Session(_) => None,
        }
    }

    /// The underlying NIP-98 event, if any.
    pub fn event(&self) -> Option<&Event> {
        match &self.kind {
            AuthKind::Nostr(ev) => Some(ev),
            AuthKind::Session(_) => None,
        }
    }

    /// Validate the auth against the request `path`/`method`. For NIP-98 this
    /// checks the `u`/`method` tags, timestamp window and signature. Session
    /// (bearer) tokens are not bound to a path/method (verified at parse time),
    /// so this is a no-op success for them.
    pub fn check(&self, path: &str, method: &str) -> anyhow::Result<()> {
        let event = match &self.kind {
            AuthKind::Nostr(ev) => ev,
            AuthKind::Session(_) => return Ok(()),
        };
        if event.kind != Kind::HttpAuth {
            bail!("Wrong event kind");
        }
        if event
            .created_at
            .as_secs()
            .abs_diff(Timestamp::now().as_secs())
            > 600
        {
            bail!("Created timestamp is out of range");
        }

        // check url tag
        if let Some(url) = event.tags.iter().find_map(|t| {
            let vec = t.as_slice();
            // Use get() to avoid panicking on a malformed single-element tag
            // like ["u"] supplied in an attacker-controlled auth event.
            match (vec.first(), vec.get(1)) {
                (Some(k), Some(v)) if k == "u" => Some(v.clone()),
                _ => None,
            }
        }) {
            // Simple path comparison - extract path from URL
            if let Ok(parsed_uri) = url.parse::<Uri>() {
                if path != parsed_uri.path() {
                    bail!("U tag does not match");
                }
            } else {
                bail!("Invalid U tag");
            }
        } else {
            bail!("Missing url tag");
        }

        // check method tag
        if let Some(t_method) = event.tags.iter().find_map(|t| {
            let vec = t.as_slice();
            match (vec.first(), vec.get(1)) {
                (Some(k), Some(v)) if k == "method" => Some(v.clone()),
                _ => None,
            }
        }) {
            if method != t_method {
                bail!("Method tag incorrect")
            }
        } else {
            bail!("Missing method tag")
        }

        if let Err(_err) = event.verify() {
            bail!("Event signature invalid");
        }

        debug!("{}", event.as_json());
        Ok(())
    }

    /// Parse a NIP-98 auth from a base64-encoded Nostr event (used by the
    /// query-parameter auth-token path). Does not validate path/method.
    pub fn from_base64(i: &str) -> anyhow::Result<Self> {
        if let Ok(j) = BASE64_STANDARD.decode(i) {
            if let Ok(ev) = Event::from_json(j) {
                Ok(Self {
                    pubkey: ev.pubkey.to_bytes(),
                    kind: AuthKind::Nostr(ev),
                })
            } else {
                bail!("Invalid nostr event")
            }
        } else {
            bail!("Invalid auth string");
        }
    }

    /// Build a session (bearer) auth from verified JWT claims.
    fn from_session_claims(claims: SessionClaims) -> anyhow::Result<Self> {
        let pubkey = claims.pubkey()?;
        Ok(Self {
            pubkey,
            kind: AuthKind::Session(claims),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Tag};

    fn signed_auth(tags: Vec<Tag>) -> Nip98Auth {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .custom_created_at(Timestamp::now())
            .sign_with_keys(&keys)
            .unwrap();
        Nip98Auth {
            pubkey: event.pubkey.to_bytes(),
            kind: AuthKind::Nostr(event),
        }
    }

    /// Regression: a validly-signed auth event containing a malformed
    /// single-element `["u"]` tag must NOT panic (previously `vec[1]` indexed
    /// out of bounds). It should be treated as a missing url tag.
    #[test]
    fn malformed_single_element_u_tag_does_not_panic() {
        let auth = signed_auth(vec![
            Tag::parse(["u"]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ]);
        let res = auth.check("/api/v1/account", "GET");
        assert!(res.is_err(), "expected error, not a panic");
    }

    /// Same for a malformed single-element `["method"]` tag.
    #[test]
    fn malformed_single_element_method_tag_does_not_panic() {
        let auth = signed_auth(vec![
            Tag::parse(["u", "https://example.com/api/v1/account"]).unwrap(),
            Tag::parse(["method"]).unwrap(),
        ]);
        let res = auth.check("/api/v1/account", "GET");
        assert!(res.is_err(), "expected error, not a panic");
    }

    /// A well-formed auth event still validates successfully.
    #[test]
    fn well_formed_tags_pass() {
        let auth = signed_auth(vec![
            Tag::parse(["u", "https://example.com/api/v1/account"]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ]);
        assert!(auth.check("/api/v1/account", "GET").is_ok());
    }
}

impl<S> FromRequestParts<S> for Nip98Auth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async {
            let auth_header = parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .ok_or((StatusCode::FORBIDDEN, "Auth header not found".to_string()))?;

            // Session (bearer) scheme: JWT issued after an external OAuth login.
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                let claims = verify_session_token(token.trim())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid session: {}", e)))?;
                return Nip98Auth::from_session_claims(claims)
                    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid session: {}", e)));
            }

            // Nostr (NIP-98) scheme.
            if !auth_header.starts_with("Nostr ") {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Auth scheme must be Nostr or Bearer".to_string(),
                ));
            }

            let auth = Nip98Auth::from_base64(&auth_header[6..])
                .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid auth: {}", e)))?;

            let path = parts.uri.path();
            let method = parts.method.as_str();

            auth.check(path, method).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("Auth check failed: {}", e),
                )
            })?;

            Ok(auth)
        })
    }
}
