use anyhow::bail;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, Uri, request::Parts},
};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{debug, warn};
use nostr::{Event, EventId, JsonUtil, Kind, PublicKey, Timestamp};
use sha2::{Digest, Sha256};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use crate::session::{SessionClaims, verify_session_token};
use crate::single_use::SingleUseGuard;

/// How far a NIP-98 event's `created_at` may be from now, in seconds.
///
/// NIP-98 suggests 60 seconds. This was 600, which — combined with the absence
/// of any replay tracking — gave a captured `Authorization` header a ten-minute
/// window in which it could be replayed verbatim.
const AUTH_WINDOW_SECS: u64 = 60;

/// Host this deployment serves on, used to bind the `u` tag to *us*.
///
/// Installed once at startup from the configured `public_url`. When unset the
/// host check is skipped (tests, local development).
static AUTH_ORIGIN: OnceLock<String> = OnceLock::new();

/// Install the expected auth origin from the service's public URL.
///
/// Without this, `check` compares only the *path* of the `u` tag, so an event a
/// user was tricked into signing for `https://evil.example/api/v1/vm/1/renew`
/// (via NIP-07 on a hostile page) replays successfully against this API.
/// Returns `true` if this call installed the value.
pub fn init_auth_origin(public_url: &str) -> bool {
    match public_url.parse::<Uri>().ok().and_then(|u| {
        u.host()
            .map(|h| h.to_ascii_lowercase())
            .filter(|h| !h.is_empty())
    }) {
        Some(host) => AUTH_ORIGIN.set(host).is_ok(),
        None => {
            warn!(
                "Could not derive an auth origin from public_url {public_url:?}; NIP-98 `u` tag host binding is DISABLED"
            );
            false
        }
    }
}

/// Hard cap on tracked event ids so a flood cannot grow the map without bound.
const MAX_TRACKED_EVENTS: usize = 100_000;

/// Seen NIP-98 event ids, for single-use enforcement within the auth window.
///
/// The window is twice `AUTH_WINDOW_SECS` because `created_at` may legitimately
/// be up to one window in *either* direction (clock skew), so an event stays
/// presentable for that whole span.
static SEEN_EVENTS: LazyLock<SingleUseGuard<EventId>> = LazyLock::new(|| {
    SingleUseGuard::new(
        "NIP-98 auth event",
        Duration::from_secs(AUTH_WINDOW_SECS * 2),
        MAX_TRACKED_EVENTS,
    )
});

/// SHA-256 of a request body, lowercase hex — the value a NIP-98 `payload` tag
/// carries.
pub fn payload_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Request extension carrying the hash of the buffered request body, populated
/// by [`crate::nip98_payload_middleware`] so the auth extractor (which only
/// sees request *parts*) can verify a `payload` tag.
#[derive(Clone, Debug)]
pub struct RequestPayloadHash(pub String);

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

    /// First value of the tag named `name`, if present and well-formed.
    ///
    /// `get(1)` rather than `[1]` so a malformed single-element tag like `["u"]`
    /// in an attacker-controlled event is treated as missing instead of
    /// panicking.
    fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
        event.tags.iter().find_map(|t| {
            let vec = t.as_slice();
            match (vec.first(), vec.get(1)) {
                (Some(k), Some(v)) if k == name => Some(v.as_str()),
                _ => None,
            }
        })
    }

    /// Validate the auth against the request `path`/`method`.
    ///
    /// For NIP-98 this checks, in order: event kind, timestamp window, the `u`
    /// tag's host *and* path, the `method` tag, the signature, and finally that
    /// this exact event has not already been used. Session (bearer) tokens are
    /// not bound to a path/method (they are verified at parse time), so this is
    /// a no-op success for them.
    ///
    /// Note the ordering: the single-use check runs **last**, so an event is
    /// only consumed once it is known to be otherwise valid. A forged or
    /// mistargeted event cannot burn a legitimate event's id.
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
            > AUTH_WINDOW_SECS
        {
            bail!("Created timestamp is out of range");
        }

        // check url tag (host + path)
        let url = Self::tag_value(event, "u").ok_or_else(|| anyhow::anyhow!("Missing url tag"))?;
        let parsed_uri = url
            .parse::<Uri>()
            .map_err(|_| anyhow::anyhow!("Invalid U tag"))?;
        if path != parsed_uri.path() {
            bail!("U tag does not match");
        }
        // Binding the host stops an event signed for a *different* site (which a
        // hostile page can obtain via NIP-07) from being replayed here.
        if let Some(expected_host) = AUTH_ORIGIN.get() {
            match parsed_uri.host() {
                Some(host) if host.eq_ignore_ascii_case(expected_host) => {}
                Some(_) => bail!("U tag host does not match this server"),
                None => bail!("U tag must be an absolute URL"),
            }
        }

        // check method tag
        match Self::tag_value(event, "method") {
            Some(t_method) if method == t_method => {}
            Some(_) => bail!("Method tag incorrect"),
            None => bail!("Missing method tag"),
        }

        if let Err(_err) = event.verify() {
            bail!("Event signature invalid");
        }

        // Signature is good: burn the event so it cannot be replayed.
        SEEN_EVENTS.consume(event.id)?;

        debug!("{}", event.as_json());
        Ok(())
    }

    /// Verify the `payload` tag against the actual request body.
    ///
    /// NIP-98 makes `payload` optional, so an event without one is accepted:
    /// requiring it would break every existing client. That is not a hole an
    /// attacker can widen — the tag is part of the signed event, so stripping it
    /// from a captured auth invalidates the signature. When a client *does* send
    /// it, the body is cryptographically bound and cannot be swapped.
    pub fn check_payload(&self, body_hash: Option<&str>) -> anyhow::Result<()> {
        let event = match &self.kind {
            AuthKind::Nostr(ev) => ev,
            AuthKind::Session(_) => return Ok(()),
        };

        let Some(expected) = Self::tag_value(event, "payload") else {
            return Ok(()); // no claim made, nothing to enforce
        };

        match body_hash {
            Some(actual) if expected.eq_ignore_ascii_case(actual) => Ok(()),
            Some(_) => bail!("Payload tag does not match request body"),
            // The event commits to a body but we never saw one.
            None => bail!("Payload tag present but request has no body"),
        }
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

    /// Install (once) and return the host every test signs against.
    ///
    /// `AUTH_ORIGIN` is a process-global `OnceLock` shared by the whole test
    /// binary, so tests must not each install a different origin — whichever
    /// ran first would win and break the rest. Every test goes through this
    /// helper and reads back whatever is actually installed.
    fn test_origin() -> String {
        init_auth_origin("https://example.com");
        AUTH_ORIGIN.get().expect("origin installed").clone()
    }

    /// A freshly-signed auth event for `path`/`method` against the test origin.
    fn signed_auth_for(path: &str, method: &str) -> Nip98Auth {
        signed_auth(vec![
            Tag::parse(["u", &format!("https://{}{path}", test_origin())]).unwrap(),
            Tag::parse(["method", method]).unwrap(),
        ])
    }

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
            Tag::parse(["u", &format!("https://{}/api/v1/account", test_origin())]).unwrap(),
            Tag::parse(["method"]).unwrap(),
        ]);
        let res = auth.check("/api/v1/account", "GET");
        assert!(res.is_err(), "expected error, not a panic");
    }

    /// Regression (F-03): `from_base64` only *parses* — `Event::from_json` is a
    /// plain serde deserialize that verifies neither the signature nor the id.
    /// A forged event (someone else's pubkey, a signature copied from an
    /// unrelated event) therefore parses happily and yields that pubkey. It is
    /// [`Nip98Auth::check`] that rejects it, which is why every caller of
    /// `from_base64` must call `check` before trusting the identity.
    #[test]
    fn from_base64_alone_does_not_authenticate() {
        let victim = Keys::generate();
        let attacker = Keys::generate();

        // A genuine event signed by the attacker for the target path...
        let genuine = EventBuilder::new(Kind::HttpAuth, "")
            .tags(vec![
                Tag::parse(["u", "https://example.com/api/admin/v1/jobs/feedback"]).unwrap(),
                Tag::parse(["method", "GET"]).unwrap(),
            ])
            .custom_created_at(Timestamp::now())
            .sign_with_keys(&attacker)
            .unwrap();

        // ...with the pubkey swapped for the victim's. The signature no longer
        // matches, but nothing in parsing notices.
        let mut forged = serde_json::to_value(&genuine).unwrap();
        forged["pubkey"] = serde_json::json!(victim.public_key().to_hex());
        let encoded = BASE64_STANDARD.encode(serde_json::to_vec(&forged).unwrap());

        let auth = Nip98Auth::from_base64(&encoded).expect("forged event still parses");

        // Parsing alone hands back the victim's identity — this is the trap.
        assert_eq!(
            auth.pubkey(),
            victim.public_key().to_bytes(),
            "from_base64 reports the claimed pubkey without verifying it"
        );

        // `check` is what actually rejects it.
        assert!(
            auth.check("/api/admin/v1/jobs/feedback", "GET").is_err(),
            "a forged auth event must fail signature verification"
        );
    }

    /// An auth event signed for one path must not authenticate another.
    #[test]
    fn auth_for_a_different_path_is_rejected() {
        let auth = signed_auth_for("/api/v1/account", "GET");

        assert!(
            auth.check("/api/admin/v1/jobs/feedback", "GET").is_err(),
            "path binding must be enforced"
        );
    }

    /// A well-formed auth event still validates successfully.
    #[test]
    fn well_formed_tags_pass() {
        let auth = signed_auth_for("/api/v1/account", "GET");
        assert!(auth.check("/api/v1/account", "GET").is_ok());
    }

    /// Regression (F-04): NIP-98 auth was replayable. The event carried no
    /// single-use marker, so a captured `Authorization` header could be
    /// resubmitted for as long as the timestamp window allowed. The second
    /// presentation of the same event must now fail.
    #[test]
    fn auth_event_is_single_use() {
        let auth = signed_auth_for("/api/v1/vm/1/renew", "GET");

        assert!(
            auth.check("/api/v1/vm/1/renew", "GET").is_ok(),
            "first use must succeed"
        );
        assert!(
            auth.check("/api/v1/vm/1/renew", "GET").is_err(),
            "replaying the same auth event must be rejected"
        );
    }

    /// Regression (F-04): the timestamp window was 600s. NIP-98 suggests 60.
    #[test]
    fn stale_auth_event_is_rejected() {
        let keys = Keys::generate();
        // Two minutes old: inside the old 600s window, outside the new one.
        let stale = Timestamp::from(Timestamp::now().as_secs() - 120);
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(vec![
                Tag::parse(["u", &format!("https://{}/api/v1/account", test_origin())]).unwrap(),
                Tag::parse(["method", "GET"]).unwrap(),
            ])
            .custom_created_at(stale)
            .sign_with_keys(&keys)
            .unwrap();
        let auth = Nip98Auth {
            pubkey: event.pubkey.to_bytes(),
            kind: AuthKind::Nostr(event),
        };

        assert!(
            auth.check("/api/v1/account", "GET").is_err(),
            "an event older than the auth window must be rejected"
        );
    }

    /// Regression (F-04): only the *path* of the `u` tag was compared, so an
    /// event a user was tricked into signing for a hostile origin replayed
    /// here. With an origin configured, the host must match.
    #[test]
    fn u_tag_host_must_match_configured_origin() {
        // `AUTH_ORIGIN` is a process-global OnceLock; set it for this binary.
        // Whichever test wins the race, both assertions below hold because they
        // are expressed relative to the value actually installed.
        let expected = test_origin();

        let hostile = signed_auth(vec![
            Tag::parse(["u", "https://evil.example/api/v1/vm/1/renew"]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ]);
        assert!(
            hostile.check("/api/v1/vm/1/renew", "GET").is_err(),
            "an event signed for another origin must not authenticate here"
        );

        let ours = signed_auth(vec![
            Tag::parse(["u", &format!("https://{expected}/api/v1/vm/1/renew")]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ]);

        assert!(
            ours.check("/api/v1/vm/1/renew", "GET").is_ok(),
            "an event signed for our own origin must still work"
        );
    }

    /// Regression (F-04): the `payload` tag was never verified, so a captured
    /// auth for a bodied request could be reused with a different body.
    #[test]
    fn payload_tag_binds_the_request_body() {
        let body = br#"{"ssh_key_id":1}"#;
        let tampered = br#"{"ssh_key_id":999}"#;

        let auth = signed_auth(vec![
            Tag::parse(["u", &format!("https://{}/api/v1/vm/1", test_origin())]).unwrap(),
            Tag::parse(["method", "PATCH"]).unwrap(),
            Tag::parse(["payload", &payload_hash(body)]).unwrap(),
        ]);

        assert!(
            auth.check_payload(Some(&payload_hash(body))).is_ok(),
            "the body the client signed over must be accepted"
        );
        assert!(
            auth.check_payload(Some(&payload_hash(tampered))).is_err(),
            "a swapped body must be rejected"
        );
        assert!(
            auth.check_payload(None).is_err(),
            "an event committing to a body must not pass with no body seen"
        );
    }

    /// A client may legitimately commit to an empty body (e.g. a POST with no
    /// content). SHA-256("") must verify like any other hash.
    #[test]
    fn payload_tag_over_an_empty_body_verifies() {
        let auth = signed_auth(vec![
            Tag::parse(["u", &format!("https://{}/api/v1/vm/1/start", test_origin())]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            Tag::parse(["payload", &payload_hash(b"")]).unwrap(),
        ]);

        assert!(auth.check_payload(Some(&payload_hash(b""))).is_ok());
        assert!(auth.check_payload(Some(&payload_hash(b"x"))).is_err());
    }

    /// NIP-98 makes `payload` optional. An event without one must still work,
    /// otherwise every existing client breaks.
    #[test]
    fn absent_payload_tag_is_accepted() {
        let auth = signed_auth_for("/api/v1/vm/1", "PATCH");

        assert!(auth.check_payload(None).is_ok());
        assert!(auth.check_payload(Some(&payload_hash(b"anything"))).is_ok());
    }

    /// The payload middleware must record the body hash for a NIP-98 request so
    /// the extractor can verify a `payload` tag — and must leave every other
    /// request completely untouched (the raw-body payment webhooks rely on
    /// that).
    #[tokio::test]
    async fn payload_middleware_hashes_only_nip98_requests() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::post;
        use tower::ServiceExt;

        // Echoes back whatever hash the middleware recorded, or "none".
        async fn echo(req: axum::extract::Request) -> String {
            req.extensions()
                .get::<RequestPayloadHash>()
                .map(|h| h.0.clone())
                .unwrap_or_else(|| "none".to_string())
        }

        let app = axum::Router::new()
            .route("/x", post(echo))
            .layer(axum::middleware::from_fn(nip98_payload_middleware));

        let body = br#"{"a":1}"#;

        // With NIP-98 auth: the hash is recorded and matches the real body.
        let rsp = app
            .clone()
            .oneshot(
                Request::post("/x")
                    .header("authorization", "Nostr abc")
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let recorded = axum::body::to_bytes(rsp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&recorded),
            payload_hash(body),
            "the middleware must record the hash of the actual body"
        );

        // Without an Authorization header (e.g. a payment webhook) nothing is
        // recorded and the body is passed through untouched.
        let rsp = app
            .clone()
            .oneshot(Request::post("/x").body(Body::from(body.to_vec())).unwrap())
            .await
            .unwrap();
        let recorded = axum::body::to_bytes(rsp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&recorded), "none");

        // A Bearer session request is not NIP-98 either.
        let rsp = app
            .oneshot(
                Request::post("/x")
                    .header("authorization", "Bearer jwt")
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let recorded = axum::body::to_bytes(rsp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&recorded), "none");
    }

    /// An oversized body is rejected rather than buffered.
    #[tokio::test]
    async fn payload_middleware_rejects_oversized_body() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::post;
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/x", post(async || "ok"))
            .layer(axum::middleware::from_fn(nip98_payload_middleware));

        let rsp = app
            .oneshot(
                Request::post("/x")
                    .header("authorization", "Nostr abc")
                    .body(Body::from(vec![0u8; MAX_HASHED_BODY + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(rsp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// The replay cache must not grow without bound under a flood.
    #[test]
    fn replay_cache_is_bounded() {
        for i in 0..64u16 {
            let mut raw = [0u8; 32];
            raw[0..2].copy_from_slice(&i.to_le_bytes());
            let _ = SEEN_EVENTS.consume(EventId::from_slice(&raw).unwrap());
        }
        assert!(SEEN_EVENTS.len() <= MAX_TRACKED_EVENTS);
    }
}

impl<S> FromRequestParts<S> for Nip98Auth
where
    S: Send + Sync,
    std::sync::Arc<dyn lnvps_db::LNVpsDb>: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        use axum::extract::FromRef;
        let db = std::sync::Arc::<dyn lnvps_db::LNVpsDb>::from_ref(state);
        Box::pin(async move {
            let auth_header = parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .ok_or((StatusCode::FORBIDDEN, "Auth header not found".to_string()))?;

            // Session (bearer) scheme: JWT issued after an external OAuth login.
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                let claims = verify_session_token(token.trim())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid session: {}", e)))?;

                // A JWT cannot be revoked by itself, so check it against the
                // account's current session version. Bumping that column (on
                // logout-everywhere, credential change, or suspected
                // compromise) invalidates every token issued before the bump.
                let user = db.get_user(claims.uid).await.map_err(|_| {
                    (
                        StatusCode::UNAUTHORIZED,
                        "Invalid session: unknown account".to_string(),
                    )
                })?;
                if user.session_version != claims.ver {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "Invalid session: session has been revoked".to_string(),
                    ));
                }

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

            // Bind the body when the client committed to one. The hash is put
            // in the extensions by `nip98_payload_middleware`; when that layer
            // is not installed the extension is absent and an event carrying a
            // `payload` tag is rejected rather than silently unverified.
            let body_hash = parts
                .extensions
                .get::<RequestPayloadHash>()
                .map(|h| h.0.as_str());
            auth.check_payload(body_hash).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("Auth check failed: {}", e),
                )
            })?;

            Ok(auth)
        })
    }
}

/// Buffer the request body and record its SHA-256 so [`Nip98Auth`] can verify a
/// NIP-98 `payload` tag.
///
/// Only runs for requests that actually carry NIP-98 auth *and* a body; every
/// other request (including the raw-body payment webhooks, which have no
/// `Authorization` header) passes straight through untouched, so this does not
/// interfere with streaming or with route-level body limits.
pub async fn nip98_payload_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let is_nostr_auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Nostr "));

    if !is_nostr_auth {
        return next.run(req).await;
    }

    let (mut parts, body) = req.into_parts();
    // `axum::body::to_bytes` enforces the limit we pass, so a hostile body
    // cannot be buffered without bound here.
    let bytes = match axum::body::to_bytes(body, MAX_HASHED_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body too large".to_string(),
            )
                .into_response();
        }
    };

    // Recorded even for an empty body: SHA-256("") is a perfectly valid thing
    // for a client to commit to, and inserting unconditionally means the
    // extractor can distinguish "no body seen" (layer not installed) from "body
    // was empty".
    parts
        .extensions
        .insert(RequestPayloadHash(payload_hash(&bytes)));

    next.run(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(bytes),
    ))
    .await
}

/// Largest body we will buffer in order to hash it for `payload` verification.
/// Comfortably above any request this API accepts.
const MAX_HASHED_BODY: usize = 2 * 1024 * 1024;
