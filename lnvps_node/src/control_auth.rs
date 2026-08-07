//! Verifying that a control request really came from LNVPS.
//!
//! The control API can start and stop guests, so every request carries a NIP-98
//! event signed by LNVPS's control key, and the node checks it against a public
//! key **compiled into the binary**.
//!
//! Why a pinned key rather than a bearer token: a token has to be generated,
//! delivered to the node, stored on the operator's disk, rotated, and revoked —
//! five chances to leak a secret that grants control of every guest on the
//! machine. A public key is not a secret, so none of those steps exist. It also
//! removes the possibility of a stolen token being replayed by whoever finds
//! it: forging a command requires LNVPS's private key, which never leaves
//! LNVPS.
//!
//! The tunnel is *not* treated as sufficient on its own. Guests run on this
//! machine, and a guest able to route to the node's tunnel address could
//! otherwise stop its neighbours.

use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use nostr::prelude::*;

/// LNVPS's control public key, injected at build time by the release workflow.
///
/// Deliberately not configurable at runtime: a config file on the operator's
/// own disk that names the key allowed to control the node is a config file
/// worth editing. Self-hosted deployments rebuild with their own key.
///
/// For the LNVPS fleet this is LNVPS's published nostr identity —
/// `npub1lnvps32qq2nvg75cqwflq4y6cmnzn55d26ypzjakpkp3khqcx2ns7t7vjj`, hex
/// `fcd818454002a6c47a980393f0549ac6e629d28d5688114bb60d831b5c1832a7` — the
/// same account customers DM for support. That is the point of reusing it: an
/// operator can check the key their binary was built with against an account
/// that publicly answers, which is not a check anyone could make against a key
/// that existed only inside LNVPS.
pub const CONTROL_PUBKEY: Option<&str> = option_env!("LNVPS_CONTROL_PUBKEY");

/// How far from the current time a signed request may be.
///
/// Wide enough for clock skew on a machine LNVPS does not administer, narrow
/// enough that a captured request stops working quickly.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// The pinned key, parsed.
///
/// Fails when the binary was built without a key rather than defaulting to
/// something permissive: a node that cannot tell who LNVPS is must refuse to
/// serve the control API, not serve it to everyone.
pub fn control_pubkey() -> Result<PublicKey> {
    let hex = CONTROL_PUBKEY.context(
        "This binary was built without LNVPS_CONTROL_PUBKEY, so it cannot verify control \
         requests; the control API is unavailable",
    )?;
    PublicKey::parse(hex).context("Embedded LNVPS_CONTROL_PUBKEY is not a valid public key")
}

/// Remembers recently-accepted event ids so none is accepted twice.
///
/// Signature checks alone do not stop a captured request being sent again, and
/// these requests are commands: replaying a stop is a second outage, and
/// replaying it repeatedly keeps a guest down.
///
/// Bounded in both directions — entries expire with the clock-skew window, and
/// the queue is capped — so a flood of distinct requests cannot grow it without
/// limit.
pub struct ReplayGuard {
    seen: HashSet<EventId>,
    order: VecDeque<(u64, EventId)>,
    window: Duration,
    capacity: usize,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(MAX_CLOCK_SKEW, 4096)
    }
}

impl ReplayGuard {
    pub fn new(window: Duration, capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            window,
            capacity,
        }
    }

    /// Record `id` as used at `now`. Returns false if it was already used.
    pub fn check_and_insert(&mut self, id: EventId, now: u64) -> bool {
        self.expire(now);
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back((now, id));
        while self.order.len() > self.capacity {
            if let Some((_, evicted)) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }

    /// Drop entries older than the window; they can no longer be replayed
    /// because the timestamp check rejects them first.
    fn expire(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.window.as_secs());
        while let Some((seen_at, _)) = self.order.front() {
            if *seen_at >= cutoff {
                break;
            }
            if let Some((_, expired)) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }
    }

    /// Number of remembered ids, for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Everything needed to judge one request.
pub struct Request<'a> {
    /// The `Authorization` header value, including the `Nostr ` scheme.
    pub authorization: &'a str,
    /// The absolute URL the request was made to, as the node sees it.
    pub url: &'a str,
    /// The HTTP method.
    pub method: &'a str,
    /// The request body, if any. Bound into the signature via the `payload`
    /// tag so a captured header cannot be reused with different arguments.
    pub body: &'a [u8],
}

/// Verify a control request. Returns the event id, so the caller can log which
/// command was executed.
///
/// Every check here is load-bearing; see the tests, each of which removes one.
pub fn verify(
    request: &Request<'_>,
    expected_pubkey: &PublicKey,
    replay: &mut ReplayGuard,
    now: u64,
) -> Result<EventId> {
    let encoded = request
        .authorization
        .strip_prefix("Nostr ")
        .context("Authorization header is not the Nostr scheme")?;
    let json = BASE64
        .decode(encoded.trim())
        .context("Authorization header is not valid base64")?;
    let event: Event =
        serde_json::from_slice(&json).context("Authorization header is not a nostr event")?;

    // Signature first: nothing else in the event means anything until it is
    // known to be authentic.
    event
        .verify()
        .map_err(|e| anyhow::anyhow!("Invalid signature on control request: {e}"))?;

    if event.kind != Kind::HttpAuth {
        bail!(
            "Control request is kind {}, expected {} (NIP-98)",
            event.kind.as_u16(),
            Kind::HttpAuth.as_u16()
        );
    }

    // The whole point: only LNVPS may command this node.
    if event.pubkey != *expected_pubkey {
        bail!(
            "Control request signed by {}, which is not the LNVPS control key",
            event.pubkey.to_hex()
        );
    }

    let created = event.created_at.as_secs();
    let skew = created.abs_diff(now);
    if skew > MAX_CLOCK_SKEW.as_secs() {
        bail!(
            "Control request timestamp is {skew}s from now, outside the {}s window",
            MAX_CLOCK_SKEW.as_secs()
        );
    }

    let tag = |name: &str| -> Option<String> {
        event
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
            .and_then(|t| t.as_slice().get(1).cloned())
    };

    // Without these two, a signed request to a harmless endpoint could be
    // redirected at a destructive one.
    match tag("u") {
        Some(u) if u == request.url => {}
        Some(u) => bail!("Control request was signed for {u}, not {}", request.url),
        None => bail!("Control request has no u tag"),
    }
    match tag("method") {
        Some(m) if m.eq_ignore_ascii_case(request.method) => {}
        Some(m) => bail!(
            "Control request was signed for {m}, not {}",
            request.method.to_uppercase()
        ),
        None => bail!("Control request has no method tag"),
    }

    // A body must be bound to the signature, or the arguments of a command can
    // be swapped after it was signed.
    if !request.body.is_empty() {
        let digest = sha256_hex(request.body);
        match tag("payload") {
            Some(p) if p.eq_ignore_ascii_case(&digest) => {}
            Some(p) => bail!("Control request payload hash {p} does not match the body"),
            None => bail!("Control request has a body but no payload tag"),
        }
    }

    if !replay.check_and_insert(event.id, now) {
        bail!("Control request has already been used (replay)");
    }

    Ok(event.id)
}

/// Hex SHA-256 of a request body, as NIP-98's `payload` tag defines it.
pub fn sha256_hex(body: &[u8]) -> String {
    use nostr::hashes::{Hash, sha256};
    sha256::Hash::hash(body).to_string()
}

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn lnvps_keys() -> Keys {
        Keys::generate()
    }

    /// Build an `Authorization` header the way LNVPS's control plane will.
    fn signed(
        keys: &Keys,
        url: &str,
        method: &str,
        body: &[u8],
        created_at: u64,
        kind: Kind,
    ) -> String {
        let mut builder = EventBuilder::new(kind, "")
            .tag(Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("u")),
                vec![url.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("method")),
                vec![method.to_uppercase()],
            ))
            .custom_created_at(Timestamp::from(created_at));
        if !body.is_empty() {
            builder = builder.tag(Tag::custom(
                TagKind::Custom(std::borrow::Cow::Borrowed("payload")),
                vec![sha256_hex(body)],
            ));
        }
        let event = builder.sign_with_keys(keys).unwrap();
        format!("Nostr {}", BASE64.encode(event.as_json()))
    }

    fn request<'a>(auth: &'a str, url: &'a str, method: &'a str, body: &'a [u8]) -> Request<'a> {
        Request {
            authorization: auth,
            url,
            method,
            body,
        }
    }

    const URL: &str = "https://10.66.0.1:8890/api/v1/vm/42/stop";

    #[test]
    fn a_request_signed_by_lnvps_is_accepted() {
        let keys = lnvps_keys();
        let auth = signed(&keys, URL, "POST", b"", NOW, Kind::HttpAuth);
        let mut replay = ReplayGuard::default();
        verify(
            &request(&auth, URL, "POST", b""),
            &keys.public_key(),
            &mut replay,
            NOW,
        )
        .unwrap();
    }

    /// The guarantee the pinned key exists for: the operator owns this machine
    /// and can sign anything they like, but not as LNVPS.
    #[test]
    fn a_request_signed_by_anyone_else_is_refused() {
        let lnvps = lnvps_keys();
        let operator = Keys::generate();
        let auth = signed(&operator, URL, "POST", b"", NOW, Kind::HttpAuth);
        let err = verify(
            &request(&auth, URL, "POST", b""),
            &lnvps.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not the LNVPS control key"), "got: {err}");
    }

    #[test]
    fn a_tampered_event_fails_the_signature_check() {
        let keys = lnvps_keys();
        let auth = signed(&keys, URL, "POST", b"", NOW, Kind::HttpAuth);
        // Re-sign nothing: flip a byte in the signed JSON.
        let encoded = auth.strip_prefix("Nostr ").unwrap();
        let json = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        let tampered = json.replace("/vm/42/stop", "/vm/43/stop");
        let auth = format!("Nostr {}", BASE64.encode(tampered));

        let err = verify(
            &request(&auth, URL, "POST", b""),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Invalid signature"), "got: {err}");
    }

    /// A signed request for one endpoint must not work against another, or a
    /// captured status poll could be pointed at a destructive command.
    #[test]
    fn a_request_signed_for_another_url_is_refused() {
        let keys = lnvps_keys();
        let auth = signed(
            &keys,
            "https://10.66.0.1:8890/api/v1/status",
            "POST",
            b"",
            NOW,
            Kind::HttpAuth,
        );
        let err = verify(
            &request(&auth, URL, "POST", b""),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("was signed for"), "got: {err}");
    }

    #[test]
    fn a_request_signed_for_another_method_is_refused() {
        let keys = lnvps_keys();
        let auth = signed(&keys, URL, "GET", b"", NOW, Kind::HttpAuth);
        let err = verify(
            &request(&auth, URL, "DELETE", b""),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("was signed for GET"), "got: {err}");
    }

    #[test]
    fn the_wrong_event_kind_is_refused() {
        let keys = lnvps_keys();
        let auth = signed(&keys, URL, "POST", b"", NOW, Kind::TextNote);
        let err = verify(
            &request(&auth, URL, "POST", b""),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("expected 27235"), "got: {err}");
    }

    /// A command's arguments must be covered by the signature. Without the
    /// payload check, a captured header could be reused with a different body.
    #[test]
    fn a_swapped_body_is_refused() {
        let keys = lnvps_keys();
        let body = br#"{"vm_id":42}"#;
        let auth = signed(&keys, URL, "POST", body, NOW, Kind::HttpAuth);

        let swapped = br#"{"vm_id":43}"#;
        let err = verify(
            &request(&auth, URL, "POST", swapped),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("payload hash"), "got: {err}");

        // The body it was signed for still works.
        verify(
            &request(&auth, URL, "POST", body),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap();
    }

    /// A body with no payload tag is unsigned input; accepting it would make
    /// the previous test's protection optional.
    #[test]
    fn a_body_without_a_payload_tag_is_refused() {
        let keys = lnvps_keys();
        let auth = signed(&keys, URL, "POST", b"", NOW, Kind::HttpAuth);
        let err = verify(
            &request(&auth, URL, "POST", br#"{"vm_id":42}"#),
            &keys.public_key(),
            &mut ReplayGuard::default(),
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no payload tag"), "got: {err}");
    }

    /// Replaying a stop command is a second outage.
    #[test]
    fn the_same_request_cannot_be_used_twice() {
        let keys = lnvps_keys();
        let auth = signed(&keys, URL, "POST", b"", NOW, Kind::HttpAuth);
        let mut replay = ReplayGuard::default();

        verify(
            &request(&auth, URL, "POST", b""),
            &keys.public_key(),
            &mut replay,
            NOW,
        )
        .unwrap();
        let err = verify(
            &request(&auth, URL, "POST", b""),
            &keys.public_key(),
            &mut replay,
            NOW,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("already been used"), "got: {err}");
    }

    /// Two genuinely different commands must both go through, or the guard
    /// would break normal operation.
    #[test]
    fn distinct_requests_are_all_accepted() {
        let keys = lnvps_keys();
        let mut replay = ReplayGuard::default();
        for vm in 1..=5 {
            let url = format!("https://10.66.0.1:8890/api/v1/vm/{vm}/stop");
            let auth = signed(&keys, &url, "POST", b"", NOW, Kind::HttpAuth);
            verify(
                &request(&auth, &url, "POST", b""),
                &keys.public_key(),
                &mut replay,
                NOW,
            )
            .unwrap();
        }
        assert_eq!(replay.len(), 5);
    }

    #[test]
    fn stale_and_future_requests_are_refused() {
        let keys = lnvps_keys();
        for created in [NOW - 3600, NOW - 61, NOW + 61, NOW + 3600] {
            let auth = signed(&keys, URL, "POST", b"", created, Kind::HttpAuth);
            let err = verify(
                &request(&auth, URL, "POST", b""),
                &keys.public_key(),
                &mut ReplayGuard::default(),
                NOW,
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("outside the"), "created_at {created}: {err}");
        }

        // Clock skew inside the window is tolerated: the node's clock is not
        // administered by LNVPS.
        for created in [NOW - 59, NOW, NOW + 59] {
            let auth = signed(&keys, URL, "POST", b"", created, Kind::HttpAuth);
            verify(
                &request(&auth, URL, "POST", b""),
                &keys.public_key(),
                &mut ReplayGuard::default(),
                NOW,
            )
            .unwrap();
        }
    }

    #[test]
    fn malformed_authorization_headers_are_refused() {
        let keys = lnvps_keys();
        for (header, expected) in [
            ("Bearer sometoken", "not the Nostr scheme"),
            ("Nostr !!!not-base64!!!", "not valid base64"),
            ("Nostr aGVsbG8=", "not a nostr event"),
        ] {
            let err = verify(
                &request(header, URL, "POST", b""),
                &keys.public_key(),
                &mut ReplayGuard::default(),
                NOW,
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains(expected), "{header}: {err}");
        }
    }

    /// The replay set must not grow without bound: it is fed by anything that
    /// can reach the listener.
    #[test]
    fn the_replay_guard_is_bounded() {
        let mut replay = ReplayGuard::new(MAX_CLOCK_SKEW, 8);
        for i in 0..100u64 {
            let id = EventId::all_zeros();
            // Distinct ids, since EventId::all_zeros is constant.
            let id = EventId::from_slice(&{
                let mut bytes = id.to_bytes();
                bytes[..8].copy_from_slice(&i.to_le_bytes());
                bytes
            })
            .unwrap();
            assert!(replay.check_and_insert(id, NOW));
        }
        assert!(replay.len() <= 8, "guard grew to {}", replay.len());
    }

    /// Entries older than the window are dropped, because the timestamp check
    /// already rejects those requests.
    #[test]
    fn the_replay_guard_expires_old_entries() {
        let mut replay = ReplayGuard::new(Duration::from_secs(60), 4096);
        let id = EventId::from_slice(&[7u8; 32]).unwrap();
        assert!(replay.check_and_insert(id, NOW));
        assert_eq!(replay.len(), 1);

        // Well past the window: nothing left to remember.
        replay.check_and_insert(EventId::from_slice(&[8u8; 32]).unwrap(), NOW + 600);
        assert_eq!(replay.len(), 1);
        assert!(!replay.is_empty());
    }

    /// A binary built without the key must refuse to serve the control API
    /// rather than accept anything.
    #[test]
    fn a_binary_without_an_embedded_key_refuses() {
        match CONTROL_PUBKEY {
            None => {
                let err = control_pubkey().unwrap_err().to_string();
                assert!(err.contains("built without"), "got: {err}");
            }
            Some(hex) => {
                // Built with one: it must be usable, or releases would ship a
                // node that cannot be controlled.
                control_pubkey().unwrap_or_else(|e| panic!("embedded key {hex} invalid: {e}"));
            }
        }
    }

    #[test]
    fn payload_hashes_match_nip98() {
        // Well-known vector: sha256("") and a known short string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn now_unix_is_a_plausible_clock() {
        // Later than 2023 and before 2100: catches a zero or millisecond clock.
        let now = now_unix();
        assert!(now > 1_700_000_000, "got {now}");
        assert!(now < 4_100_000_000, "got {now}");
    }
}
