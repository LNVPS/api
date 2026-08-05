use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};

/// Create a NIP-98 Authorization header value for the given URL and HTTP method.
///
/// The header format is: `Nostr <base64-encoded-event-json>`
/// The event is kind 27235 (HttpAuth) with `u` (URL) and `method` tags.
///
/// A random `nonce` tag is included so every call produces a distinct event.
/// A nostr event id is the hash of (pubkey, created_at, kind, tags, content)
/// and `created_at` only has **one-second** resolution, so without it two
/// identical requests (same key, URL and method) issued within the same second
/// hash to the same id. The API burns each auth event id on use, so the second
/// request would be rejected as a replay with
/// "Auth check failed: Credential has already been used".
pub fn make_nip98_auth(keys: &Keys, url: &str, method: &str) -> anyhow::Result<String> {
    let mut nonce_bytes = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let tags = vec![
        Tag::parse(["u", url])?,
        Tag::parse(["method", method])?,
        Tag::parse(["nonce", nonce.as_str()])?,
    ];

    let event: Event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::now())
        .sign_with_keys(keys)?;

    let json = serde_json::to_string(&event)?;
    let encoded = BASE64_STANDARD.encode(json.as_bytes());
    Ok(format!("Nostr {encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    /// Regression: identical requests inside one second must still produce
    /// distinct auth events, or the API's replay protection rejects the second.
    #[test]
    fn test_make_nip98_auth_is_unique_per_call() {
        let keys = Keys::generate();
        let url = "https://example.com/api/v1/account";

        let ids: Vec<_> = (0..5)
            .map(|_| {
                let auth = make_nip98_auth(&keys, url, "GET").unwrap();
                let json = BASE64_STANDARD.decode(&auth["Nostr ".len()..]).unwrap();
                serde_json::from_slice::<Event>(&json).unwrap().id
            })
            .collect();

        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "auth event ids must all differ");
    }

    #[test]
    fn test_make_nip98_auth_produces_valid_header() {
        let keys = Keys::generate();
        let auth = make_nip98_auth(&keys, "https://example.com/api/v1/account", "GET").unwrap();
        assert!(auth.starts_with("Nostr "));

        // Decode and verify the event
        let b64 = &auth["Nostr ".len()..];
        let json = BASE64_STANDARD.decode(b64).unwrap();
        let event: Event = serde_json::from_slice(&json).unwrap();
        assert_eq!(event.kind, Kind::HttpAuth);
        assert!(event.verify().is_ok());
    }
}
