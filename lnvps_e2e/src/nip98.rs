use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};

/// Create a NIP-98 Authorization header value for the given URL and HTTP method.
///
/// The header format is: `Nostr <base64-encoded-event-json>`
/// The event is kind 27235 (HttpAuth) with `u` (URL) and `method` tags.
pub fn make_nip98_auth(keys: &Keys, url: &str, method: &str) -> anyhow::Result<String> {
    let tags = vec![Tag::parse(["u", url])?, Tag::parse(["method", method])?];

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
