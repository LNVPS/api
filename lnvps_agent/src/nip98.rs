use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use nostr::prelude::*;

/// Generates fresh NIP-98 auth tokens from an nsec key.
pub struct Nip98Signer {
    keys: Keys,
}

impl Nip98Signer {
    pub fn from_nsec(nsec: &str) -> Result<Self> {
        let sk = SecretKey::from_bech32(nsec).context("Invalid nsec key")?;
        Ok(Self {
            keys: Keys::new(sk),
        })
    }

    /// Create a signed NIP-98 HTTP auth event (Kind 27235) for the given URL
    /// and method, then base64-encode the entire event JSON for the
    /// `Authorization: Nostr <base64>` header.
    pub fn sign_auth_token(&self, url: &str, method: &str) -> Result<String> {
        let url_tag = Tag::custom(
            TagKind::Custom(std::borrow::Cow::Borrowed("u")),
            vec![url.to_string()],
        );
        let method_tag = Tag::custom(
            TagKind::Custom(std::borrow::Cow::Borrowed("method")),
            vec![method.to_uppercase()],
        );

        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tag(url_tag)
            .tag(method_tag)
            .sign_with_keys(&self.keys)
            .context("Failed to sign NIP-98 event")?;

        let json = event.as_json();
        Ok(BASE64.encode(json.as_bytes()))
    }
}
