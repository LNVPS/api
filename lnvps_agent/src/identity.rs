//! Sender identity types shared between channels, the resolver, and the agent.

/// How a channel identifies the sender of a support request.
///
/// Channels know only this — resolving it to an LNVPS customer is done by the
/// resolver ([`crate::api_client::ApiClient::resolve`]), so channels never call
/// the API themselves.
#[derive(Clone, Debug)]
pub enum SenderIdentity {
    /// Identified by email address (email channel).
    Email(String),
    /// Identified by nostr pubkey hex (Nostr channel).
    Pubkey(String),
}

impl SenderIdentity {
    /// Stable per-sender key used for conversation storage.
    /// For email this is the From address; for Nostr it's the author pubkey hex.
    pub fn conversation_key(&self) -> &str {
        match self {
            SenderIdentity::Email(email) => email,
            SenderIdentity::Pubkey(pubkey) => pubkey,
        }
    }
}

/// A sender resolved against the LNVPS API — everything the agent needs to
/// handle the request.
#[derive(Clone, Debug)]
pub enum Requester {
    /// A known LNVPS customer.
    Customer {
        /// Resolved LNVPS user id — tools are scoped to this user.
        user_id: u64,
        /// The full account record from the resolution lookup
        /// (admin `AdminUserInfo` JSON), reused as prompt context.
        account: serde_json::Value,
    },
    /// Not a known customer — general public question.
    Anonymous,
}
