pub mod email;
pub mod kind1;

use anyhow::Result;
use async_trait::async_trait;

/// Who sent a support request, as resolved by the channel against the LNVPS API.
///
/// The channel does this lookup once (to route the reply and gate access), so
/// the agent never has to resolve the user again.
#[derive(Clone, Debug)]
pub enum Requester {
    /// A known LNVPS customer.
    Customer {
        /// Resolved LNVPS user id — tools are scoped to this user.
        user_id: u64,
        /// The customer's nostr pubkey hex, if their account has one.
        /// Used only for prompt context; not all customers have a pubkey.
        pubkey: Option<String>,
    },
    /// Not a known customer — general public question.
    Anonymous,
}

/// An incoming support request from a customer.
#[derive(Clone, Debug)]
pub struct IncomingSupportRequest {
    /// Stable per-sender key used for conversation storage.
    /// For email this is the From address; for Nostr it's the author pubkey hex.
    pub conversation_key: String,
    /// The resolved sender identity.
    pub requester: Requester,
    /// The customer's message.
    pub message: String,
    /// Opaque channel-specific token — the channel stashes whatever it needs
    /// here to route the reply later (e.g. email threading headers, nostr event).
    /// The agent treats this as a pass-through and never inspects it.
    pub channel_context: Option<String>,
}

/// The reply produced by the agent for delivery back through the channel.
#[derive(Clone, Debug)]
pub struct SupportReply {
    /// The agent's text response.
    pub response: String,
    /// The original channel context so the channel knows where to route the reply.
    pub channel_context: Option<String>,
}

/// A channel over which support requests arrive and replies are delivered.
///
/// Implementations might poll a database table, listen on a Nostr relay,
/// read from a message queue, or monitor an IMAP inbox.
#[async_trait]
pub trait SupportChannel: Send + Sync {
    /// Wait for the next inbound support request.
    /// Blocks until a request is available, or returns `None` if the channel
    /// has been shut down.
    async fn next_request(&self) -> Option<IncomingSupportRequest>;

    /// Deliver a reply back to the customer through this channel.
    async fn send_reply(&self, reply: SupportReply) -> Result<()>;

    /// Additional channel-specific instructions appended to the system prompt.
    /// E.g. email channels might request plain-text formatting and sign-offs;
    /// a Nostr channel might want short messages with emoji.
    fn channel_prompt(&self) -> &str {
        ""
    }
}
