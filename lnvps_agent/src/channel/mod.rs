pub mod email;
pub mod kind1;

use anyhow::Result;
use async_trait::async_trait;

/// An incoming support request from a customer.
#[derive(Clone, Debug)]
pub struct IncomingSupportRequest {
    /// The customer's nostr pubkey in hex format (64 chars).
    /// `None` for general questions from unknown senders.
    pub pubkey: Option<String>,
    /// Stable identifier for this sender across requests.
    /// For email channels this is the From email address.
    pub sender_id: String,
    /// The customer's message.
    pub message: String,
    /// Opaque channel-specific identifier — the channel implementation
    /// can stash whatever it needs here to route the reply later.
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
