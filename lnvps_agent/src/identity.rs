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
    /// Identified by nostr pubkey hex (Nostr channel, live chat).
    Pubkey(String),
    /// A logged-out visitor on live chat, identified only by an opaque
    /// server-issued session id.
    ///
    /// The id is a bearer token: whoever presents it resumes that transcript,
    /// so it must be unguessable (the API issues 32 random bytes). It proves
    /// nothing about who the visitor is, which is why a guest never resolves to
    /// a [`Requester::Customer`].
    Guest(String),
}

impl SenderIdentity {
    /// The raw identity string, unnamespaced. Use [`conversation_key`] to derive
    /// the storage key — this is only for logging and channel bookkeeping.
    pub fn as_str(&self) -> &str {
        match self {
            SenderIdentity::Email(email) => email,
            SenderIdentity::Pubkey(pubkey) => pubkey,
            SenderIdentity::Guest(session) => session,
        }
    }
}

/// Which support channel a message travelled over.
///
/// Carried alongside the sender identity because the channel affects both how a
/// conversation is keyed (see [`conversation_key`]) and how the message is
/// recorded for later analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportChannelKind {
    /// IMAP/SMTP support mailbox. Private.
    Email,
    /// Public Nostr kind-1 mention. World-readable.
    Nostr,
    /// Live-chat WebSocket served by the API. Private.
    WebChat,
}

impl SupportChannelKind {
    /// Whether messages on this channel are visible to third parties.
    ///
    /// Public channels are kept in their own conversation thread so the agent
    /// can never quote privately-shared information into a public reply.
    pub fn is_public(&self) -> bool {
        matches!(self, SupportChannelKind::Nostr)
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

impl Requester {
    /// The resolved LNVPS user id, if the sender matched an account.
    pub fn user_id(&self) -> Option<u64> {
        match self {
            Requester::Customer { user_id, .. } => Some(*user_id),
            Requester::Anonymous => None,
        }
    }
}

/// Derive the storage key for a conversation.
///
/// Keys are namespaced by kind so that different identity types can never
/// collide, and so the namespace itself records why a thread is separate:
///
/// - `user:<id>` — a resolved customer on a **private** channel. Email and live
///   chat share this key, giving the agent one continuous memory of the
///   customer regardless of how they got in touch.
/// - `nostr:<pubkey>` — a public kind-1 mention. Deliberately its own namespace
///   even for a known customer: kind-1 replies are readable by the whole relay
///   network, so a thread shared with email would let the agent quote a
///   privately-reported billing or account detail into a public post.
/// - `email:<addr>` / `pubkey:<hex>` — senders that matched no account.
/// - `guest:<session>` — a logged-out live-chat visitor. Its own namespace so a
///   guest id can never be confused with a pubkey, whatever its shape.
pub fn conversation_key(
    identity: &SenderIdentity,
    requester: &Requester,
    channel: SupportChannelKind,
) -> String {
    // A public channel never joins the shared private thread, regardless of
    // whether we know who the sender is.
    if channel.is_public() {
        return format!("nostr:{}", identity.as_str());
    }

    match requester.user_id() {
        Some(user_id) => format!("user:{user_id}"),
        None => match identity {
            SenderIdentity::Email(email) => format!("email:{}", email.to_lowercase()),
            SenderIdentity::Pubkey(pubkey) => format!("pubkey:{pubkey}"),
            SenderIdentity::Guest(session) => format!("guest:{session}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn customer(user_id: u64) -> Requester {
        Requester::Customer {
            user_id,
            account: serde_json::json!({ "id": user_id }),
        }
    }

    #[test]
    fn known_customer_shares_one_private_thread() {
        let email = SenderIdentity::Email("bob@example.com".to_string());
        let pubkey = SenderIdentity::Pubkey("ab".repeat(32));

        let via_email = conversation_key(&email, &customer(7), SupportChannelKind::Email);
        let via_chat = conversation_key(&pubkey, &customer(7), SupportChannelKind::WebChat);

        assert_eq!(via_email, "user:7");
        assert_eq!(
            via_email, via_chat,
            "email and live chat must share one thread for the same customer"
        );
    }

    /// The privacy regression this namespacing exists to prevent: a public
    /// kind-1 thread must never resolve to the same key as a private one, or
    /// the agent could quote a private email into a world-readable reply.
    #[test]
    fn public_nostr_never_joins_the_private_thread() {
        let pubkey = SenderIdentity::Pubkey("cd".repeat(32));
        let private = conversation_key(&pubkey, &customer(7), SupportChannelKind::WebChat);
        let public = conversation_key(&pubkey, &customer(7), SupportChannelKind::Nostr);

        assert_eq!(private, "user:7");
        assert_eq!(public, format!("nostr:{}", "cd".repeat(32)));
        assert_ne!(private, public);
    }

    #[test]
    fn anonymous_senders_key_on_their_identity() {
        let email = SenderIdentity::Email("nobody@example.com".to_string());
        assert_eq!(
            conversation_key(&email, &Requester::Anonymous, SupportChannelKind::Email),
            "email:nobody@example.com"
        );

        let pubkey = SenderIdentity::Pubkey("ef".repeat(32));
        assert_eq!(
            conversation_key(&pubkey, &Requester::Anonymous, SupportChannelKind::WebChat),
            format!("pubkey:{}", "ef".repeat(32))
        );
    }

    /// Email addresses are case-insensitive, so the same mailbox must not open
    /// two threads before the sender is resolved to an account.
    #[test]
    fn anonymous_email_key_is_case_insensitive() {
        let upper = SenderIdentity::Email("Bob@Example.COM".to_string());
        let lower = SenderIdentity::Email("bob@example.com".to_string());
        assert_eq!(
            conversation_key(&upper, &Requester::Anonymous, SupportChannelKind::Email),
            conversation_key(&lower, &Requester::Anonymous, SupportChannelKind::Email)
        );
    }

    /// A guest transcript is keyed only on the server-issued session id, and
    /// must never share a namespace with a pubkey-identified sender.
    #[test]
    fn guest_sessions_key_on_their_session_id() {
        let session = "ab".repeat(32);
        assert_eq!(
            conversation_key(
                &SenderIdentity::Guest(session.clone()),
                &Requester::Anonymous,
                SupportChannelKind::WebChat
            ),
            format!("guest:{session}")
        );
        assert_ne!(
            conversation_key(
                &SenderIdentity::Guest(session.clone()),
                &Requester::Anonymous,
                SupportChannelKind::WebChat
            ),
            conversation_key(
                &SenderIdentity::Pubkey(session),
                &Requester::Anonymous,
                SupportChannelKind::WebChat
            )
        );
    }

    #[test]
    fn requester_exposes_user_id() {
        assert_eq!(customer(3).user_id(), Some(3));
        assert_eq!(Requester::Anonymous.user_id(), None);
    }

    #[test]
    fn only_nostr_is_public() {
        assert!(SupportChannelKind::Nostr.is_public());
        assert!(!SupportChannelKind::Email.is_public());
        assert!(!SupportChannelKind::WebChat.is_public());
    }
}
