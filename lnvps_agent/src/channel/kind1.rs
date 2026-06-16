use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use nostr_sdk::prelude::*;
use tokio::sync::mpsc;

use crate::api_client::ApiClient;
use crate::channel::{IncomingSupportRequest, Requester, SupportChannel, SupportReply};
use crate::settings::Kind1Config;

/// Kind 1 Nostr support channel.
///
/// Connects to relays, subscribes for kind 1 events that mention the bot's
/// pubkey, and receives them in real-time via `handle_notifications`.
/// Replies are published as NIP-10 kind 1 replies.
pub struct Kind1SupportChannel {
    client: Client,
    /// Receive end of the channel fed by the notification handler.
    rx: tokio::sync::Mutex<mpsc::Receiver<IncomingSupportRequest>>,
}

impl Kind1SupportChannel {
    pub async fn new(config: Kind1Config, nsec: &str, api: Arc<ApiClient>) -> Result<Self> {
        let keys = Keys::parse(nsec).context("Invalid nsec key for kind1 channel")?;
        let bot_pubkey = keys.public_key();

        if config.relays.is_empty() {
            anyhow::bail!("kind1.relays must contain at least one relay URL");
        }

        let mention_pubkeys = match &config.mention_pubkeys {
            Some(pk_hexes) => pk_hexes
                .iter()
                .map(|h| PublicKey::from_hex(h).context("Invalid mention pubkey hex"))
                .collect::<Result<Vec<_>>>()?,
            None => vec![bot_pubkey],
        };

        let opts = ClientOptions::new().automatic_authentication(false);

        let client = Client::builder().signer(keys).opts(opts).build();

        // Connect to relays
        for relay in &config.relays {
            client
                .add_relay(relay)
                .await
                .with_context(|| format!("Failed to add relay: {}", relay))?;
        }
        client.connect().await;
        log::info!("Kind1 channel connected to {} relays", config.relays.len());

        // Subscribe to kind 1 events that mention any of our monitored pubkeys
        let filter = Filter::new()
            .kind(Kind::TextNote)
            .pubkeys(mention_pubkeys.clone())
            .since(Timestamp::now());

        client.subscribe(filter, None).await?;
        log::info!(
            "Kind1 channel subscribed to mentions of {} pubkey(s)",
            mention_pubkeys.len()
        );

        // Clone client for the notification handler
        let client_clone = client.clone();

        // Spawn notification handler that pushes incoming events into an mpsc channel
        let (tx, rx) = mpsc::channel::<IncomingSupportRequest>(256);
        let handler_bot = bot_pubkey;
        let handler_mentions = mention_pubkeys.clone();
        let handler_api = api.clone();

        tokio::spawn(async move {
            let seen = Arc::new(std::sync::Mutex::new(HashSet::<EventId>::new()));

            let result = client_clone
                .handle_notifications(|notification| {
                    let tx = tx.clone();
                    let handler_mentions = handler_mentions.clone();
                    let handler_api = handler_api.clone();
                    let seen = seen.clone();

                    async move {
                        match notification {
                            RelayPoolNotification::Event { event, .. } => {
                                // Skip our own events
                                if event.pubkey == handler_bot {
                                    return Ok(false);
                                }

                                // Skip already seen
                                {
                                    let mut seen = seen.lock().unwrap();
                                    if seen.contains(&event.id) {
                                        return Ok(false);
                                    }
                                    seen.insert(event.id);
                                }

                                // Verify the event has a p-tag for one of our monitored pubkeys
                                let mentions_us = event.tags.iter().any(|tag| {
                                    if let Some(TagStandard::PublicKey {
                                        public_key,
                                        uppercase: false,
                                        ..
                                    }) = tag.as_standardized()
                                    {
                                        handler_mentions.contains(public_key)
                                    } else {
                                        false
                                    }
                                });

                                if !mentions_us {
                                    return Ok(false);
                                }

                                let author_hex = event.pubkey.to_string();
                                let short = &author_hex[..16.min(author_hex.len())];

                                // Resolve the author against the LNVPS API once.
                                let requester = match handler_api
                                    .admin_find_user_by_pubkey(&author_hex)
                                    .await
                                {
                                    Ok(Some(user)) => {
                                        match user.get("id").and_then(|v| v.as_u64()) {
                                            Some(user_id) => Requester::Customer {
                                                user_id,
                                                pubkey: Some(author_hex.clone()),
                                            },
                                            None => {
                                                log::warn!(
                                                    "Kind1 user {} has no id field — general",
                                                    short
                                                );
                                                Requester::Anonymous
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        log::info!(
                                            "Kind1 mention from {} is not an LNVPS user — general",
                                            short
                                        );
                                        Requester::Anonymous
                                    }
                                    Err(e) => {
                                        log::error!("API error looking up {}: {}", short, e);
                                        Requester::Anonymous
                                    }
                                };

                                log::info!(
                                    "Kind1 mention from {} (event {}): {}",
                                    &author_hex[..16.min(author_hex.len())],
                                    event.id,
                                    &event.content[..event.content.len().min(100)]
                                );

                                let req = IncomingSupportRequest {
                                    requester,
                                    conversation_key: author_hex,
                                    message: event.content.clone(),
                                    channel_context: Some(
                                        serde_json::json!({
                                            "event_id": event.id.to_hex(),
                                            "event_json": event.as_json(),
                                        })
                                        .to_string(),
                                    ),
                                };

                                let _ = tx.send(req).await;

                                Ok(false) // keep listening
                            }
                            _ => Ok(false),
                        }
                    }
                })
                .await;

            if let Err(e) = result {
                log::error!("Kind1 notification handler exited: {}", e);
            }
        });

        Ok(Self {
            client,
            rx: tokio::sync::Mutex::new(rx),
        })
    }
}

#[async_trait]
impl SupportChannel for Kind1SupportChannel {
    fn channel_prompt(&self) -> &str {
        r#"Format your responses for a Nostr kind 1 post:
- Keep it SHORT — Nostr kind 1 events should be concise (under ~500 chars is ideal, max ~2000)
- You may use Nostr-style formatting: **bold**, _italic_, and `code`
- Be friendly and direct — social media tone, not corporate email
- Include relevant links if helpful (e.g. https://lnvps.net)
- Do NOT sign off with "Best regards" or similar — this is a public social media reply
- Do NOT include "Re:" or subject lines
- Remember: your reply will be PUBLIC on Nostr — be professional and helpful
- Use emoji sparingly if it fits the context"#
    }

    async fn next_request(&self) -> Option<IncomingSupportRequest> {
        self.rx.lock().await.recv().await
    }

    async fn send_reply(&self, reply: SupportReply) -> Result<()> {
        let ctx: serde_json::Value = reply
            .channel_context
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let event_id_hex = ctx
            .get("event_id")
            .and_then(|v| v.as_str())
            .context("Missing event_id in channel context")?;

        let event_json = ctx
            .get("event_json")
            .and_then(|v| v.as_str())
            .context("Missing event_json in channel context")?;

        let original_event =
            Event::from_json(event_json).context("Failed to parse original event JSON")?;

        // Build a NIP-10 text note reply
        let builder = EventBuilder::text_note_reply(
            &reply.response,
            &original_event,
            None::<&Event>,   // root = same as reply_to (top-level reply)
            None::<RelayUrl>, // no specific relay URL
        );

        let output = self
            .client
            .send_event_builder(builder)
            .await
            .context("Failed to publish kind 1 reply")?;

        log::info!(
            "Kind1 reply published for event {}: {}",
            event_id_hex,
            output.val
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nsec_and_derive_pubkey() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let parsed = Keys::parse(&nsec).unwrap();
        assert_eq!(parsed.public_key(), keys.public_key());
    }
}
