//! Database-backed conversation storage.
//!
//! Used when the agent runs inside `lnvps_api`. Unlike the file and in-memory
//! stores, this one is **append-only**: compaction advances a watermark on the
//! parent row instead of deleting messages, so the full transcript is retained
//! as a training corpus while the replayed context stays bounded.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use lnvps_db::{AgentChannel, AgentMessageRole, LNVpsDb, NewAgentMessage};

use crate::conversation::{ChatMessage, ConversationStore, SenderConversation, StoredToolCall};
use crate::identity::SupportChannelKind;

/// Map the agent's channel enum onto the database representation.
fn db_channel(channel: SupportChannelKind) -> AgentChannel {
    match channel {
        SupportChannelKind::Email => AgentChannel::Email,
        SupportChannelKind::Nostr => AgentChannel::Nostr,
        SupportChannelKind::WebChat => AgentChannel::WebChat,
    }
}

/// Flatten a chat message into its database row form.
fn to_new_message(channel: AgentChannel, message: &ChatMessage) -> Result<NewAgentMessage> {
    Ok(match message {
        ChatMessage::User { content, .. } => NewAgentMessage {
            role: AgentMessageRole::User,
            channel,
            content: Some(content.clone()),
            tool_calls: None,
            tool_call_id: None,
        },
        ChatMessage::Assistant {
            content,
            tool_calls,
            ..
        } => NewAgentMessage {
            role: AgentMessageRole::Assistant,
            channel,
            content: content.clone(),
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(serde_json::to_string(tool_calls).context("serialize tool calls")?)
            },
            tool_call_id: None,
        },
        ChatMessage::Tool {
            tool_call_id,
            content,
            ..
        } => NewAgentMessage {
            role: AgentMessageRole::Tool,
            channel,
            content: Some(content.clone()),
            tool_calls: None,
            tool_call_id: Some(tool_call_id.clone()),
        },
    })
}

/// Rebuild a chat message from its database row.
///
/// A row that fails to convert is skipped rather than failing the whole load:
/// losing one malformed message degrades the agent's memory, whereas erroring
/// out would make the conversation permanently unusable.
fn from_db_message(row: &lnvps_db::AgentMessage) -> Option<ChatMessage> {
    let timestamp = row.created.timestamp();
    let content = row.content.as_ref().map(|c| c.as_str().to_string());

    match row.role {
        AgentMessageRole::User => Some(ChatMessage::User {
            content: content?,
            timestamp,
        }),
        AgentMessageRole::Assistant => {
            let tool_calls: Vec<StoredToolCall> = match row.tool_calls.as_deref() {
                Some(raw) => serde_json::from_slice(raw)
                    .map_err(|e| log::warn!("agent_message {}: bad tool_calls: {}", row.id, e))
                    .ok()?,
                None => vec![],
            };
            // An assistant row with neither prose nor tool calls carries no
            // information and would replay as an empty turn.
            if content.is_none() && tool_calls.is_empty() {
                return None;
            }
            Some(ChatMessage::Assistant {
                content,
                tool_calls,
                timestamp,
            })
        }
        AgentMessageRole::Tool => Some(ChatMessage::Tool {
            tool_call_id: row.tool_call_id.clone()?,
            content: content.unwrap_or_default(),
            timestamp,
        }),
    }
}

/// Conversation store backed by the `agent_conversation` / `agent_message`
/// tables.
pub struct DbConversationStore {
    db: Arc<dyn LNVpsDb>,
    /// Resolved LNVPS user for this conversation, denormalised onto the thread
    /// row. `None` for a sender that matched no account.
    user_id: Option<u64>,
}

impl DbConversationStore {
    /// Create a store for a sender resolved to `user_id` (or `None` if
    /// anonymous).
    pub fn new(db: Arc<dyn LNVpsDb>, user_id: Option<u64>) -> Self {
        Self { db, user_id }
    }

    /// Resolve the conversation row id for a key, creating the thread if needed.
    async fn conversation_id(&self, sender_id: &str) -> Result<u64> {
        Ok(self
            .db
            .upsert_agent_conversation(sender_id, self.user_id)
            .await?
            .id)
    }
}

#[async_trait]
impl ConversationStore for DbConversationStore {
    async fn load(&self, sender_id: &str) -> SenderConversation {
        match self.load_inner(sender_id).await {
            Ok(conv) => conv,
            Err(e) => {
                // Matches the file store's contract: a failed load degrades to
                // an empty context rather than failing the customer's request.
                log::error!("Failed to load conversation for {}: {}", sender_id, e);
                SenderConversation::default()
            }
        }
    }

    async fn append(
        &self,
        sender_id: &str,
        channel: SupportChannelKind,
        messages: Vec<ChatMessage>,
    ) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }
        let conversation_id = self.conversation_id(sender_id).await?;
        let channel = db_channel(channel);
        let rows = messages
            .iter()
            .map(|m| to_new_message(channel, m))
            .collect::<Result<Vec<_>>>()?;
        self.db
            .append_agent_messages(conversation_id, &rows)
            .await?;
        Ok(())
    }

    async fn compact(&self, sender_id: &str, summary: String, cursor: u64) -> Result<()> {
        let conversation_id = self.conversation_id(sender_id).await?;
        // `cursor` is the id of the last message that went into the summary; the
        // DB clamps it monotonically so a stale compaction can't regress it.
        self.db
            .compact_agent_conversation(conversation_id, &summary, cursor)
            .await?;
        Ok(())
    }
}

impl DbConversationStore {
    /// Fallible body of [`ConversationStore::load`].
    async fn load_inner(&self, sender_id: &str) -> Result<SenderConversation> {
        let conversation = self
            .db
            .upsert_agent_conversation(sender_id, self.user_id)
            .await?;
        let rows = self
            .db
            .list_agent_messages_after_watermark(conversation.id)
            .await?;

        // The cursor is the highest row id in this snapshot, so a compaction
        // only covers what was actually summarised. Falling back to the stored
        // watermark keeps an empty snapshot from resetting it to zero.
        let cursor = rows
            .last()
            .map(|m| m.id)
            .unwrap_or(conversation.compacted_upto);

        Ok(SenderConversation {
            summary: conversation.summary,
            messages: rows.iter().filter_map(from_db_message).collect(),
            cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;

    fn store(db: Arc<dyn LNVpsDb>, user_id: Option<u64>) -> DbConversationStore {
        DbConversationStore::new(db, user_id)
    }

    fn turn() -> Vec<ChatMessage> {
        vec![
            ChatMessage::user("show my vms"),
            ChatMessage::assistant(
                None,
                vec![StoredToolCall {
                    id: "c1".to_string(),
                    name: "list_my_vms".to_string(),
                    arguments: "{}".to_string(),
                }],
            ),
            ChatMessage::tool("c1", "[vm 5]"),
            ChatMessage::assistant(Some("You have one VM.".to_string()), vec![]),
        ]
    }

    #[tokio::test]
    async fn roundtrips_a_full_turn_including_tool_calls() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let store = store(db, Some(1));

        store
            .append("user:1", SupportChannelKind::WebChat, turn())
            .await
            .unwrap();

        let conv = store.load("user:1").await;
        assert_eq!(conv.messages.len(), 4);
        assert!(
            matches!(&conv.messages[0], ChatMessage::User { content, .. } if content == "show my vms")
        );
        assert!(
            matches!(&conv.messages[1], ChatMessage::Assistant { content, tool_calls, .. }
                if content.is_none() && tool_calls.len() == 1 && tool_calls[0].name == "list_my_vms")
        );
        assert!(
            matches!(&conv.messages[2], ChatMessage::Tool { tool_call_id, content, .. }
                if tool_call_id == "c1" && content == "[vm 5]")
        );
        assert!(conv.cursor > 0);
    }

    #[tokio::test]
    async fn append_empty_is_noop() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let store = store(db, Some(1));
        store
            .append("user:1", SupportChannelKind::Email, vec![])
            .await
            .unwrap();
        assert!(store.load("user:1").await.messages.is_empty());
    }

    /// Compaction must bound the replay window without destroying the corpus.
    #[tokio::test]
    async fn compaction_bounds_context_but_retains_transcript() {
        let mock = Arc::new(MockDb::default());
        let db: Arc<dyn LNVpsDb> = mock.clone();
        let store = store(db.clone(), Some(2));

        store
            .append("user:2", SupportChannelKind::Email, turn())
            .await
            .unwrap();
        let before = store.load("user:2").await;
        assert_eq!(before.messages.len(), 4);

        store
            .compact("user:2", "summarised".to_string(), before.cursor)
            .await
            .unwrap();

        let after = store.load("user:2").await;
        assert!(after.messages.is_empty(), "context must be bounded");
        assert_eq!(after.summary.as_deref(), Some("summarised"));

        // The transcript itself survives for training.
        let conversation = db
            .upsert_agent_conversation("user:2", Some(2))
            .await
            .unwrap();
        let all = db
            .list_agent_messages_paginated(conversation.id, 100, 0)
            .await
            .unwrap();
        assert_eq!(all.len(), 4, "compaction must not delete messages");
    }

    /// Messages appended while a summary is being generated must not be
    /// silently dropped from context.
    #[tokio::test]
    async fn messages_appended_during_compaction_survive() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let store = store(db, Some(3));

        store
            .append(
                "user:3",
                SupportChannelKind::Email,
                vec![ChatMessage::user("first")],
            )
            .await
            .unwrap();
        let snapshot = store.load("user:3").await;

        // A late message lands after the snapshot was taken.
        store
            .append(
                "user:3",
                SupportChannelKind::WebChat,
                vec![ChatMessage::user("late")],
            )
            .await
            .unwrap();

        // Compaction only covers the snapshot.
        store
            .compact("user:3", "sum".to_string(), snapshot.cursor)
            .await
            .unwrap();

        let after = store.load("user:3").await;
        assert_eq!(after.messages.len(), 1);
        assert!(
            matches!(&after.messages[0], ChatMessage::User { content, .. } if content == "late")
        );
    }

    /// Threads are keyed independently, so the public Nostr thread cannot see
    /// anything from the private one.
    #[tokio::test]
    async fn threads_are_isolated_by_key() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let store = store(db, Some(9));

        store
            .append(
                "user:9",
                SupportChannelKind::Email,
                vec![ChatMessage::user("card ending 4242 failed")],
            )
            .await
            .unwrap();

        let public = store.load("nostr:deadbeef").await;
        assert!(
            public.messages.is_empty(),
            "private message must not leak into the public thread"
        );
    }

    #[test]
    fn skips_unconvertible_rows() {
        // An assistant row with no content and no tool calls carries nothing.
        let row = lnvps_db::AgentMessage {
            id: 1,
            conversation_id: 1,
            role: AgentMessageRole::Assistant,
            channel: AgentChannel::Email,
            content: None,
            tool_calls: None,
            tool_call_id: None,
            created: chrono::Utc::now(),
        };
        assert!(from_db_message(&row).is_none());

        // A tool row without its correlating id cannot be replayed.
        let orphan = lnvps_db::AgentMessage {
            role: AgentMessageRole::Tool,
            content: Some("result".into()),
            tool_call_id: None,
            ..row.clone()
        };
        assert!(from_db_message(&orphan).is_none());

        // Malformed tool_calls JSON is dropped rather than poisoning the load.
        let bad_json = lnvps_db::AgentMessage {
            role: AgentMessageRole::Assistant,
            tool_calls: Some(b"not json".to_vec()),
            ..row.clone()
        };
        assert!(from_db_message(&bad_json).is_none());
    }

    #[test]
    fn channel_mapping_is_total() {
        assert_eq!(db_channel(SupportChannelKind::Email), AgentChannel::Email);
        assert_eq!(db_channel(SupportChannelKind::Nostr), AgentChannel::Nostr);
        assert_eq!(
            db_channel(SupportChannelKind::WebChat),
            AgentChannel::WebChat
        );
    }
}
