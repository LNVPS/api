use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;

use crate::identity::SupportChannelKind;

pub mod db;
pub use db::DbConversationStore;

/// A tool call requested by the assistant within a chat turn.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredToolCall {
    /// Provider-assigned tool call id (used to correlate the tool result).
    pub id: String,
    /// Name of the tool that was invoked.
    pub name: String,
    /// Raw JSON arguments string passed to the tool.
    pub arguments: String,
}

/// A single message in a sender's conversation log.
///
/// The log is a faithful chat transcript: user messages, assistant
/// messages (which may carry tool calls instead of text), and tool
/// result messages, in the order they occurred. This lets the agent
/// replay full context — including prior tool usage — on later turns.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ChatMessage {
    /// A message from the sender.
    User {
        /// The sender's text.
        content: String,
        /// Unix timestamp (seconds) when the message was recorded.
        timestamp: i64,
    },
    /// A message from the assistant, optionally requesting tool calls.
    Assistant {
        /// Assistant text. `None` when the turn only requested tool calls.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        /// Tool calls requested in this turn (empty for plain replies).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<StoredToolCall>,
        /// Unix timestamp (seconds) when the message was recorded.
        timestamp: i64,
    },
    /// The result of executing a tool call.
    Tool {
        /// The `StoredToolCall::id` this result corresponds to.
        tool_call_id: String,
        /// The tool's output (or error text).
        content: String,
        /// Unix timestamp (seconds) when the message was recorded.
        timestamp: i64,
    },
}

impl ChatMessage {
    /// Build a user message stamped with the current time.
    pub fn user(content: impl Into<String>) -> Self {
        ChatMessage::User {
            content: content.into(),
            timestamp: now(),
        }
    }

    /// Build an assistant message stamped with the current time.
    pub fn assistant(content: Option<String>, tool_calls: Vec<StoredToolCall>) -> Self {
        ChatMessage::Assistant {
            content,
            tool_calls,
            timestamp: now(),
        }
    }

    /// Build a tool-result message stamped with the current time.
    pub fn tool(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        ChatMessage::Tool {
            tool_call_id: tool_call_id.into(),
            content: content.into(),
            timestamp: now(),
        }
    }

    /// Render this message as a transcript line for summarisation.
    pub fn transcript_line(&self) -> String {
        match self {
            ChatMessage::User { content, .. } => format!("User: {content}"),
            ChatMessage::Assistant {
                content,
                tool_calls,
                ..
            } => {
                let mut line = format!("Agent: {}", content.as_deref().unwrap_or(""));
                for tc in tool_calls {
                    line.push_str(&format!("\n  [tool call] {}({})", tc.name, tc.arguments));
                }
                line
            }
            ChatMessage::Tool { content, .. } => format!("Tool result: {content}"),
        }
    }
}

/// Current Unix timestamp in seconds.
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The conversation context to replay for a sender: the accumulated summary
/// plus every message not yet folded into it.
///
/// This is a *snapshot*, not the whole history. Compaction summarises the
/// messages in a snapshot and advances a high-water mark so they stop being
/// replayed; depending on the store, the underlying messages may be retained
/// (the database store keeps them as a training corpus).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SenderConversation {
    /// LLM-generated summary of all compacted messages.
    #[serde(default)]
    pub summary: Option<String>,
    /// Chat log that hasn't been compacted yet.
    #[serde(default, alias = "entries")]
    pub messages: Vec<ChatMessage>,
    /// Opaque high-water mark identifying the last message in this snapshot.
    ///
    /// Passed back to [`ConversationStore::compact`] so that only what was
    /// actually summarised is marked compacted — messages that arrive while the
    /// summary is being generated must not be silently dropped from context.
    /// Never persisted; each store defines its own meaning (a row id, a count).
    #[serde(skip)]
    pub cursor: u64,
}

/// Trait for conversation storage.
#[async_trait]
pub trait ConversationStore: Send + Sync {
    /// Load the context to replay for a sender: summary + uncompacted messages.
    async fn load(&self, sender_id: &str) -> SenderConversation;

    /// Append one or more chat messages for a sender.
    ///
    /// `channel` records how the message travelled, so a single private thread
    /// can distinguish an email exchange from a live-chat one.
    async fn append(
        &self,
        sender_id: &str,
        channel: SupportChannelKind,
        messages: Vec<ChatMessage>,
    ) -> Result<()>;

    /// Record a compaction: store `summary` and stop replaying every message up
    /// to `cursor` (the value from the [`SenderConversation`] that was
    /// summarised).
    ///
    /// Implementations must treat the high-water mark as monotonic — a late or
    /// duplicated compaction must never re-expose messages already summarised.
    async fn compact(&self, sender_id: &str, summary: String, cursor: u64) -> Result<()>;
}

/// Ephemeral, process-local conversation store.
///
/// Used by the live-chat websocket, where history is scoped to the lifetime of
/// a single connection: one store is created per socket and dropped when the
/// socket closes, so nothing is persisted and nothing leaks between sessions.
#[derive(Default)]
pub struct MemoryStore {
    conversations: RwLock<HashMap<String, SenderConversation>>,
}

impl MemoryStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ConversationStore for MemoryStore {
    async fn load(&self, sender_id: &str) -> SenderConversation {
        let key = normalize_key(sender_id);
        let mut conv = self
            .conversations
            .read()
            .await
            .get(&key)
            .cloned()
            .unwrap_or_default();
        conv.cursor = conv.messages.len() as u64;
        conv
    }

    async fn append(
        &self,
        sender_id: &str,
        _channel: SupportChannelKind,
        messages: Vec<ChatMessage>,
    ) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }
        let key = normalize_key(sender_id);
        self.conversations
            .write()
            .await
            .entry(key)
            .or_default()
            .messages
            .extend(messages);
        Ok(())
    }

    async fn compact(&self, sender_id: &str, summary: String, cursor: u64) -> Result<()> {
        let key = normalize_key(sender_id);
        let mut conversations = self.conversations.write().await;
        let conv = conversations.entry(key).or_default();
        conv.summary = Some(summary);
        // Drop only what was summarised; anything appended during summarisation
        // stays in the replay window.
        drain_compacted(&mut conv.messages, cursor);
        Ok(())
    }
}

/// Drop the first `cursor` messages, saturating at the current length.
///
/// Shared by the in-memory and file stores, which both represent the high-water
/// mark as "number of messages summarised so far".
fn drain_compacted(messages: &mut Vec<ChatMessage>, cursor: u64) {
    let take = (cursor as usize).min(messages.len());
    messages.drain(..take);
}

/// Normalize a sender_id into a cache key / filename.
/// Lowercases and replaces non-alphanumeric chars so that
/// `Kieran@Harkin.me` and `kieran@harkin.me` and `kieran_harkin.me`
/// all map to the same key.
fn normalize_key(sender_id: &str) -> String {
    sender_id
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

// ── Legacy on-disk format migration ─────────────────────────────────

/// A pre-chat-log exchange (user message + final agent response).
#[derive(Deserialize)]
struct LegacyEntry {
    user_message: String,
    agent_response: String,
    #[serde(default)]
    timestamp: i64,
}

/// The pre-chat-log `SenderConversation` shape.
#[derive(Deserialize)]
struct LegacyConversation {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    entries: Vec<LegacyEntry>,
}

impl LegacyEntry {
    /// Expand a legacy exchange into the equivalent user + assistant messages.
    fn into_messages(self) -> Vec<ChatMessage> {
        vec![
            ChatMessage::User {
                content: self.user_message,
                timestamp: self.timestamp,
            },
            ChatMessage::Assistant {
                content: Some(self.agent_response),
                tool_calls: vec![],
                timestamp: self.timestamp,
            },
        ]
    }
}

/// Parse stored conversation JSON, accepting the current format and both
/// legacy formats (`SenderConversation` with `entries`, or a bare
/// `Vec<LegacyEntry>`).
fn parse_conversation(data: &str) -> Option<SenderConversation> {
    // Current format (messages, with `entries` accepted as an alias).
    if let Ok(conv) = serde_json::from_str::<SenderConversation>(data)
        && (conv.summary.is_some() || !conv.messages.is_empty())
    {
        return Some(conv);
    }

    // Legacy `{ summary, entries: [{user_message, agent_response}] }`.
    if let Ok(legacy) = serde_json::from_str::<LegacyConversation>(data) {
        let messages = legacy
            .entries
            .into_iter()
            .flat_map(LegacyEntry::into_messages)
            .collect::<Vec<_>>();
        if legacy.summary.is_some() || !messages.is_empty() {
            return Some(SenderConversation {
                summary: legacy.summary,
                messages,
                cursor: 0,
            });
        }
    }

    // Oldest legacy format: a bare array of exchanges.
    if let Ok(legacy) = serde_json::from_str::<Vec<LegacyEntry>>(data) {
        return Some(SenderConversation {
            summary: None,
            messages: legacy
                .into_iter()
                .flat_map(LegacyEntry::into_messages)
                .collect(),
            cursor: 0,
        });
    }

    None
}

/// JSON-file-backed conversation store.
///
/// Each sender gets a file at `<root>/<normalized_key>.json`.
pub struct JsonFileStore {
    root: PathBuf,
    /// In-memory cache, periodically flushed to disk.
    /// Keys are always normalized via `normalize_key`.
    cache: RwLock<HashMap<String, SenderConversation>>,
}

impl JsonFileStore {
    pub async fn new(root: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&root).await?;

        let mut cache = HashMap::new();
        let mut entries = tokio::fs::read_dir(&root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                let key = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                match tokio::fs::read_to_string(&path).await {
                    Ok(data) => match parse_conversation(&data) {
                        Some(conv) => {
                            log::info!(
                                "Loaded history for {}: summary={}, {} messages",
                                key,
                                conv.summary.is_some(),
                                conv.messages.len()
                            );
                            cache.insert(key, conv);
                        }
                        None => log::warn!("Failed to parse history for {}", key),
                    },
                    Err(e) => {
                        log::warn!("Failed to read history for {}: {}", key, e);
                    }
                }
            }
        }

        Ok(Self {
            root,
            cache: RwLock::new(cache),
        })
    }

    async fn flush(&self, key: &str, conv: &SenderConversation) -> Result<()> {
        let path = self.root.join(format!("{}.json", key));
        let json = serde_json::to_string_pretty(conv)?;
        tokio::fs::write(&path, json).await?;
        Ok(())
    }
}

#[async_trait]
impl ConversationStore for JsonFileStore {
    async fn load(&self, sender_id: &str) -> SenderConversation {
        let key = normalize_key(sender_id);
        let cache = self.cache.read().await;
        let mut conv = cache.get(&key).cloned().unwrap_or_default();
        conv.cursor = conv.messages.len() as u64;
        conv
    }

    async fn append(
        &self,
        sender_id: &str,
        _channel: SupportChannelKind,
        messages: Vec<ChatMessage>,
    ) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }
        let key = normalize_key(sender_id);
        let mut cache = self.cache.write().await;
        let conv = cache.entry(key.clone()).or_default();
        conv.messages.extend(messages);
        let snapshot = conv.clone();
        drop(cache);

        self.flush(&key, &snapshot).await
    }

    async fn compact(&self, sender_id: &str, summary: String, cursor: u64) -> Result<()> {
        let key = normalize_key(sender_id);
        let mut cache = self.cache.write().await;
        let conv = cache.entry(key.clone()).or_default();
        conv.summary = Some(summary);
        drain_compacted(&mut conv.messages, cursor);
        let snapshot = conv.clone();
        drop(cache);

        self.flush(&key, &snapshot).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SupportChannelKind;
    use tempfile::TempDir;

    /// Channel used by store tests; the file/memory stores ignore it.
    const CH: SupportChannelKind = SupportChannelKind::Email;

    fn exchange(user: &str, agent: &str) -> Vec<ChatMessage> {
        vec![
            ChatMessage::user(user),
            ChatMessage::assistant(Some(agent.to_string()), vec![]),
        ]
    }

    #[tokio::test]
    async fn append_and_load() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store
            .append("alice@example.com", CH, exchange("hello", "hi there"))
            .await
            .unwrap();
        store
            .append("alice@example.com", CH, exchange("vm status?", "running"))
            .await
            .unwrap();

        let conv = store.load("alice@example.com").await;
        assert_eq!(conv.messages.len(), 4);
        assert!(conv.summary.is_none());
        assert!(
            matches!(&conv.messages[0], ChatMessage::User { content, .. } if content == "hello")
        );
    }

    #[tokio::test]
    async fn append_empty_is_noop() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store.append("nobody", CH, vec![]).await.unwrap();
        assert!(store.load("nobody").await.messages.is_empty());
    }

    #[tokio::test]
    async fn append_with_tool_calls_roundtrips() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        let turn = vec![
            ChatMessage::user("show my vms"),
            ChatMessage::assistant(
                None,
                vec![StoredToolCall {
                    id: "call_1".to_string(),
                    name: "list_my_vms".to_string(),
                    arguments: "{}".to_string(),
                }],
            ),
            ChatMessage::tool("call_1", "[vm 5]"),
            ChatMessage::assistant(Some("You have one VM.".to_string()), vec![]),
        ];
        store.append("bob", CH, turn).await.unwrap();

        // Reload from a fresh store to exercise disk roundtrip.
        let store2 = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();
        let conv = store2.load("bob").await;
        assert_eq!(conv.messages.len(), 4);
        assert!(
            matches!(&conv.messages[1], ChatMessage::Assistant { tool_calls, .. } if tool_calls.len() == 1)
        );
        assert!(
            matches!(&conv.messages[2], ChatMessage::Tool { tool_call_id, .. } if tool_call_id == "call_1")
        );
    }

    #[tokio::test]
    async fn empty_load_returns_default() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        let conv = store.load("nobody@example.com").await;
        assert!(conv.messages.is_empty());
        assert!(conv.summary.is_none());
    }

    #[tokio::test]
    async fn compact_and_load_with_summary() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store
            .append("carol", CH, exchange("msg1", "resp1"))
            .await
            .unwrap();

        let snapshot = store.load("carol").await;
        assert_eq!(snapshot.cursor, 2);
        store
            .compact(
                "carol",
                "Carol asked about VM status. She has a running VM on Proxmox.".to_string(),
                snapshot.cursor,
            )
            .await
            .unwrap();

        let loaded = store.load("carol").await;
        assert_eq!(
            loaded.summary.unwrap(),
            "Carol asked about VM status. She has a running VM on Proxmox."
        );
        assert!(loaded.messages.is_empty());

        // New message after compaction
        store
            .append("carol", CH, exchange("how do I extend?", "call extend_vm"))
            .await
            .unwrap();
        let loaded = store.load("carol").await;
        assert_eq!(loaded.messages.len(), 2);
    }

    /// A message that lands while the summary is being generated must stay in
    /// the replay window — the cursor bounds what compaction consumes.
    #[tokio::test]
    async fn compact_only_drops_up_to_the_cursor() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store
            .append("frank", CH, vec![ChatMessage::user("first")])
            .await
            .unwrap();
        let snapshot = store.load("frank").await;

        store
            .append("frank", CH, vec![ChatMessage::user("late")])
            .await
            .unwrap();

        store
            .compact("frank", "sum".to_string(), snapshot.cursor)
            .await
            .unwrap();

        let loaded = store.load("frank").await;
        assert_eq!(loaded.messages.len(), 1);
        assert!(
            matches!(&loaded.messages[0], ChatMessage::User { content, .. } if content == "late")
        );
    }

    /// A cursor beyond the current length must clamp rather than panic.
    #[test]
    fn drain_compacted_saturates() {
        let mut messages = vec![ChatMessage::user("a"), ChatMessage::user("b")];
        drain_compacted(&mut messages, 99);
        assert!(messages.is_empty());

        let mut messages = vec![ChatMessage::user("a"), ChatMessage::user("b")];
        drain_compacted(&mut messages, 0);
        assert_eq!(messages.len(), 2);
    }

    #[tokio::test]
    async fn persists_across_sessions() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        let store1 = JsonFileStore::new(path.clone()).await.unwrap();
        store1
            .append("dave", CH, exchange("hello", "hi"))
            .await
            .unwrap();

        let store2 = JsonFileStore::new(path).await.unwrap();
        let conv = store2.load("dave").await;
        assert_eq!(conv.messages.len(), 2);
        assert!(
            matches!(&conv.messages[0], ChatMessage::User { content, .. } if content == "hello")
        );
    }

    #[tokio::test]
    async fn legacy_bare_array_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        // Oldest format: a bare Vec of {user_message, agent_response}.
        let legacy = serde_json::json!([
            {"user_message": "msg", "agent_response": "resp", "timestamp": 1700000000}
        ]);
        let _ = tokio::fs::create_dir_all(&path).await;
        let _ = tokio::fs::write(path.join("legacy_user.json"), legacy.to_string()).await;

        let store = JsonFileStore::new(path).await.unwrap();
        let conv = store.load("legacy_user").await;
        assert_eq!(conv.messages.len(), 2);
        assert!(matches!(&conv.messages[0], ChatMessage::User { content, .. } if content == "msg"));
        assert!(
            matches!(&conv.messages[1], ChatMessage::Assistant { content, .. } if content.as_deref() == Some("resp"))
        );
    }

    #[tokio::test]
    async fn legacy_entries_object_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        // Older SenderConversation shape with `entries`.
        let legacy = serde_json::json!({
            "summary": "prior context",
            "entries": [{"user_message": "hi", "agent_response": "hello", "timestamp": 1}]
        });
        let _ = tokio::fs::create_dir_all(&path).await;
        let _ = tokio::fs::write(path.join("legacy2.json"), legacy.to_string()).await;

        let store = JsonFileStore::new(path).await.unwrap();
        let conv = store.load("legacy2").await;
        assert_eq!(conv.summary.as_deref(), Some("prior context"));
        assert_eq!(conv.messages.len(), 2);
    }

    #[tokio::test]
    async fn email_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store
            .append("Kieran@Harkin.me", CH, exchange("msg1", "resp1"))
            .await
            .unwrap();

        // Same email, different case — should find the same data
        let conv = store.load("kieran@harkin.me").await;
        assert_eq!(conv.messages.len(), 2);

        // Append under lowercase key
        store
            .append("kieran@harkin.me", CH, exchange("msg2", "resp2"))
            .await
            .unwrap();

        // Check under original case — should see both exchanges
        let conv = store.load("Kieran@Harkin.me").await;
        assert_eq!(conv.messages.len(), 4);
    }

    #[tokio::test]
    async fn memory_store_roundtrips_and_isolates() {
        let store = MemoryStore::new();
        assert!(store.load("nobody").await.messages.is_empty());

        store
            .append("eve", CH, exchange("hi", "hello"))
            .await
            .unwrap();
        store.append("eve", CH, vec![]).await.unwrap();
        assert_eq!(store.load("eve").await.messages.len(), 2);

        // Case-insensitive keying matches the file store.
        assert_eq!(store.load("EVE").await.messages.len(), 2);

        // Compaction folds the snapshot into a summary.
        let snapshot = store.load("eve").await;
        store
            .compact("eve", "summarised".to_string(), snapshot.cursor)
            .await
            .unwrap();
        let conv = store.load("eve").await;
        assert_eq!(conv.summary.as_deref(), Some("summarised"));
        assert!(conv.messages.is_empty());

        // A second store shares no state — one per websocket connection.
        assert!(MemoryStore::new().load("eve").await.messages.is_empty());
    }

    #[test]
    fn normalize_key_works() {
        assert_eq!(normalize_key("kieran@harkin.me"), "kieran_harkin_me");
        assert_eq!(normalize_key("Kieran@Harkin.me"), "kieran_harkin_me");
        assert_eq!(normalize_key("KIERAN@HARKIN.ME"), "kieran_harkin_me");
        assert_eq!(normalize_key("bob"), "bob");
        assert_eq!(
            normalize_key("user+tag@example.com"),
            "user_tag_example_com"
        );
    }

    #[test]
    fn transcript_line_formats_each_role() {
        assert_eq!(ChatMessage::user("hi").transcript_line(), "User: hi");
        assert_eq!(
            ChatMessage::assistant(Some("ok".to_string()), vec![]).transcript_line(),
            "Agent: ok"
        );
        let with_call = ChatMessage::assistant(
            None,
            vec![StoredToolCall {
                id: "1".to_string(),
                name: "list_my_vms".to_string(),
                arguments: "{}".to_string(),
            }],
        );
        assert_eq!(
            with_call.transcript_line(),
            "Agent: \n  [tool call] list_my_vms({})"
        );
        assert_eq!(
            ChatMessage::tool("1", "result").transcript_line(),
            "Tool result: result"
        );
    }
}
