use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;

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

/// Full conversation state for a single sender.
///
/// When history is compacted, `summary` contains a condensed narrative
/// of all prior messages and `messages` is reset to empty. New messages
/// after compaction accumulate in `messages` until the next compaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SenderConversation {
    /// LLM-generated summary of all compacted messages.
    #[serde(default)]
    pub summary: Option<String>,
    /// Raw chat log that hasn't been compacted yet.
    #[serde(default, alias = "entries")]
    pub messages: Vec<ChatMessage>,
}

/// Trait for persistent conversation storage.
#[async_trait]
pub trait ConversationStore: Send + Sync {
    /// Load full conversation state for a sender.
    async fn load(&self, sender_id: &str) -> SenderConversation;

    /// Append one or more chat messages for a sender.
    async fn append(&self, sender_id: &str, messages: Vec<ChatMessage>) -> Result<()>;

    /// Replace the entire conversation state for a sender (used after compaction).
    async fn save(&self, sender_id: &str, conversation: SenderConversation) -> Result<()>;
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
        cache.get(&key).cloned().unwrap_or_default()
    }

    async fn append(&self, sender_id: &str, messages: Vec<ChatMessage>) -> Result<()> {
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

    async fn save(&self, sender_id: &str, conversation: SenderConversation) -> Result<()> {
        let key = normalize_key(sender_id);
        let mut cache = self.cache.write().await;
        cache.insert(key.clone(), conversation.clone());
        drop(cache);

        self.flush(&key, &conversation).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
            .append("alice@example.com", exchange("hello", "hi there"))
            .await
            .unwrap();
        store
            .append("alice@example.com", exchange("vm status?", "running"))
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

        store.append("nobody", vec![]).await.unwrap();
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
        store.append("bob", turn).await.unwrap();

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
    async fn save_and_load_with_summary() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store
            .append("carol", exchange("msg1", "resp1"))
            .await
            .unwrap();

        // Compact: save summary, clear messages
        let conv = SenderConversation {
            summary: Some(
                "Carol asked about VM status. She has a running VM on Proxmox.".to_string(),
            ),
            messages: vec![],
        };
        store.save("carol", conv).await.unwrap();

        let loaded = store.load("carol").await;
        assert_eq!(
            loaded.summary.unwrap(),
            "Carol asked about VM status. She has a running VM on Proxmox."
        );
        assert!(loaded.messages.is_empty());

        // New message after compaction
        store
            .append("carol", exchange("how do I extend?", "call extend_vm"))
            .await
            .unwrap();
        let loaded = store.load("carol").await;
        assert_eq!(loaded.messages.len(), 2);
    }

    #[tokio::test]
    async fn persists_across_sessions() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        let store1 = JsonFileStore::new(path.clone()).await.unwrap();
        store1
            .append("dave", exchange("hello", "hi"))
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
            .append("Kieran@Harkin.me", exchange("msg1", "resp1"))
            .await
            .unwrap();

        // Same email, different case — should find the same data
        let conv = store.load("kieran@harkin.me").await;
        assert_eq!(conv.messages.len(), 2);

        // Append under lowercase key
        store
            .append("kieran@harkin.me", exchange("msg2", "resp2"))
            .await
            .unwrap();

        // Check under original case — should see both exchanges
        let conv = store.load("Kieran@Harkin.me").await;
        assert_eq!(conv.messages.len(), 4);
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
