use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;

/// A single exchange between the user and the agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationEntry {
    /// The sender's message.
    pub user_message: String,
    /// The agent's final response (tool-call chains are not stored).
    pub agent_response: String,
    /// Unix timestamp (seconds) when the exchange happened.
    pub timestamp: i64,
}

/// Full conversation state for a single sender.
///
/// When history is compacted, `summary` contains a condensed
/// narrative of all prior exchanges and `entries` is reset to empty.
/// New exchanges after compaction accumulate in `entries` until the
/// next compaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SenderConversation {
    /// LLM-generated summary of all compacted exchanges.
    pub summary: Option<String>,
    /// Raw exchanges that haven't been compacted yet.
    pub entries: Vec<ConversationEntry>,
}

/// Trait for persistent conversation storage.
#[async_trait]
pub trait ConversationStore: Send + Sync {
    /// Load full conversation state for a sender.
    async fn load(&self, sender_id: &str) -> SenderConversation;

    /// Append an entry for a sender.
    async fn append(&self, sender_id: &str, entry: ConversationEntry) -> Result<()>;

    /// Truncate entries (not summary) to the most recent `keep` entries.
    async fn trim(&self, sender_id: &str, keep: usize) -> Result<()>;

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
                    Ok(data) => {
                        // Support both legacy format (Vec<ConversationEntry>) and new SenderConversation
                        if let Ok(conv) = serde_json::from_str::<SenderConversation>(&data) {
                            log::info!(
                                "Loaded history for {}: summary={}, {} entries",
                                key,
                                conv.summary.is_some(),
                                conv.entries.len()
                            );
                            cache.insert(key, conv);
                        } else if let Ok(legacy) = serde_json::from_str::<Vec<ConversationEntry>>(&data)
                        {
                            log::info!(
                                "Loaded legacy history for {}: {} entries",
                                key,
                                legacy.len()
                            );
                            cache.insert(
                                key,
                                SenderConversation {
                                    summary: None,
                                    entries: legacy,
                                },
                            );
                        } else {
                            log::warn!("Failed to parse history for {}", key);
                        }
                    }
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

    async fn append(&self, sender_id: &str, entry: ConversationEntry) -> Result<()> {
        let key = normalize_key(sender_id);
        let mut cache = self.cache.write().await;
        let conv = cache.entry(key.clone()).or_default();
        conv.entries.push(entry);
        let snapshot = conv.clone();
        drop(cache);

        self.flush(&key, &snapshot).await
    }

    async fn trim(&self, sender_id: &str, keep: usize) -> Result<()> {
        let key = normalize_key(sender_id);
        let mut cache = self.cache.write().await;
        let Some(conv) = cache.get_mut(&key) else {
            return Ok(());
        };
        if conv.entries.len() <= keep {
            return Ok(());
        }
        let drain = conv.entries.len() - keep;
        conv.entries.drain(0..drain);
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

    fn entry(user: &str, agent: &str) -> ConversationEntry {
        ConversationEntry {
            user_message: user.to_string(),
            agent_response: agent.to_string(),
            timestamp: 1700000000,
        }
    }

    #[tokio::test]
    async fn append_and_load() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store.append("alice@example.com", entry("hello", "hi there")).await.unwrap();
        store.append("alice@example.com", entry("vm status?", "running")).await.unwrap();

        let conv = store.load("alice@example.com").await;
        assert_eq!(conv.entries.len(), 2);
        assert!(conv.summary.is_none());
        assert_eq!(conv.entries[0].user_message, "hello");
    }

    #[tokio::test]
    async fn empty_load_returns_default() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        let conv = store.load("nobody@example.com").await;
        assert!(conv.entries.is_empty());
        assert!(conv.summary.is_none());
    }

    #[tokio::test]
    async fn trim_removes_oldest() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        for i in 0..5 {
            store.append("bob", entry(&format!("msg{}", i), &format!("resp{}", i))).await.unwrap();
        }

        store.trim("bob", 2).await.unwrap();

        let conv = store.load("bob").await;
        assert_eq!(conv.entries.len(), 2);
        assert_eq!(conv.entries[0].user_message, "msg3");
        assert_eq!(conv.entries[1].user_message, "msg4");
    }

    #[tokio::test]
    async fn save_and_load_with_summary() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store.append("carol", entry("msg1", "resp1")).await.unwrap();
        store.append("carol", entry("msg2", "resp2")).await.unwrap();

        // Compact: save summary, clear entries
        let conv = SenderConversation {
            summary: Some("Carol asked about VM status. She has a running VM on Proxmox.".to_string()),
            entries: vec![],
        };
        store.save("carol", conv).await.unwrap();

        let loaded = store.load("carol").await;
        assert_eq!(loaded.summary.unwrap(), "Carol asked about VM status. She has a running VM on Proxmox.");
        assert!(loaded.entries.is_empty());

        // New exchange after compaction
        store.append("carol", entry("how do I extend?", "call extend_vm")).await.unwrap();
        let loaded = store.load("carol").await;
        assert_eq!(loaded.entries.len(), 1);
    }

    #[tokio::test]
    async fn persists_across_sessions() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        let store1 = JsonFileStore::new(path.clone()).await.unwrap();
        store1.append("dave", entry("hello", "hi")).await.unwrap();

        let store2 = JsonFileStore::new(path).await.unwrap();
        let conv = store2.load("dave").await;
        assert_eq!(conv.entries.len(), 1);
        assert_eq!(conv.entries[0].user_message, "hello");
    }

    #[tokio::test]
    async fn legacy_format_loads() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        // Write raw Vec<ConversationEntry> (legacy format)
        let legacy: Vec<ConversationEntry> = vec![entry("msg", "resp")];
        let file = path.join("legacy_user.json");
        let _ = tokio::fs::create_dir_all(&path).await;
        let _ = tokio::fs::write(&file, serde_json::to_string(&legacy).unwrap()).await;

        let store = JsonFileStore::new(path).await.unwrap();
        let conv = store.load("legacy_user").await;
        assert_eq!(conv.entries.len(), 1);
        assert!(conv.summary.is_none());
    }

    #[tokio::test]
    async fn email_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let store = JsonFileStore::new(dir.path().to_path_buf()).await.unwrap();

        store.append("Kieran@Harkin.me", entry("msg1", "resp1")).await.unwrap();

        // Same email, different case — should find the same data
        let conv = store.load("kieran@harkin.me").await;
        assert_eq!(conv.entries.len(), 1);
        assert_eq!(conv.entries[0].user_message, "msg1");

        // Append under lowercase key
        store.append("kieran@harkin.me", entry("msg2", "resp2")).await.unwrap();

        // Check under original case — should see both
        let conv = store.load("Kieran@Harkin.me").await;
        assert_eq!(conv.entries.len(), 2);
    }

    #[test]
    fn normalize_key_works() {
        assert_eq!(normalize_key("kieran@harkin.me"), "kieran_harkin_me");
        assert_eq!(normalize_key("Kieran@Harkin.me"), "kieran_harkin_me");
        assert_eq!(normalize_key("KIERAN@HARKIN.ME"), "kieran_harkin_me");
        assert_eq!(normalize_key("bob"), "bob");
        assert_eq!(normalize_key("user+tag@example.com"), "user_tag_example_com");
    }
}
