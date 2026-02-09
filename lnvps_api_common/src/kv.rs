use anyhow::Result;
use async_trait::async_trait;
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Simple KV store
#[async_trait]
pub trait KeyValueStore: Send + Sync {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
}

pub struct RedisKeyValueStore {
    conn: MultiplexedConnection,
}

impl RedisKeyValueStore {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        Self::from_client(client).await
    }

    pub async fn from_client(client: redis::Client) -> Result<Self> {
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl KeyValueStore for RedisKeyValueStore {
    /// Generic KV store
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(key, value).await?;
        Ok(())
    }

    /// Generic KV store
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let value = conn.get(key).await?;
        Ok(value)
    }
}

pub struct InMemoryKeyValueStore {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Default for InMemoryKeyValueStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKeyValueStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeyValueStore for InMemoryKeyValueStore {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.data
            .write()
            .await
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.data.read().await.get(key).cloned())
    }
}
