use anyhow::Result;
use redis::AsyncCommands;
use rocket::serde::Deserialize;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize, Default, JsonSchema, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum VmRunningStates {
    Running,
    #[default]
    Stopped,
    Starting,
    Deleting,
}

#[derive(Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct VmRunningState {
    pub timestamp: u64,
    pub state: VmRunningStates,
    pub cpu_usage: f32,
    pub mem_usage: f32,
    pub uptime: u64,
    pub net_in: u64,
    pub net_out: u64,
    pub disk_write: u64,
    pub disk_read: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub ttl: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            ttl: 300, // 5 minutes
        }
    }
}

#[async_trait::async_trait]
pub trait VmStateCacheBackend: Send + Sync {
    async fn set_state(&self, id: u64, state: VmRunningState) -> Result<()>;
    async fn get_state(&self, id: u64) -> Result<Option<VmRunningState>>;
}

/// Local in-memory cache backend
#[derive(Clone)]
pub struct LocalVmStateCache {
    state: Arc<RwLock<HashMap<u64, VmRunningState>>>,
}

impl LocalVmStateCache {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl VmStateCacheBackend for LocalVmStateCache {
    async fn set_state(&self, id: u64, state: VmRunningState) -> Result<()> {
        let mut guard = self.state.write().await;
        guard.insert(id, state);
        Ok(())
    }

    async fn get_state(&self, id: u64) -> Result<Option<VmRunningState>> {
        let guard = self.state.read().await;
        Ok(guard.get(&id).cloned())
    }
}

/// Redis-backed cache backend
#[derive(Clone)]
pub struct RedisVmStateCache {
    client: Arc<redis::Client>,
    ttl: Duration,
}

impl RedisVmStateCache {
    pub fn new(config: RedisConfig) -> Result<Self> {
        let client = redis::Client::open(config.url)?;
        Ok(Self {
            client: Arc::new(client),
            ttl: Duration::from_secs(config.ttl),
        })
    }

    fn vm_key(&self, id: u64) -> String {
        format!("vm_state:{}", id)
    }
}

#[async_trait::async_trait]
impl VmStateCacheBackend for RedisVmStateCache {
    async fn set_state(&self, id: u64, state: VmRunningState) -> Result<()> {
        let key = self.vm_key(id);
        let serialized = serde_json::to_string(&state)?;

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.set_ex(&key, &serialized, self.ttl.as_secs()).await?;
        Ok(())
    }

    async fn get_state(&self, id: u64) -> Result<Option<VmRunningState>> {
        let key = self.vm_key(id);

        let mut conn = self.client.get_multiplexed_async_connection().await?;
        match conn.get::<_, Option<String>>(&key).await? {
            Some(serialized) => {
                let state = serde_json::from_str::<VmRunningState>(&serialized)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }
}

/// Main VM state cache that wraps different backends
#[derive(Clone)]
pub struct VmStateCache {
    backend: Arc<dyn VmStateCacheBackend>,
}

impl VmStateCache {
    pub fn new() -> Self {
        Self {
            backend: Arc::new(LocalVmStateCache::new()),
        }
    }

    pub fn new_with_redis(config: RedisConfig) -> Result<Self> {
        Ok(Self {
            backend: Arc::new(RedisVmStateCache::new(config)?),
        })
    }

    pub fn new_with_backend(backend: Arc<dyn VmStateCacheBackend>) -> Self {
        Self { backend }
    }

    pub async fn set_state(&self, id: u64, state: VmRunningState) -> Result<()> {
        self.backend.set_state(id, state).await
    }

    pub async fn get_state(&self, id: u64) -> Option<VmRunningState> {
        match self.backend.get_state(id).await {
            Ok(state) => state,
            Err(e) => {
                log::error!("Failed to get VM state for VM {}: {}", id, e);
                None
            }
        }
    }
}

impl Default for VmStateCache {
    fn default() -> Self {
        Self::new()
    }
}
