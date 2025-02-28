use anyhow::Result;
use rocket::serde::Deserialize;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum VmRunningState {
    Running,
    #[default]
    Stopped,
    Starting,
    Deleting,
}

#[derive(Clone, Serialize, Deserialize, Default, JsonSchema)]
pub struct VmState {
    pub timestamp: u64,
    pub state: VmRunningState,
    pub cpu_usage: f32,
    pub mem_usage: f32,
    pub uptime: u64,
    pub net_in: u64,
    pub net_out: u64,
    pub disk_write: u64,
    pub disk_read: u64,
}

/// Stores a cached vm status which is used to serve to api clients
#[derive(Clone)]
pub struct VmStateCache {
    state: Arc<RwLock<HashMap<u64, VmState>>>,
}

impl Default for VmStateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl VmStateCache {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_state(&self, id: u64, state: VmState) -> Result<()> {
        let mut guard = self.state.write().await;
        guard.insert(id, state);
        Ok(())
    }

    pub async fn get_state(&self, id: u64) -> Option<VmState> {
        let guard = self.state.read().await;
        guard.get(&id).cloned()
    }
}
