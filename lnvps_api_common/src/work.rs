use crate::model::UpgradeConfig;
use anyhow::Result;
use redis::{
    streams::{StreamReadOptions, StreamReadReply},
    AsyncCommands, FromRedisValue,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WorkJob {
    /// Sync resources from hosts to database
    PatchHosts,
    /// Check all running VMS
    CheckVms,
    /// Check the VM status matches database state
    ///
    /// This job starts a vm if stopped and also creates the vm if it doesn't exist yet
    CheckVm { vm_id: u64 },
    /// Send a notification to the users chosen contact preferences
    SendNotification {
        user_id: u64,
        message: String,
        title: Option<String>,
    },
    /// Delete a VM at admin request
    DeleteVm {
        vm_id: u64,
        reason: Option<String>,
        admin_user_id: Option<u64>,
    },
    /// Start a VM
    StartVm {
        vm_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Stop a VM  
    StopVm {
        vm_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Check all nostr domains DNS records - enable disabled domains with DNS records, disable active domains without DNS records
    CheckNostrDomains,
    /// Process VM upgrade after payment confirmation
    ProcessVmUpgrade { vm_id: u64, config: UpgradeConfig },
    /// Re-configure a VM using current database configuration
    ConfigureVm {
        vm_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Assign an IP to a VM using the provisioner (handles all additional steps)
    AssignVmIp {
        vm_id: u64,
        ip_range_id: u64,
        ip: Option<String>, // If None, auto-assign from range
        admin_user_id: Option<u64>,
    },
    /// Delete/unassign an IP from a VM using the provisioner (handles all cleanup)
    UnassignVmIp {
        assignment_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Update an assignment
    UpdateVmIp {
        assignment_id: u64,
        admin_user_id: Option<u64>,
    },
}

pub struct WorkCommander {
    redis: redis::Client,
    group_name: String,
    consumer_name: String,
}

impl WorkCommander {
    pub fn new(redis_url: &str, group_name: &str, consumer_name: &str) -> Result<Self> {
        let redis = redis::Client::open(redis_url)?;
        Ok(Self {
            redis,
            group_name: group_name.to_string(),
            consumer_name: consumer_name.to_string(),
        })
    }

    pub fn client(&self) -> redis::Client {
        self.redis.clone()
    }

    /// Generic KV store
    pub async fn store_key(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut conn = self.client().get_multiplexed_async_connection().await?;
        conn.set::<_, _, ()>(key, value).await?;
        Ok(())
    }

    /// Generic KV store
    pub async fn get_key(&self, key: &str) -> Result<Vec<u8>> {
        let mut conn = self.client().get_multiplexed_async_connection().await?;
        let value = conn.get(key).await?;
        Ok(value)
    }

    pub fn new_publisher(redis_url: &str) -> Result<Self> {
        let redis = redis::Client::open(redis_url)?;
        Ok(Self {
            redis,
            group_name: String::new(),
            consumer_name: String::new(),
        })
    }

    pub async fn ensure_group_exists(&self) -> Result<()> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        // Try to create the group with MKSTREAM option, ignore error if it already exists
        let _: Result<String, _> = conn
            .xgroup_create_mkstream("worker", &self.group_name, "$")
            .await;
        Ok(())
    }

    pub async fn send_job(&self, job: WorkJob) -> Result<String> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let job_json = serde_json::to_string(&job)?;

        let fields = &[("job", job_json.as_str())];

        let stream_id: String = conn.xadd("worker", "*", fields).await?;
        Ok(stream_id)
    }

    pub async fn listen_for_jobs(&self) -> Result<Vec<(String, WorkJob)>> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        // Ensure the consumer group exists
        self.ensure_group_exists().await?;

        let opts = StreamReadOptions::default()
            .count(10)
            .block(1000)
            .group(&self.group_name, &self.consumer_name);

        let results: StreamReadReply = conn.xread_options(&["worker"], &[">"], &opts).await?;

        let mut jobs = Vec::new();

        for stream_key in results.keys {
            for stream_id in stream_key.ids {
                if let Some(job_value) = stream_id.map.get("job") {
                    if let Ok(job_str) = String::from_redis_value(job_value) {
                        match serde_json::from_str::<WorkJob>(&job_str) {
                            Ok(job) => {
                                jobs.push((stream_id.id.clone(), job));
                            }
                            Err(e) => {
                                log::warn!("Failed to deserialize job from stream: {}", e);
                            }
                        }
                    }
                }
            }
        }

        Ok(jobs)
    }

    pub async fn acknowledge_job(&self, stream_id: &str) -> Result<()> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let _: u64 = conn.xack("worker", &self.group_name, &[stream_id]).await?;
        Ok(())
    }
}
