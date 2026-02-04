use crate::model::UpgradeConfig;
use anyhow::{Result, bail};
use chrono::Utc;
use futures::{Stream, StreamExt};
use log::info;
use redis::aio::MultiplexedConnection;
use redis::streams::{
    StreamAddOptions, StreamAutoClaimOptions, StreamAutoClaimReply, StreamId, StreamTrimStrategy,
    StreamTrimmingMode,
};
use redis::{
    AsyncCommands, FromRedisValue, Value,
    streams::{StreamReadOptions, StreamReadReply},
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tokio::sync::mpsc::UnboundedSender;

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
    /// Send a notification to all admin users
    /// This job looks up all admin users in the database and creates individual SendNotification jobs for each
    SendAdminNotification {
        message: String,
        title: Option<String>,
    },
    /// Send bulk message to all active customers based on their contact preferences
    BulkMessage {
        subject: String,
        message: String,
        admin_user_id: u64,
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
    /// Process a refund for a VM automatically
    ProcessVmRefund {
        vm_id: u64,
        admin_user_id: u64,
        refund_from_date: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<String>,
        payment_method: String,            // "lightning", "revolut", "paypal"
        lightning_invoice: Option<String>, // Required when payment_method is "lightning"
    },
    /// Create a VM for a specific user (admin action)
    CreateVm {
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
        ref_code: Option<String>,
        admin_user_id: u64,
        reason: Option<String>,
    },
}

impl WorkJob {
    /// If this job can be skipped on failure
    pub fn can_skip(&self) -> bool {
        match self {
            Self::CheckNostrDomains { .. } => true,
            Self::StopVm { .. } => true,
            Self::StartVm { .. } => true,
            Self::CheckVm { .. } => true,
            Self::CheckVms => true,
            _ => false,
        }
    }
}

impl fmt::Display for WorkJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkJob::PatchHosts => write!(f, "PatchHosts"),
            WorkJob::CheckVms => write!(f, "CheckVms"),
            WorkJob::CheckVm { .. } => write!(f, "CheckVm"),
            WorkJob::SendNotification { .. } => write!(f, "SendNotification"),
            WorkJob::SendAdminNotification { .. } => write!(f, "SendAdminNotification"),
            WorkJob::BulkMessage { .. } => write!(f, "BulkMessage"),
            WorkJob::DeleteVm { .. } => write!(f, "DeleteVm"),
            WorkJob::StartVm { .. } => write!(f, "StartVm"),
            WorkJob::StopVm { .. } => write!(f, "StopVm"),
            WorkJob::CheckNostrDomains => write!(f, "CheckNostrDomains"),
            WorkJob::ProcessVmUpgrade { .. } => write!(f, "ProcessVmUpgrade"),
            WorkJob::ConfigureVm { .. } => write!(f, "ConfigureVm"),
            WorkJob::AssignVmIp { .. } => write!(f, "AssignVmIp"),
            WorkJob::UnassignVmIp { .. } => write!(f, "UnassignVmIp"),
            WorkJob::UpdateVmIp { .. } => write!(f, "UpdateVmIp"),
            WorkJob::ProcessVmRefund { .. } => write!(f, "ProcessVmRefund"),
            WorkJob::CreateVm { .. } => write!(f, "CreateVm"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkJobMessage {
    pub id: String,
    pub job: WorkJob,
    pub is_pending: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum JobFeedbackStatus {
    Started,
    Progress {
        percent: u8,
        message: Option<String>,
    },
    Completed {
        result: Option<String>,
    },
    Failed {
        error: String,
    },
    Cancelled {
        reason: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobFeedback {
    pub job_id: String,
    pub job_type: String,
    pub status: JobFeedbackStatus,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
}

impl JobFeedback {
    pub fn new(job_id: String, job_type: String, status: JobFeedbackStatus) -> Self {
        Self {
            job_id,
            job_type,
            status,
            timestamp: Utc::now().timestamp() as _,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn channel_name(job_id: &str) -> String {
        format!("worker:feedback:{}", job_id)
    }

    pub fn global_channel_name() -> String {
        "worker:feedback".to_string()
    }
}

#[derive(Clone)]
pub struct WorkCommander {
    redis: redis::Client,
    conn: MultiplexedConnection,
    group_name: String,
    consumer_name: String,
}

impl WorkCommander {
    pub async fn new(redis_url: &str, group_name: &str, consumer_name: &str) -> Result<Self> {
        let redis = redis::Client::open(redis_url)?;
        let conn = redis.get_multiplexed_async_connection().await?;
        Ok(Self {
            conn,
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
        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(key, value).await?;
        Ok(())
    }

    /// Generic KV store
    pub async fn get_key(&self, key: &str) -> Result<Vec<u8>> {
        let mut conn = self.conn.clone();
        let value = conn.get(key).await?;
        Ok(value)
    }

    pub async fn new_publisher(redis_url: &str) -> Result<Self> {
        let redis = redis::Client::open(redis_url)?;
        let conn = redis.get_multiplexed_async_connection().await?;
        Ok(Self {
            conn,
            redis,
            group_name: String::new(),
            consumer_name: String::new(),
        })
    }

    pub async fn ensure_group_exists(&self, conn: &mut MultiplexedConnection) -> Result<()> {
        // Try to create the group with MKSTREAM option, ignore error if it already exists
        let _: Result<String, _> = conn
            .xgroup_create_mkstream("worker", &self.group_name, "$")
            .await;
        Ok(())
    }

    pub async fn send_job(&self, job: WorkJob) -> Result<String> {
        let job_json = serde_json::to_string(&job)?;

        let fields = &[("job", job_json.as_str())];

        let mut conn = self.conn.clone();
        let opts = StreamAddOptions::default()
            .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
        let stream_id: String = conn.xadd_options("worker", "*", fields, &opts).await?;
        Ok(stream_id)
    }

    pub async fn listen_for_jobs(&self) -> Result<Vec<WorkJobMessage>> {
        let mut conn = self.conn.clone();

        let pending = self.claim_pending_jobs().await?;
        if !pending.is_empty() {
            info!("Got {} pending jobs", pending.len());
            return Ok(pending);
        }

        // Ensure the consumer group exists
        self.ensure_group_exists(&mut conn).await?;
        let opts = StreamReadOptions::default()
            .count(10)
            .block(100)
            .group(&self.group_name, &self.consumer_name);

        let results: StreamReadReply = conn.xread_options(&["worker"], &[">"], &opts).await?;
        let mut jobs = Vec::new();
        for stream_key in results.keys {
            jobs.extend(stream_key.ids.iter().filter_map(Self::map_work_job));
        }
        Ok(jobs)
    }

    /// Check for pending jobs in the consumer group and claim old ones
    pub async fn claim_pending_jobs(&self) -> Result<Vec<WorkJobMessage>> {
        let mut conn = self.conn.clone();

        let opts = StreamAutoClaimOptions::default();

        // Parse pending messages and claim them
        let jobs: StreamAutoClaimReply = conn
            .xautoclaim_options(
                "worker",
                &self.group_name,
                &self.consumer_name,
                10,
                "0-0",
                opts,
            )
            .await?;
        Ok(jobs
            .claimed
            .iter()
            .filter_map(|j| {
                Self::map_work_job(j).map(|mut x| {
                    x.is_pending = true;
                    x
                })
            })
            .collect())
    }

    fn map_work_job(stream_id: &StreamId) -> Option<WorkJobMessage> {
        if let Some(job_value) = stream_id.map.get("job")
            && let Ok(job_str) = String::from_redis_value(job_value)
        {
            match serde_json::from_str::<WorkJob>(&job_str) {
                Ok(job) => {
                    return Some(WorkJobMessage {
                        id: stream_id.id.to_string(),
                        job,
                        is_pending: false,
                    });
                }
                Err(e) => {
                    log::warn!("Failed to deserialize job from stream: {}", e);
                }
            }
        }
        None
    }

    pub async fn acknowledge_job(&self, job: &WorkJobMessage) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: u64 = conn.xack("worker", &self.group_name, &[&job.id]).await?;
        Ok(())
    }

    /// Publish job feedback to Redis pub/sub
    pub async fn publish_feedback(&self, feedback: &JobFeedback) -> Result<()> {
        let mut conn = self.conn.clone();
        let feedback_json = serde_json::to_string(feedback)?;

        // Publish to specific job channel
        let _: u64 = conn
            .publish(JobFeedback::channel_name(&feedback.job_id), &feedback_json)
            .await?;

        // Also publish to global feedback channel for monitoring
        let _: u64 = conn
            .publish(JobFeedback::global_channel_name(), &feedback_json)
            .await?;

        Ok(())
    }

    // Create a pub/sub receiver that receives JSON serialized objects
    pub async fn subscribe_channel_message<T: DeserializeOwned + Send + 'static>(
        &self,
        channel: &str,
    ) -> Result<impl Stream<Item = Result<T>>> {
        let mut ps = self.redis.get_async_pubsub().await?;
        ps.subscribe(channel).await?;

        fn map_json_into_t<T: DeserializeOwned + Send + 'static>(msg: Value) -> Result<T> {
            let body = match &msg {
                Value::BulkString(str) => str.as_slice(),
                Value::SimpleString(str) => str.as_bytes(),
                _ => bail!("Unknown message type"),
            };
            match serde_json::from_slice(body) {
                Ok(t) => Ok(t),
                Err(e) => {
                    bail!(
                        "Failed to parse job feedback: {} {}",
                        str::from_utf8(body).unwrap_or("<INVALID UTF-8 DATA>"),
                        e
                    );
                }
            }
        }

        Ok(ps
            .into_on_message()
            .map(|t| map_json_into_t(t.get_payload()?)))
    }

    /// Create a job feedback with started status
    pub fn create_job_started_feedback(&self, job_id: String, job_type: String) -> JobFeedback {
        JobFeedback::new(job_id, job_type, JobFeedbackStatus::Started)
    }

    /// Create a job feedback with progress status
    pub fn create_job_progress_feedback(
        &self,
        job_id: String,
        job_type: String,
        percent: u8,
        message: Option<String>,
    ) -> JobFeedback {
        JobFeedback::new(
            job_id,
            job_type,
            JobFeedbackStatus::Progress { percent, message },
        )
    }

    /// Create a job feedback with completed status
    pub fn create_job_completed_feedback(
        &self,
        job_id: String,
        job_type: String,
        result: Option<String>,
    ) -> JobFeedback {
        JobFeedback::new(job_id, job_type, JobFeedbackStatus::Completed { result })
    }

    /// Create a job feedback with failed status
    pub fn create_job_failed_feedback(
        &self,
        job_id: String,
        job_type: String,
        error: String,
    ) -> JobFeedback {
        JobFeedback::new(job_id, job_type, JobFeedbackStatus::Failed { error })
    }

    /// Create a job feedback with cancelled status
    pub fn create_job_cancelled_feedback(
        &self,
        job_id: String,
        job_type: String,
        reason: Option<String>,
    ) -> JobFeedback {
        JobFeedback::new(job_id, job_type, JobFeedbackStatus::Cancelled { reason })
    }
}

#[derive(Clone)]
pub struct WorkSender {
    sender: UnboundedSender<WorkJob>,
}

impl WorkSender {
    pub fn new(sender: UnboundedSender<WorkJob>) -> Self {
        Self { sender }
    }

    pub fn send(&self, job: WorkJob) -> Result<()> {
        self.sender.send(job)?;
        Ok(())
    }
}
