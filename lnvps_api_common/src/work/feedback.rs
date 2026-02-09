use anyhow::{Result, bail};
use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use futures::stream;
use futures::stream::BoxStream;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, Value};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generic job feedback handler
#[async_trait]
pub trait WorkFeedback: Send + Sync {
    async fn publish(&self, feedback: JobFeedback) -> Result<()>;
    async fn subscribe(&self, channel: &str) -> Result<BoxStream<Result<JobFeedback>>>;
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

    /// Create a job feedback with started status
    pub fn create_job_started_feedback(job_id: String, job_type: String) -> Self {
        Self::new(job_id, job_type, JobFeedbackStatus::Started)
    }

    /// Create a job feedback with progress status
    pub fn create_job_progress_feedback(
        job_id: String,
        job_type: String,
        percent: u8,
        message: Option<String>,
    ) -> Self {
        Self::new(
            job_id,
            job_type,
            JobFeedbackStatus::Progress { percent, message },
        )
    }

    /// Create a job feedback with completed status
    pub fn create_job_completed_feedback(
        job_id: String,
        job_type: String,
        result: Option<String>,
    ) -> Self {
        Self::new(job_id, job_type, JobFeedbackStatus::Completed { result })
    }

    /// Create a job feedback with failed status
    pub fn create_job_failed_feedback(job_id: String, job_type: String, error: String) -> Self {
        Self::new(job_id, job_type, JobFeedbackStatus::Failed { error })
    }

    /// Create a job feedback with cancelled status
    pub fn create_job_cancelled_feedback(
        job_id: String,
        job_type: String,
        reason: Option<String>,
    ) -> Self {
        Self::new(job_id, job_type, JobFeedbackStatus::Cancelled { reason })
    }
}

#[derive(Clone, Debug)]
pub struct RedisWorkFeedback {
    redis: redis::Client,
    conn: MultiplexedConnection,
}

impl RedisWorkFeedback {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let redis = redis::Client::open(redis_url)?;
        Self::new_from_client(redis).await
    }

    pub async fn new_from_client(client: redis::Client) -> Result<Self> {
        // get a reusable connection object
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self {
            conn,
            redis: client,
        })
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
}

#[async_trait]
impl WorkFeedback for RedisWorkFeedback {
    async fn publish(&self, feedback: JobFeedback) -> Result<()> {
        self.publish_feedback(&feedback).await
    }

    async fn subscribe(&self, channel: &str) -> Result<BoxStream<Result<JobFeedback>>> {
        let mut ps = self.redis.get_async_pubsub().await?;
        ps.subscribe(channel.to_string()).await?;

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
            .map(|t| map_json_into_t(t.get_payload()?))
            .boxed())
    }
}

/// Work feedback is not sent anywhere
pub struct BlackholeWorkFeedback;

#[async_trait]
impl WorkFeedback for BlackholeWorkFeedback {
    async fn publish(&self, _feedback: JobFeedback) -> Result<()> {
        Ok(())
    }

    async fn subscribe(&self, _channel: &str) -> Result<BoxStream<Result<JobFeedback>>> {
        Ok(stream::empty().boxed())
    }
}
