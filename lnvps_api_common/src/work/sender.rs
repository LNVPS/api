use crate::{WorkCommander, WorkJob, WorkJobMessage};
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use redis::aio::MultiplexedConnection;
use redis::streams::{
    StreamAddOptions, StreamAutoClaimOptions, StreamAutoClaimReply, StreamId, StreamReadOptions,
    StreamReadReply, StreamTrimStrategy, StreamTrimmingMode,
};
use redis::{AsyncCommands, FromRedisValue};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

#[derive(Clone)]
pub struct RedisWorkCommander {
    redis: redis::Client,
    conn: MultiplexedConnection,
    group_name: String,
    consumer_name: String,
}

impl RedisWorkCommander {
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

    pub async fn listen_for_jobs(&self) -> Result<Vec<WorkJobMessage>> {
        let mut conn = self.conn.clone();

        // Ensure the consumer group exists
        self.ensure_group_exists(&mut conn).await?;

        let pending = self.claim_pending_jobs().await?;
        if !pending.is_empty() {
            info!("Got {} pending jobs", pending.len());
            return Ok(pending);
        }

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
                10_000,
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
            && let Ok(job_str) = String::from_redis_value(job_value.clone())
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
}

#[async_trait]
impl WorkCommander for RedisWorkCommander {
    async fn send(&self, job: WorkJob) -> Result<String> {
        let job_json = serde_json::to_string(&job)?;

        let fields = &[("job", job_json.as_str())];

        let mut conn = self.conn.clone();
        let opts = StreamAddOptions::default()
            .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
        let id: String = conn.xadd_options("worker", "*", fields, &opts).await?;
        Ok(id)
    }

    async fn recv(&self) -> Result<Vec<WorkJobMessage>> {
        self.listen_for_jobs().await
    }

    async fn ack(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: u64 = conn.xack("worker", &self.group_name, &[id]).await?;
        Ok(())
    }
}

pub struct ChannelWorkCommander {
    sender: UnboundedSender<WorkJobMessage>,
    receiver: Mutex<UnboundedReceiver<WorkJobMessage>>,
}

impl Default for ChannelWorkCommander {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelWorkCommander {
    pub fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            sender: tx,
            receiver: Mutex::new(rx),
        }
    }
}

#[async_trait]
impl WorkCommander for ChannelWorkCommander {
    async fn send(&self, job: WorkJob) -> Result<String> {
        let id = Utc::now().timestamp_millis().to_string();
        let msg = WorkJobMessage {
            id: id.clone(),
            job,
            is_pending: false,
        };
        self.sender.send(msg)?;
        Ok(id)
    }

    async fn recv(&self) -> Result<Vec<WorkJobMessage>> {
        let Some(next) = self.receiver.lock().await.recv().await else {
            return Ok(vec![]);
        };
        Ok(vec![next])
    }

    async fn ack(&self, _id: &str) -> Result<()> {
        Ok(())
    }
}
