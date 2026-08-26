use crate::{WorkCommander, WorkJob, WorkJobMessage};
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use log::{error, info, warn};
use redis::aio::MultiplexedConnection;
use redis::streams::{
    StreamAddOptions, StreamId, StreamReadOptions, StreamReadReply, StreamTrimStrategy,
    StreamTrimmingMode,
};
use redis::streams::{StreamClaimReply, StreamPendingCountReply, StreamRangeReply};
use redis::{AsyncCommands, FromRedisValue};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Default stream: the general worker queue the API's worker process consumes.
pub const DEFAULT_WORK_STREAM: &str = "worker";

/// How a failing job is redelivered.
///
/// A job that errors is left unacked, so it stays in the consumer group's
/// pending list and is reclaimed on a later poll. Without a policy that is a
/// fixed ~10s loop forever: a job that can never succeed (a deleted host, an
/// address another VM holds) re-ran every few seconds indefinitely, filling the
/// logs and, for jobs that build state on a host, doing real work each time.
#[derive(Debug, Clone)]
pub struct JobRetryPolicy {
    /// Delay before the first retry. Doubles per attempt.
    pub base_delay: Duration,
    /// Ceiling for the doubling, so a long-broken job still retries hourly-ish
    /// rather than drifting to never.
    pub max_delay: Duration,
    /// Deliveries after which the job is dead-lettered instead of retried.
    pub max_attempts: usize,
}

impl Default for JobRetryPolicy {
    fn default() -> Self {
        Self {
            // The first retry keeps the old 10s behaviour, which is short
            // enough to ride out a host reboot or a brief API outage.
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(15 * 60),
            // 10s, 20s, 40s ... capped at 15m — roughly an hour of retries
            // before giving up.
            max_attempts: 8,
        }
    }
}

/// What to do with one entry in the consumer group's pending list.
#[derive(Debug, PartialEq, Eq)]
pub enum PendingAction {
    /// Still inside the backoff window (or in flight on another consumer).
    Wait,
    /// Backoff elapsed — claim it and run it again.
    Claim,
    /// Out of attempts; move it to the dead-letter stream and ack it.
    DeadLetter,
}

/// Delay required before delivery number `attempt` may be retried.
///
/// `attempt` is Redis' `times_delivered`, which is 1 after the first delivery,
/// so the first retry waits `base_delay`.
pub fn retry_delay(policy: &JobRetryPolicy, attempt: usize) -> Duration {
    let exp = attempt.saturating_sub(1).min(32) as u32;
    policy
        .base_delay
        .saturating_mul(2u32.saturating_pow(exp))
        .min(policy.max_delay)
}

/// Decide what to do with a pending entry delivered `attempt` times and idle
/// for `idle`.
///
/// Idle time is the guard against stealing a job that is still running on
/// another consumer: an entry is only ever claimed once it has been silent for
/// at least the backoff window.
pub fn pending_action(policy: &JobRetryPolicy, attempt: usize, idle: Duration) -> PendingAction {
    if attempt > policy.max_attempts {
        // Only give up once the job is actually idle — a long-running attempt
        // that has not reported back yet is not a failure.
        return if idle >= retry_delay(policy, attempt) {
            PendingAction::DeadLetter
        } else {
            PendingAction::Wait
        };
    }
    if idle >= retry_delay(policy, attempt) {
        PendingAction::Claim
    } else {
        PendingAction::Wait
    }
}

#[derive(Clone)]
pub struct RedisWorkCommander {
    redis: redis::Client,
    conn: MultiplexedConnection,
    group_name: String,
    consumer_name: String,
    /// Stream this commander reads from, and writes to unless
    /// [`WorkCommander::send_to_stream`] names another.
    stream: String,
    retry: JobRetryPolicy,
}

impl RedisWorkCommander {
    pub async fn new(redis_url: &str, group_name: &str, consumer_name: &str) -> Result<Self> {
        Self::new_for_stream(redis_url, DEFAULT_WORK_STREAM, group_name, consumer_name).await
    }

    /// A commander bound to a named stream — the operator's per-cluster
    /// reconcile queue (issue #254), where the stream name is the routing.
    pub async fn new_for_stream(
        redis_url: &str,
        stream: &str,
        group_name: &str,
        consumer_name: &str,
    ) -> Result<Self> {
        let redis = redis::Client::open(redis_url)?;
        let conn = redis.get_multiplexed_async_connection().await?;
        Ok(Self {
            conn,
            redis,
            group_name: group_name.to_string(),
            consumer_name: consumer_name.to_string(),
            stream: stream.to_string(),
            retry: JobRetryPolicy::default(),
        })
    }

    /// Override the redelivery policy (see [`JobRetryPolicy`]).
    pub fn with_retry_policy(mut self, retry: JobRetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Stream failed jobs are parked on once they run out of attempts.
    pub fn dead_letter_stream(&self) -> String {
        format!("{}:dead", self.stream)
    }

    /// Hash holding the last error per pending message, so a dead-lettered job
    /// carries the reason it failed rather than just an id.
    fn error_key(&self) -> String {
        format!("{}:errors", self.stream)
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
            stream: DEFAULT_WORK_STREAM.to_string(),
            // A publisher never consumes, so the policy is never consulted.
            retry: JobRetryPolicy::default(),
        })
    }

    pub async fn ensure_group_exists(&self, conn: &mut MultiplexedConnection) -> Result<()> {
        // Try to create the group with MKSTREAM option, ignore error if it already exists
        let _: Result<String, _> = conn
            .xgroup_create_mkstream(&self.stream, &self.group_name, "$")
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

        let results: StreamReadReply = conn
            .xread_options(&[self.stream.as_str()], &[">"], &opts)
            .await?;
        let mut jobs = Vec::new();
        for stream_key in results.keys {
            jobs.extend(stream_key.ids.iter().filter_map(Self::map_work_job));
        }
        Ok(jobs)
    }

    /// Check for pending jobs in the consumer group and claim the ones whose
    /// backoff has elapsed.
    ///
    /// Redis tracks a delivery count per pending message, which is the retry
    /// count for a job that keeps failing: it spaces redeliveries exponentially
    /// and gives up entirely once [`JobRetryPolicy::max_attempts`] is exceeded.
    /// Entries still inside their backoff window are left alone, which is also
    /// what stops a job that is merely slow from being stolen from the consumer
    /// currently running it.
    pub async fn claim_pending_jobs(&self) -> Result<Vec<WorkJobMessage>> {
        let mut conn = self.conn.clone();

        let pending: StreamPendingCountReply = conn
            .xpending_count(self.stream.as_str(), &self.group_name, "-", "+", 100usize)
            .await?;

        let mut claim_ids = Vec::new();
        for entry in &pending.ids {
            let idle = Duration::from_millis(entry.last_delivered_ms as u64);
            match pending_action(&self.retry, entry.times_delivered, idle) {
                PendingAction::Wait => {}
                PendingAction::Claim => claim_ids.push(entry.id.clone()),
                PendingAction::DeadLetter => {
                    if let Err(e) = self.dead_letter(&entry.id, entry.times_delivered).await {
                        // Leave it pending rather than dropping it: a failure to
                        // park the job must not also lose it.
                        warn!("Failed to dead-letter job {}: {}", entry.id, e);
                    }
                }
            }
        }

        if claim_ids.is_empty() {
            return Ok(vec![]);
        }

        // min_idle_time 0: the backoff check above already decided these are
        // eligible, and re-checking against a single idle threshold here would
        // undo the per-attempt spacing.
        let claimed: StreamClaimReply = conn
            .xclaim(
                self.stream.as_str(),
                &self.group_name,
                &self.consumer_name,
                0usize,
                &claim_ids,
            )
            .await?;

        Ok(claimed
            .ids
            .iter()
            .filter_map(|j| {
                Self::map_work_job(j).map(|mut x| {
                    x.is_pending = true;
                    x
                })
            })
            .collect())
    }

    /// Park a job that has exhausted its attempts on the dead-letter stream and
    /// ack it, so the worker stops re-running something that cannot succeed.
    ///
    /// The entry keeps the original payload plus the attempt count and the last
    /// error, so it can be inspected and replayed by hand.
    async fn dead_letter(&self, id: &str, attempts: usize) -> Result<()> {
        let mut conn = self.conn.clone();

        let original: StreamRangeReply = conn.xrange_count(self.stream.as_str(), id, id, 1).await?;
        let job_json = original
            .ids
            .first()
            .and_then(|e| e.map.get("job").cloned())
            .and_then(|v| String::from_redis_value(v).ok())
            .unwrap_or_default();

        let last_error: Option<String> = conn.hget(self.error_key(), id).await.unwrap_or(None);
        let last_error = last_error.unwrap_or_else(|| "unknown".to_string());

        error!(
            "Giving up on job {} after {} attempts, moving to {}: {} ({})",
            id,
            attempts,
            self.dead_letter_stream(),
            job_json,
            last_error
        );

        let attempts = attempts.to_string();
        let failed_at = Utc::now().to_rfc3339();
        let fields = &[
            ("job", job_json.as_str()),
            ("original_id", id),
            ("attempts", attempts.as_str()),
            ("error", last_error.as_str()),
            ("failed_at", failed_at.as_str()),
        ];
        let opts = StreamAddOptions::default()
            .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
        let _: String = conn
            .xadd_options(self.dead_letter_stream(), "*", fields, &opts)
            .await?;

        // Only ack once the job is safely parked.
        let _: u64 = conn
            .xack(self.stream.as_str(), &self.group_name, &[id])
            .await?;
        let _: u64 = conn.hdel(self.error_key(), id).await.unwrap_or(0);
        Ok(())
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
    async fn send_to_stream(&self, stream: &str, job: WorkJob) -> Result<String> {
        let job_json = serde_json::to_string(&job)?;
        let fields = &[("job", job_json.as_str())];
        let mut conn = self.conn.clone();
        let opts = StreamAddOptions::default()
            .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
        let id: String = conn.xadd_options(stream, "*", fields, &opts).await?;
        Ok(id)
    }

    async fn send(&self, job: WorkJob) -> Result<String> {
        let job_json = serde_json::to_string(&job)?;

        let fields = &[("job", job_json.as_str())];

        let mut conn = self.conn.clone();
        let opts = StreamAddOptions::default()
            .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
        let id: String = conn
            .xadd_options(self.stream.as_str(), "*", fields, &opts)
            .await?;
        Ok(id)
    }

    async fn recv(&self) -> Result<Vec<WorkJobMessage>> {
        self.listen_for_jobs().await
    }

    async fn ack(&self, id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: u64 = conn
            .xack(self.stream.as_str(), &self.group_name, &[id])
            .await?;
        // A succeeded job keeps no failure history.
        let _: u64 = conn.hdel(self.error_key(), id).await.unwrap_or(0);
        Ok(())
    }

    async fn record_failure(&self, id: &str, error: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: u64 = conn.hset(self.error_key(), id, error).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> JobRetryPolicy {
        JobRetryPolicy {
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(900),
            max_attempts: 8,
        }
    }

    #[test]
    fn test_retry_delay_doubles_then_caps() {
        let p = policy();
        // times_delivered is 1 after the first delivery, so the first retry
        // waits exactly base_delay.
        assert_eq!(retry_delay(&p, 1), Duration::from_secs(10));
        assert_eq!(retry_delay(&p, 2), Duration::from_secs(20));
        assert_eq!(retry_delay(&p, 3), Duration::from_secs(40));
        assert_eq!(retry_delay(&p, 7), Duration::from_secs(640));
        // Capped, and no overflow panic for absurd delivery counts.
        assert_eq!(retry_delay(&p, 8), p.max_delay);
        assert_eq!(retry_delay(&p, 500), p.max_delay);
    }

    #[test]
    fn test_pending_action_waits_inside_the_backoff_window() {
        let p = policy();
        // A job delivered once 3s ago is most likely still running.
        assert_eq!(
            pending_action(&p, 1, Duration::from_secs(3)),
            PendingAction::Wait
        );
        assert_eq!(
            pending_action(&p, 1, Duration::from_secs(10)),
            PendingAction::Claim
        );
        // The third delivery must wait 40s, not 10s.
        assert_eq!(
            pending_action(&p, 3, Duration::from_secs(20)),
            PendingAction::Wait
        );
        assert_eq!(
            pending_action(&p, 3, Duration::from_secs(40)),
            PendingAction::Claim
        );
    }

    #[test]
    fn test_pending_action_gives_up_after_max_attempts() {
        let p = policy();
        assert_eq!(
            pending_action(&p, p.max_attempts, Duration::from_secs(3600)),
            PendingAction::Claim,
            "the last allowed attempt still runs"
        );
        assert_eq!(
            pending_action(&p, p.max_attempts + 1, Duration::from_secs(3600)),
            PendingAction::DeadLetter
        );
        // Out of attempts but recently delivered: the attempt may still be in
        // flight, so don't rip it out from under the consumer running it.
        assert_eq!(
            pending_action(&p, p.max_attempts + 1, Duration::from_secs(5)),
            PendingAction::Wait
        );
    }
}
