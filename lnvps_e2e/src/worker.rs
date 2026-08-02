//! Helpers for interacting with the API worker via Redis.
//!
//! The worker consumes jobs from a Redis Stream named `"worker"` using consumer
//! groups.  Tests can publish jobs directly and clear the rate-limit timestamps
//! that the worker uses to avoid running the same check too frequently.

use redis::AsyncCommands;
use redis::streams::{StreamAddOptions, StreamTrimStrategy, StreamTrimmingMode};

/// Redis URL used by the E2E test environment.
/// Reads `LNVPS_REDIS_URL`, falling back to the docker-compose.e2e.yaml default.
pub fn redis_url() -> String {
    std::env::var("LNVPS_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6399".to_string())
}

/// Publish a `WorkJob` to the worker stream.
///
/// The job is serialized as JSON (matching how `RedisWorkCommander::send` works)
/// and added to the `"worker"` stream.  The worker will pick it up on its next
/// poll cycle (~100 ms).
pub async fn publish_job(job_json: &str) -> anyhow::Result<()> {
    publish_job_id(job_json).await.map(|_| ())
}

/// Publish a `WorkJob` and return the stream entry id it was written to.
///
/// The id is what [`wait_for_job_consumed`] waits on, so a test can assert on
/// the *absence* of an effect without guessing how long the worker needs.
pub async fn publish_job_id(job_json: &str) -> anyhow::Result<String> {
    let client = redis::Client::open(redis_url())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let opts = StreamAddOptions::default()
        .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
    let id: String = conn
        .xadd_options("worker", "*", &[("job", job_json)], &opts)
        .await?;
    Ok(id)
}

/// Compare two Redis stream ids (`"<ms>-<seq>"`) numerically.
///
/// A lexical compare is wrong here: `"1785675442124-2"` sorts above
/// `"1785675442124-10"` as text, which would report a job as consumed before
/// it actually was.
fn stream_id_ge(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u64, u64) {
        let (ms, seq) = s.split_once('-').unwrap_or((s, "0"));
        (ms.parse().unwrap_or(0), seq.parse().unwrap_or(0))
    };
    parse(a) >= parse(b)
}

/// Wait until the worker's consumer group has delivered past `id`.
///
/// Tests that assert a job had *no* effect (idempotency, rate-limit skips) have
/// no positive signal to poll for, so they previously slept a blind three
/// seconds. That is both slow and fragile — it is pure guesswork about worker
/// latency, and too short a guess makes the assertion vacuous.
///
/// The consumer group's `last-delivered-id` is an exact record of what the
/// worker has taken off the stream, so this returns as soon as our job has
/// genuinely been picked up (typically within one ~100ms worker cycle).
/// Delivery is not completion, so callers should still allow a short settle
/// before asserting on a negative.
pub async fn wait_for_job_consumed(id: &str, timeout: std::time::Duration) -> anyhow::Result<bool> {
    let client = redis::Client::open(redis_url())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let info: redis::Value = redis::cmd("XINFO")
            .arg("GROUPS")
            .arg("worker")
            .query_async(&mut conn)
            .await?;
        if group_delivered_past(&info, id) {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Whether any consumer group in an `XINFO GROUPS` reply has a
/// `last-delivered-id` at or past `id`.
fn group_delivered_past(info: &redis::Value, id: &str) -> bool {
    fn as_str(v: &redis::Value) -> Option<String> {
        match v {
            redis::Value::BulkString(b) => Some(String::from_utf8_lossy(b).into_owned()),
            redis::Value::SimpleString(s) => Some(s.clone()),
            _ => None,
        }
    }
    let groups = match info {
        redis::Value::Array(g) => g,
        _ => return false,
    };
    groups.iter().any(|g| {
        let fields = match g {
            redis::Value::Array(f) => f,
            redis::Value::Map(m) => {
                return m.iter().any(|(k, v)| {
                    as_str(k).as_deref() == Some("last-delivered-id")
                        && as_str(v).is_some_and(|d| stream_id_ge(&d, id))
                });
            }
            _ => return false,
        };
        fields.chunks(2).any(|kv| {
            kv.len() == 2
                && as_str(&kv[0]).as_deref() == Some("last-delivered-id")
                && as_str(&kv[1]).is_some_and(|d| stream_id_ge(&d, id))
        })
    })
}

/// Publish `CheckVms` to the worker stream.
pub async fn trigger_check_vms() -> anyhow::Result<()> {
    // Clear the rate-limit key first so the worker doesn't skip the job.
    clear_last_check("worker-last-check-vms").await?;
    publish_job("\"CheckVms\"").await
}

/// Publish `CheckSubscriptions` to the worker stream.
pub async fn trigger_check_subscriptions() -> anyhow::Result<()> {
    // Clear the rate-limit key first so the worker doesn't skip the job.
    clear_last_check("worker-last-check-subscriptions").await?;
    publish_job("\"CheckSubscriptions\"").await
}

/// Every job payload currently held in the worker stream.
///
/// Entries survive being consumed (the stream is only trimmed by length), so a
/// test can assert an endpoint dispatched a job without racing the worker.
pub async fn stream_jobs() -> anyhow::Result<Vec<String>> {
    let client = redis::Client::open(redis_url())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let reply: redis::streams::StreamRangeReply = conn.xrange_all("worker").await?;
    Ok(reply
        .ids
        .into_iter()
        .filter_map(|id| id.get::<String>("job"))
        .collect())
}

/// Delete a worker rate-limit key so the next job execution is not skipped.
///
/// The worker stores the last-run timestamp under keys such as
/// `"worker-last-check-vms"` and `"worker-last-check-subscriptions"`.
/// Deleting the key forces the rate-limit guard to consider sufficient
/// time as having passed.
async fn clear_last_check(key: &str) -> anyhow::Result<()> {
    let client = redis::Client::open(redis_url())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let _: u64 = conn.del(key).await?;
    Ok(())
}
