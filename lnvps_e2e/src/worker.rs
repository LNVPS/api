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
    let client = redis::Client::open(redis_url())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    let opts = StreamAddOptions::default()
        .trim(StreamTrimStrategy::maxlen(StreamTrimmingMode::Approx, 1000));
    let _id: String = conn
        .xadd_options("worker", "*", &[("job", job_json)], &opts)
        .await?;
    Ok(())
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
