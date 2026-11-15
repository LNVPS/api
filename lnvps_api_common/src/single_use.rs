//! A bounded, time-windowed "have I seen this before?" set.
//!
//! Used to make one-shot credentials actually one-shot: NIP-98 auth events and
//! WebAuthn challenge tokens are both stateless (nothing server-side records
//! that they were used), so without this a captured credential can be replayed
//! for as long as its validity window lasts.
//!
//! Per-process, like the rate limiter: not exact across replicas, but every
//! replica enforces it independently, which removes the trivial "capture and
//! resubmit" path. Entries are dropped once they age past the window, because a
//! credential that old fails its own expiry check anyway.

use anyhow::{Result, bail};
use log::warn;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[async_trait::async_trait]
pub trait SharedSeenSet: Send + Sync {
    async fn first_use(&self, key: &str, ttl: Duration) -> Result<bool>;
}

#[derive(Default)]
pub struct MemorySeenSet {
    seen: Mutex<HashMap<String, Instant>>,
}

#[async_trait::async_trait]
impl SharedSeenSet for MemorySeenSet {
    async fn first_use(&self, key: &str, ttl: Duration) -> Result<bool> {
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, at| now.duration_since(*at) < ttl);
        Ok(seen.insert(key.to_string(), now).is_none())
    }
}

pub struct RedisSeenSet {
    conn: redis::aio::ConnectionManager,
}

impl RedisSeenSet {
    pub async fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            conn: redis::aio::ConnectionManager::new(client).await?,
        })
    }
}

#[async_trait::async_trait]
impl SharedSeenSet for RedisSeenSet {
    async fn first_use(&self, key: &str, ttl: Duration) -> Result<bool> {
        let mut conn = self.conn.clone();
        let reply: Option<String> = redis::cmd("SET")
            .arg(format!("seen:{key}"))
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .query_async(&mut conn)
            .await?;
        Ok(reply.is_some())
    }
}

static SHARED_SEEN_SET: OnceLock<Arc<dyn SharedSeenSet>> = OnceLock::new();

pub fn install_shared_seen_set(set: Arc<dyn SharedSeenSet>) -> bool {
    SHARED_SEEN_SET.set(set).is_ok()
}

pub async fn consume_shared(
    set: Option<&Arc<dyn SharedSeenSet>>,
    label: &str,
    key: &str,
    ttl: Duration,
) -> Result<()> {
    let Some(set) = set else { return Ok(()) };
    match set.first_use(&format!("{label}:{key}"), ttl).await {
        Ok(true) => Ok(()),
        Ok(false) => bail!("Credential has already been used"),
        Err(e) => {
            warn!("shared {label} set unavailable, using the local set only: {e}");
            Ok(())
        }
    }
}

pub async fn consume_installed(label: &str, key: &str, ttl: Duration) -> Result<()> {
    consume_shared(SHARED_SEEN_SET.get(), label, key, ttl).await
}

/// Tracks recently-used credential identifiers.
pub struct SingleUseGuard<K> {
    seen: Mutex<HashMap<K, Instant>>,
    /// How long an entry is remembered.
    window: Duration,
    /// Hard cap on tracked entries, so a flood cannot grow the map unbounded.
    capacity: usize,
    /// Name used in log messages.
    label: &'static str,
}

impl<K: Eq + Hash> SingleUseGuard<K> {
    /// Create a guard remembering entries for `window`, holding at most
    /// `capacity` of them.
    pub fn new(label: &'static str, window: Duration, capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            window,
            capacity,
            label,
        }
    }

    /// Record `key` as used. Fails if it was already used inside the window.
    ///
    /// Callers must only reach this **after** every other validity check has
    /// passed, so an invalid credential cannot burn a legitimate one's id.
    pub fn consume(&self, key: K) -> Result<()> {
        let now = Instant::now();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        seen.retain(|_, used_at| now.duration_since(*used_at) < self.window);

        // If ageing out was not enough we are under an active flood. Clearing
        // is far better than unbounded growth: the worst case is that a
        // credential becomes replayable for the rest of its (short) window,
        // which is exactly the pre-existing behaviour.
        if seen.len() >= self.capacity {
            warn!(
                "{} single-use cache is full ({} entries), clearing",
                self.label, self.capacity
            );
            seen.clear();
        }

        if seen.insert(key, now).is_some() {
            bail!("Credential has already been used");
        }
        Ok(())
    }

    /// Number of tracked entries. Test/diagnostic helper.
    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether nothing is currently tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_succeeds_and_replay_fails() {
        let guard: SingleUseGuard<u32> = SingleUseGuard::new("test", Duration::from_secs(60), 1000);

        assert!(guard.consume(1).is_ok());
        assert!(
            guard.consume(1).is_err(),
            "the same credential must not be usable twice"
        );
        // A different credential is unaffected.
        assert!(guard.consume(2).is_ok());
    }

    #[test]
    fn entries_age_out_of_the_window() {
        let guard: SingleUseGuard<u32> =
            SingleUseGuard::new("test", Duration::from_millis(20), 1000);

        assert!(guard.consume(1).is_ok());
        assert!(guard.consume(1).is_err());

        std::thread::sleep(Duration::from_millis(25));

        // Past the window the entry is forgotten. That is safe: a credential
        // this old fails its own expiry check before ever reaching here.
        assert!(guard.consume(1).is_ok());
    }

    #[test]
    fn capacity_is_enforced() {
        let guard: SingleUseGuard<u32> = SingleUseGuard::new("test", Duration::from_secs(60), 8);

        for i in 0..32 {
            let _ = guard.consume(i);
        }

        assert!(
            guard.len() <= 8,
            "cache grew past its capacity: {}",
            guard.len()
        );
    }

    #[tokio::test]
    async fn a_shared_set_rejects_a_replay_seen_by_another_replica() {
        let shared: Arc<dyn SharedSeenSet> = Arc::new(MemorySeenSet::default());
        let replica_a: SingleUseGuard<u32> = SingleUseGuard::new("a", Duration::from_secs(60), 10);
        let replica_b: SingleUseGuard<u32> = SingleUseGuard::new("b", Duration::from_secs(60), 10);
        let ttl = Duration::from_secs(60);
        replica_a.consume(7).unwrap();
        consume_shared(Some(&shared), "nip98", "7", ttl).await.unwrap();
        replica_b.consume(7).unwrap();
        assert!(consume_shared(Some(&shared), "nip98", "7", ttl).await.is_err());
    }

    #[tokio::test]
    async fn redis_set_is_shared_when_available() {
        let Ok(url) = std::env::var("LNVPS_TEST_REDIS_URL") else { return };
        let a = RedisSeenSet::new(&url).await.unwrap();
        let b = RedisSeenSet::new(&url).await.unwrap();
        let key = format!("test-{}", std::process::id());
        assert!(a.first_use(&key, Duration::from_secs(5)).await.unwrap());
        assert!(!b.first_use(&key, Duration::from_secs(5)).await.unwrap());
    }

    #[test]
    fn reports_emptiness() {
        let guard: SingleUseGuard<u32> = SingleUseGuard::new("test", Duration::from_secs(60), 1000);
        assert!(guard.is_empty());
        assert!(guard.consume(1).is_ok());
        assert!(!guard.is_empty());
    }
}
