use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::http::StatusCode;

use crate::ApiError;

pub const ABUSE_LOG_TARGET: &str = "lnvps_abuse";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAction {
    VmOrder,
    Payment,
    Refund,
}

impl AccountAction {
    pub const fn name(self) -> &'static str {
        match self {
            Self::VmOrder => "vm_order",
            Self::Payment => "payment",
            Self::Refund => "refund",
        }
    }

    pub const fn max(self) -> u64 {
        match self {
            Self::VmOrder => 20,
            Self::Payment => 60,
            Self::Refund => 10,
        }
    }

    pub const fn window(self) -> Duration {
        Duration::from_secs(3600)
    }
}

#[async_trait::async_trait]
pub trait CounterStore: Send + Sync {
    async fn incr(&self, key: &str, window: Duration) -> Result<u64>;
}

#[derive(Default)]
pub struct MemoryCounterStore {
    counters: Mutex<HashMap<String, (u64, Instant)>>,
}

#[async_trait::async_trait]
impl CounterStore for MemoryCounterStore {
    async fn incr(&self, key: &str, window: Duration) -> Result<u64> {
        let now = Instant::now();
        let mut map = self.counters.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, (_, start)| now.duration_since(*start) < window);
        let entry = map.entry(key.to_string()).or_insert((0, now));
        entry.0 += 1;
        Ok(entry.0)
    }
}

pub struct RedisCounterStore {
    conn: redis::aio::ConnectionManager,
}

impl RedisCounterStore {
    pub async fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            conn: redis::aio::ConnectionManager::new(client).await?,
        })
    }
}

#[async_trait::async_trait]
impl CounterStore for RedisCounterStore {
    async fn incr(&self, key: &str, window: Duration) -> Result<u64> {
        let mut conn = self.conn.clone();
        let (count,): (u64,) = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(key)
            .cmd("EXPIRE")
            .arg(key)
            .arg(window.as_secs().max(1))
            .arg("NX")
            .ignore()
            .query_async(&mut conn)
            .await?;
        Ok(count)
    }
}

#[derive(Clone)]
pub struct AccountLimiter {
    store: Arc<dyn CounterStore>,
    enabled: bool,
}

impl Default for AccountLimiter {
    fn default() -> Self {
        Self::new(Arc::new(MemoryCounterStore::default()), true)
    }
}

impl AccountLimiter {
    pub fn new(store: Arc<dyn CounterStore>, enabled: bool) -> Self {
        Self { store, enabled }
    }

    pub async fn check(&self, action: AccountAction, user_id: u64) -> Result<(), ApiError> {
        self.check_with(action, user_id, action.max()).await
    }

    pub async fn check_with(
        &self,
        action: AccountAction,
        user_id: u64,
        max: u64,
    ) -> Result<(), ApiError> {
        if !self.enabled {
            return Ok(());
        }
        let key = format!("acctlimit:{}:{}", action.name(), user_id);
        let count = match self.store.incr(&key, action.window()).await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("account limiter store unavailable, allowing: {e}");
                return Ok(());
            }
        };
        if count > max {
            if count == max + 1 {
                log::error!(
                    target: ABUSE_LOG_TARGET,
                    "rate-limit burst action={} user_id={} limit={} window_secs={}",
                    action.name(),
                    user_id,
                    max,
                    action.window().as_secs()
                );
            }
            return Err(ApiError::with_status(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Too many {} requests for this account. Try again later.",
                    action.name()
                ),
            ));
        }
        Ok(())
    }
}

static INSTALLED: OnceLock<AccountLimiter> = OnceLock::new();

pub fn install_account_limiter(limiter: AccountLimiter) -> bool {
    INSTALLED.set(limiter).is_ok()
}

pub async fn enforce_account_limit(action: AccountAction, user_id: u64) -> Result<(), ApiError> {
    match INSTALLED.get() {
        Some(l) => l.check(action, user_id).await,
        None => {
            static FALLBACK: OnceLock<AccountLimiter> = OnceLock::new();
            FALLBACK
                .get_or_init(AccountLimiter::default)
                .check(action, user_id)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_account_is_bounded_across_any_number_of_source_ips() {
        let l = AccountLimiter::default();
        for _ in 0..3 {
            l.check_with(AccountAction::VmOrder, 1, 3).await.unwrap();
        }
        let err = l.check_with(AccountAction::VmOrder, 1, 3).await.unwrap_err();
        assert_eq!(err.code, StatusCode::TOO_MANY_REQUESTS);
        l.check_with(AccountAction::VmOrder, 2, 3).await.unwrap();
        l.check_with(AccountAction::Payment, 1, 3).await.unwrap();
    }

    #[tokio::test]
    async fn two_replicas_sharing_a_store_share_the_budget() {
        let store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::default());
        let a = AccountLimiter::new(store.clone(), true);
        let b = AccountLimiter::new(store, true);
        a.check_with(AccountAction::Refund, 9, 2).await.unwrap();
        b.check_with(AccountAction::Refund, 9, 2).await.unwrap();
        assert!(a.check_with(AccountAction::Refund, 9, 2).await.is_err());
    }

    #[tokio::test]
    async fn a_disabled_limiter_allows_everything() {
        let l = AccountLimiter::new(Arc::new(MemoryCounterStore::default()), false);
        for _ in 0..100 {
            l.check_with(AccountAction::Payment, 1, 1).await.unwrap();
        }
    }

    #[tokio::test]
    async fn two_replicas_on_one_redis_share_an_account_budget() {
        let Ok(url) = std::env::var("LNVPS_TEST_REDIS_URL") else {
            return;
        };
        let a = AccountLimiter::new(Arc::new(RedisCounterStore::new(&url).await.unwrap()), true);
        let b = AccountLimiter::new(Arc::new(RedisCounterStore::new(&url).await.unwrap()), true);
        let user = 9_000_000 + std::process::id() as u64;
        a.check_with(AccountAction::Refund, user, 2).await.unwrap();
        b.check_with(AccountAction::Refund, user, 2).await.unwrap();
        assert!(a.check_with(AccountAction::Refund, user, 2).await.is_err());
        assert!(b.check_with(AccountAction::Refund, user, 2).await.is_err());
    }

    #[tokio::test]
    async fn redis_counter_is_shared_when_available() {
        let Ok(url) = std::env::var("LNVPS_TEST_REDIS_URL") else {
            return;
        };
        let a = RedisCounterStore::new(&url).await.unwrap();
        let b = RedisCounterStore::new(&url).await.unwrap();
        let key = format!("acctlimit:test:{}", std::process::id());
        assert_eq!(a.incr(&key, Duration::from_secs(5)).await.unwrap(), 1);
        assert_eq!(b.incr(&key, Duration::from_secs(5)).await.unwrap(), 2);
    }
}
