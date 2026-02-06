//! Retry with error classification and step-based rollback pipelines.
//!
//! This crate provides two main abstractions:
//!
//! - [`RetryOp`] / [`Retryable`]: Retry an async operation with exponential backoff,
//!   distinguishing between transient (retryable) and fatal (non-recoverable) errors.
//!
//! - [`Pipeline`]: Execute a sequence of async steps with automatic rollback on failure.
//!   If step N fails, rollbacks for steps 0..N-1 are executed in reverse order.
//!
//! # Error Classification
//!
//! The key insight is that **only the operation itself knows** whether a failure is
//! transient or fatal. Operations return [`OpResult<T, E>`] which wraps errors in
//! [`OpError::Transient`] or [`OpError::Fatal`]:
//!
//! ```ignore
//! use try_procedure::{OpError, OpResult};
//!
//! async fn call_api() -> OpResult<String> {
//!     match do_request().await {
//!         Ok(v) => Ok(v),
//!         Err(e) if e.is_timeout() => Err(OpError::Transient(e)),
//!         Err(e) => Err(OpError::Fatal(e)),
//!     }
//! }
//! ```
//!
//! # Retry
//!
//! ```ignore
//! use try_procedure::{Retryable, RetryPolicy};
//!
//! let value = (|| async { call_api().await })
//!     .with_retry(RetryPolicy::default())
//!     .await?;
//! ```
//!
//! # Pipeline
//!
//! ```ignore
//! use try_procedure::Pipeline;
//!
//! struct Ctx { resource_id: Option<u64> }
//!
//! let ctx = Pipeline::new(Ctx { resource_id: None })
//!     .step_with_rollback("create_resource",
//!         |ctx| Box::pin(async move {
//!             ctx.resource_id = Some(create().await?);
//!             Ok(())
//!         }),
//!         |ctx| Box::pin(async move {
//!             if let Some(id) = ctx.resource_id {
//!                 delete(id).await?;
//!             }
//!             Ok(())
//!         }),
//!     )
//!     .execute()
//!     .await?;
//! ```

use log::warn;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::time::Duration;
use tokio::time::sleep;

// ─── Error Classification ──────────────────────────────────────────────────────

/// An error that classifies itself as transient (retryable) or fatal (non-recoverable).
#[derive(Debug)]
pub enum OpError<E> {
    /// A transient failure that may succeed on retry
    Transient(E),
    /// A fatal failure that should not be retried
    Fatal(E),
}

impl<E> OpError<E> {
    /// Extract the inner error regardless of variant
    pub fn into_inner(self) -> E {
        match self {
            OpError::Transient(e) | OpError::Fatal(e) => e,
        }
    }

    /// Returns true if the error is transient (retryable)
    pub fn is_transient(&self) -> bool {
        matches!(self, OpError::Transient(_))
    }

    /// Returns true if the error is fatal (non-recoverable)
    pub fn is_fatal(&self) -> bool {
        matches!(self, OpError::Fatal(_))
    }

    /// Reference to the inner error
    pub fn inner(&self) -> &E {
        match self {
            OpError::Transient(e) | OpError::Fatal(e) => e,
        }
    }

    /// Map the inner error to a different type
    pub fn map<F, U>(self, f: F) -> OpError<U>
    where
        F: FnOnce(E) -> U,
    {
        match self {
            OpError::Transient(e) => OpError::Transient(f(e)),
            OpError::Fatal(e) => OpError::Fatal(f(e)),
        }
    }
}

impl<E: fmt::Display> fmt::Display for OpError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpError::Transient(e) => write!(f, "transient error: {}", e),
            OpError::Fatal(e) => write!(f, "fatal error: {}", e),
        }
    }
}

impl<E: fmt::Display + fmt::Debug> std::error::Error for OpError<E> {}

/// Convenience type alias for operations that return retryable results.
///
/// The default error type is `Box<dyn std::error::Error + Send + Sync>`.
pub type OpResult<T, E = Box<dyn std::error::Error + Send + Sync>> = Result<T, OpError<E>>;

// ─── Retry Policy ──────────────────────────────────────────────────────────────

/// Configuration for retry behavior with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Minimum delay between retries
    pub min_delay: Duration,
    /// Maximum delay between retries (caps exponential backoff)
    pub max_delay: Duration,
    /// Maximum number of retry attempts (not counting the first attempt)
    pub max_retries: u32,
    /// Multiplier for exponential backoff (delay *= factor each attempt)
    pub factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            max_retries: 3,
            factor: 2.0,
        }
    }
}

impl RetryPolicy {
    pub fn with_min_delay(mut self, delay: Duration) -> Self {
        self.min_delay = delay;
        self
    }

    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_factor(mut self, factor: f64) -> Self {
        self.factor = factor;
        self
    }

    /// Calculate the delay for a given attempt number (0-indexed)
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay = self.min_delay.as_secs_f64() * self.factor.powi(attempt as i32);
        let clamped = delay.min(self.max_delay.as_secs_f64());
        Duration::from_secs_f64(clamped)
    }
}

// ─── Retry Operation ───────────────────────────────────────────────────────────

/// An awaitable retry wrapper around an async operation.
///
/// Retries on [`OpError::Transient`] errors up to the configured limit,
/// and short-circuits immediately on [`OpError::Fatal`].
///
/// Implements [`IntoFuture`] so it can be directly `.await`ed.
///
/// # Example
/// ```ignore
/// let result = RetryOp::new(RetryPolicy::default(), || async {
///     match do_something().await {
///         Ok(v) => Ok(v),
///         Err(e) if e.is_timeout() => Err(OpError::Transient(e)),
///         Err(e) => Err(OpError::Fatal(e)),
///     }
/// }).await;
/// ```
pub struct RetryOp<F, Fut, T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OpError<E>>>,
    E: fmt::Display,
{
    factory: F,
    policy: RetryPolicy,
    on_retry: Option<Box<dyn Fn(&E, u32, Duration) + Send + Sync>>,
}

impl<F, Fut, T, E> RetryOp<F, Fut, T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OpError<E>>>,
    E: fmt::Display,
{
    pub fn new(policy: RetryPolicy, factory: F) -> Self {
        Self {
            factory,
            policy,
            on_retry: None,
        }
    }

    /// Register a callback invoked before each retry attempt.
    ///
    /// Receives the error, attempt number (1-indexed), and delay before next attempt.
    pub fn on_retry<C>(mut self, callback: C) -> Self
    where
        C: Fn(&E, u32, Duration) + Send + Sync + 'static,
    {
        self.on_retry = Some(Box::new(callback));
        self
    }

    /// Execute the operation with retries
    async fn execute(mut self) -> Result<T, E> {
        let mut attempt = 0u32;

        loop {
            match (self.factory)().await {
                Ok(val) => return Ok(val),
                Err(OpError::Fatal(e)) => return Err(e),
                Err(OpError::Transient(e)) => {
                    if attempt >= self.policy.max_retries {
                        return Err(e);
                    }
                    let delay = self.policy.delay_for_attempt(attempt);
                    if let Some(ref cb) = self.on_retry {
                        cb(&e, attempt + 1, delay);
                    }
                    sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

impl<F, Fut, T, E> IntoFuture for RetryOp<F, Fut, T, E>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, OpError<E>>> + Send + 'static,
    T: Send + 'static,
    E: fmt::Display + Send + 'static,
{
    type Output = Result<T, E>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

// ─── Retryable Extension Trait ─────────────────────────────────────────────────

/// Extension trait to convert a closure into a [`RetryOp`].
///
/// # Example
/// ```ignore
/// use try_procedure::{Retryable, OpError, RetryPolicy};
///
/// let value = (|| async {
///     match some_api_call().await {
///         Ok(v) => Ok(v),
///         Err(e) => Err(OpError::Transient(e)),
///     }
/// })
///     .with_retry(RetryPolicy::default())
///     .await?;
/// ```
pub trait Retryable<F, Fut, T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OpError<E>>>,
    E: fmt::Display,
{
    fn with_retry(self, policy: RetryPolicy) -> RetryOp<F, Fut, T, E>;
}

impl<F, Fut, T, E> Retryable<F, Fut, T, E> for F
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OpError<E>>>,
    E: fmt::Display,
{
    fn with_retry(self, policy: RetryPolicy) -> RetryOp<F, Fut, T, E> {
        RetryOp::new(policy, self)
    }
}

// ─── Standalone retry function ───────────────────────────────────────────────

/// Retry an async operation with the given policy, without requiring `'static` bounds.
///
/// Unlike [`RetryOp`] / [`Retryable`], this function does not box the future and
/// imposes no `'static` constraint on the closure or its captures. The retry loop
/// runs inline, so borrowed references in the closure remain valid.
///
/// # Example
/// ```ignore
/// let result = retry_async(RetryPolicy::default(), || async {
///     router.update_arp_entry(&entry).await
/// }).await?;
/// ```
pub async fn retry_async<F, Fut, T, E>(policy: RetryPolicy, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, OpError<E>>>,
    E: fmt::Display,
{
    let mut attempt = 0u32;

    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(OpError::Fatal(e)) => return Err(e),
            Err(OpError::Transient(e)) => {
                if attempt >= policy.max_retries {
                    return Err(e);
                }
                let delay = policy.delay_for_attempt(attempt);
                warn!(
                    "Transient error (attempt {}/{}), retrying in {:?}: {}",
                    attempt + 1,
                    policy.max_retries,
                    delay,
                    e
                );
                sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

// ─── Step-based Pipeline ───────────────────────────────────────────────────────

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Type-erased step function that operates on a mutable context
type StepFn<Ctx, E> = Box<dyn FnOnce(&mut Ctx) -> BoxFuture<'_, Result<(), E>> + Send>;

/// A step in the pipeline: an action and an optional rollback.
struct PipelineStep<Ctx, E> {
    name: String,
    action: StepFn<Ctx, E>,
    rollback: Option<StepFn<Ctx, E>>,
}

/// A pipeline of steps that execute in order with automatic rollback on failure.
///
/// Each step is an `(action, rollback)` pair. If step N fails, rollbacks for
/// steps 0..N-1 are executed in reverse order.
///
/// The pipeline operates on a shared mutable context `Ctx` that steps can
/// read from and write to, allowing later steps to access data produced
/// by earlier steps.
///
/// # Example
/// ```ignore
/// struct MyCtx {
///     ip_allocated: bool,
///     vm_id: u64,
/// }
///
/// let result = Pipeline::new(MyCtx { ip_allocated: false, vm_id: 42 })
///     .step("allocate_ip",
///         |ctx| Box::pin(async move {
///             allocate_ip(ctx.vm_id).await?;
///             ctx.ip_allocated = true;
///             Ok(())
///         }),
///     )
///     .step_with_rollback("create_vm",
///         |ctx| Box::pin(async move {
///             create_vm(ctx.vm_id).await
///         }),
///         |ctx| Box::pin(async move {
///             delete_vm(ctx.vm_id).await
///         }),
///     )
///     .execute()
///     .await;
/// ```
pub struct Pipeline<Ctx, E = Box<dyn std::error::Error + Send + Sync>> {
    ctx: Ctx,
    steps: Vec<PipelineStep<Ctx, E>>,
}

impl<Ctx, E> Pipeline<Ctx, E>
where
    Ctx: Send + 'static,
    E: fmt::Display + fmt::Debug + Send + 'static,
{
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx,
            steps: Vec::new(),
        }
    }

    /// Add a step with only an action (no rollback).
    pub fn step(
        mut self,
        name: impl Into<String>,
        action: impl FnOnce(&mut Ctx) -> BoxFuture<'_, Result<(), E>> + Send + 'static,
    ) -> Self {
        self.steps.push(PipelineStep {
            name: name.into(),
            action: Box::new(action),
            rollback: None,
        });
        self
    }

    /// Add a step with both an action and a rollback.
    ///
    /// The rollback runs only if this step succeeded and a later step fails.
    pub fn step_with_rollback(
        mut self,
        name: impl Into<String>,
        action: impl FnOnce(&mut Ctx) -> BoxFuture<'_, Result<(), E>> + Send + 'static,
        rollback: impl FnOnce(&mut Ctx) -> BoxFuture<'_, Result<(), E>> + Send + 'static,
    ) -> Self {
        self.steps.push(PipelineStep {
            name: name.into(),
            action: Box::new(action),
            rollback: Some(Box::new(rollback)),
        });
        self
    }

    /// Execute all steps in order. On failure, rollback completed steps in reverse.
    ///
    /// Returns the context on success so the caller can extract results from it.
    pub async fn execute(mut self) -> Result<Ctx, E> {
        let mut completed_rollbacks: Vec<StepFn<Ctx, E>> = Vec::new();

        // Drain steps so we can take ownership of each one
        let steps: Vec<PipelineStep<Ctx, E>> = self.steps.drain(..).collect();

        for step in steps {
            match (step.action)(&mut self.ctx).await {
                Ok(()) => {
                    if let Some(rollback) = step.rollback {
                        completed_rollbacks.push(rollback);
                    }
                }
                Err(e) => {
                    warn!(
                        "Pipeline step '{}' failed: {}, rolling back {} steps",
                        step.name,
                        e,
                        completed_rollbacks.len()
                    );

                    // Rollback in reverse order
                    for rollback in completed_rollbacks.into_iter().rev() {
                        if let Err(rb_err) = (rollback)(&mut self.ctx).await {
                            warn!("Rollback failed: {}", rb_err);
                        }
                    }

                    return Err(e);
                }
            }
        }

        Ok(self.ctx)
    }
}

impl<Ctx, E> IntoFuture for Pipeline<Ctx, E>
where
    Ctx: Send + 'static,
    E: fmt::Display + fmt::Debug + Send + 'static,
{
    type Output = Result<Ctx, E>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn retry_op_succeeds_first_attempt() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<u32, anyhow::Error> = RetryOp::new(
            RetryPolicy::default().with_min_delay(Duration::from_millis(1)),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(42)
                }
            },
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_op_retries_on_transient_then_succeeds() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<&str, anyhow::Error> = RetryOp::new(
            RetryPolicy::default().with_min_delay(Duration::from_millis(1)),
            move || {
                let c = c.clone();
                async move {
                    let attempt = c.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err(OpError::Transient(anyhow::anyhow!("transient failure")))
                    } else {
                        Ok("done")
                    }
                }
            },
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn retry_op_stops_on_fatal() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<(), anyhow::Error> = RetryOp::new(
            RetryPolicy::default().with_min_delay(Duration::from_millis(1)),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err(OpError::Fatal(anyhow::anyhow!("fatal failure")))
                }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // no retries
    }

    #[tokio::test]
    async fn retry_op_exhausts_retries() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<(), anyhow::Error> = RetryOp::new(
            RetryPolicy::default()
                .with_min_delay(Duration::from_millis(1))
                .with_max_retries(2),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err(OpError::Transient(anyhow::anyhow!("always fails")))
                }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn retry_op_with_extension_trait() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<u32, anyhow::Error> = (move || {
            let c = c.clone();
            async move {
                let attempt = c.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err(OpError::Transient(anyhow::anyhow!("try again")))
                } else {
                    Ok(99)
                }
            }
        })
        .with_retry(RetryPolicy::default().with_min_delay(Duration::from_millis(1)))
        .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retry_op_on_retry_callback() {
        let retry_count = Arc::new(AtomicU32::new(0));
        let rc = retry_count.clone();
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<(), anyhow::Error> = (move || {
            let c = c.clone();
            async move {
                let attempt = c.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(OpError::Transient(anyhow::anyhow!("retry me")))
                } else {
                    Ok(())
                }
            }
        })
        .with_retry(RetryPolicy::default().with_min_delay(Duration::from_millis(1)))
        .on_retry(move |_err, attempt, _delay| {
            rc.fetch_add(1, Ordering::SeqCst);
            assert!(attempt >= 1);
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(retry_count.load(Ordering::SeqCst), 2);
    }

    // ─── retry_async tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn retry_async_borrows_without_cloning() {
        // Demonstrates that retry_async works with borrowed (non-Clone) data
        let data = String::from("hello");
        let counter = AtomicU32::new(0);

        let result: Result<String, anyhow::Error> = retry_async(
            RetryPolicy::default().with_min_delay(Duration::from_millis(1)),
            || {
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                let data_clone = data.clone();
                async move {
                    if attempt == 0 {
                        Err(OpError::Transient(anyhow::anyhow!("retry")))
                    } else {
                        Ok(data_clone)
                    }
                }
            },
        )
        .await;

        assert_eq!(result.unwrap(), "hello");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        // data is still accessible here — it was borrowed, not moved
        assert_eq!(data, "hello");
    }

    #[tokio::test]
    async fn retry_async_stops_on_fatal() {
        let counter = AtomicU32::new(0);

        let result: Result<(), anyhow::Error> = retry_async(
            RetryPolicy::default().with_min_delay(Duration::from_millis(1)),
            || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Err(OpError::Fatal(anyhow::anyhow!("fatal"))) }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ─── Pipeline tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn pipeline_all_steps_succeed() {
        let executed = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let rolled_back = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let e1 = executed.clone();
        let e2 = executed.clone();
        let r1 = rolled_back.clone();
        let r2 = rolled_back.clone();

        let _ctx: () = Pipeline::<(), anyhow::Error>::new(())
            .step_with_rollback(
                "step1",
                move |_ctx| {
                    let e = e1.clone();
                    Box::pin(async move {
                        e.lock().await.push("step1".into());
                        Ok(())
                    })
                },
                move |_ctx| {
                    let r = r1.clone();
                    Box::pin(async move {
                        r.lock().await.push("step1".into());
                        Ok(())
                    })
                },
            )
            .step_with_rollback(
                "step2",
                move |_ctx| {
                    let e = e2.clone();
                    Box::pin(async move {
                        e.lock().await.push("step2".into());
                        Ok(())
                    })
                },
                move |_ctx| {
                    let r = r2.clone();
                    Box::pin(async move {
                        r.lock().await.push("step2".into());
                        Ok(())
                    })
                },
            )
            .await
            .unwrap();

        assert_eq!(*executed.lock().await, vec!["step1", "step2"]);
        assert!(rolled_back.lock().await.is_empty());
    }

    #[tokio::test]
    async fn pipeline_rollback_on_failure() {
        let rolled_back = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let r1 = rolled_back.clone();
        let r2 = rolled_back.clone();

        let result = Pipeline::<(), anyhow::Error>::new(())
            .step_with_rollback(
                "step1",
                |_ctx| Box::pin(async { Ok(()) }),
                move |_ctx| {
                    let r = r1.clone();
                    Box::pin(async move {
                        r.lock().await.push("step1".into());
                        Ok(())
                    })
                },
            )
            .step_with_rollback(
                "step2",
                |_ctx| Box::pin(async { Ok(()) }),
                move |_ctx| {
                    let r = r2.clone();
                    Box::pin(async move {
                        r.lock().await.push("step2".into());
                        Ok(())
                    })
                },
            )
            .step(
                "step3_fails",
                |_ctx| Box::pin(async { Err(anyhow::anyhow!("step 3 failed")) }),
            )
            .execute()
            .await;

        assert!(result.is_err());
        // Rollbacks should have run in reverse order
        let rb = rolled_back.lock().await;
        assert_eq!(*rb, vec!["step2", "step1"]);
    }

    #[tokio::test]
    async fn pipeline_rollback_runs_in_reverse() {
        let rollback_order = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let ro1 = rollback_order.clone();
        let ro2 = rollback_order.clone();

        let result = Pipeline::<(), anyhow::Error>::new(())
            .step_with_rollback(
                "step1",
                |_ctx| Box::pin(async { Ok(()) }),
                move |_ctx| {
                    let ro = ro1.clone();
                    Box::pin(async move {
                        ro.lock().await.push("rollback1".into());
                        Ok(())
                    })
                },
            )
            .step_with_rollback(
                "step2",
                |_ctx| Box::pin(async { Ok(()) }),
                move |_ctx| {
                    let ro = ro2.clone();
                    Box::pin(async move {
                        ro.lock().await.push("rollback2".into());
                        Ok(())
                    })
                },
            )
            .step(
                "step3_fails",
                |_ctx| Box::pin(async { Err(anyhow::anyhow!("boom")) }),
            )
            .execute()
            .await;

        assert!(result.is_err());
        let order = rollback_order.lock().await;
        assert_eq!(*order, vec!["rollback2", "rollback1"]);
    }

    #[tokio::test]
    async fn pipeline_no_rollback_when_first_step_fails() {
        let rollback_ran = Arc::new(AtomicU32::new(0));
        let rr = rollback_ran.clone();

        let result = Pipeline::<(), anyhow::Error>::new(())
            .step_with_rollback(
                "step1_fails",
                |_ctx| Box::pin(async { Err(anyhow::anyhow!("immediate failure")) }),
                move |_ctx| {
                    let rr = rr.clone();
                    Box::pin(async move {
                        rr.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                },
            )
            .execute()
            .await;

        assert!(result.is_err());
        // step1's own rollback should NOT run since it didn't succeed
        assert_eq!(rollback_ran.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pipeline_steps_without_rollback() {
        let executed = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let e1 = executed.clone();
        let e2 = executed.clone();

        let _ctx: () = Pipeline::<(), anyhow::Error>::new(())
            .step(
                "step1",
                move |_ctx| {
                    let e = e1.clone();
                    Box::pin(async move {
                        e.lock().await.push("step1".into());
                        Ok(())
                    })
                },
            )
            .step(
                "step2",
                move |_ctx| {
                    let e = e2.clone();
                    Box::pin(async move {
                        e.lock().await.push("step2".into());
                        Ok(())
                    })
                },
            )
            .await
            .unwrap();

        assert_eq!(*executed.lock().await, vec!["step1", "step2"]);
    }

    #[tokio::test]
    async fn pipeline_context_flows_between_steps() {
        struct Ctx {
            value: u32,
        }

        let ctx = Pipeline::<Ctx, anyhow::Error>::new(Ctx { value: 0 })
            .step(
                "set_value",
                |ctx| {
                    Box::pin(async move {
                        ctx.value = 42;
                        Ok(())
                    })
                },
            )
            .step(
                "double_value",
                |ctx| {
                    Box::pin(async move {
                        ctx.value *= 2;
                        Ok(())
                    })
                },
            )
            .await
            .unwrap();

        assert_eq!(ctx.value, 84);
    }
}
