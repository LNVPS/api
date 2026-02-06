//! Retry utilities with anyhow integration.
//!
//! Re-exports everything from [`try_procedure`] and provides anyhow-flavored
//! convenience types so that callers using `anyhow::Error` don't need to
//! specify the error type parameter.

// Re-export the core crate
pub use try_procedure::{retry_async, OpError, Pipeline, RetryOp, RetryPolicy, Retryable};

/// Convenience type alias that defaults the error to [`anyhow::Error`].
///
/// All trait definitions in this codebase use `OpResult<T>` (without specifying `E`),
/// which resolves to `Result<T, OpError<anyhow::Error>>`.
pub type OpResult<T, E = anyhow::Error> = Result<T, OpError<E>>;

/// Backwards-compatible alias: the new crate calls it `Pipeline`,
/// but existing code may reference `RetryPipeline`.
pub type RetryPipeline<Ctx> = Pipeline<Ctx, anyhow::Error>;
