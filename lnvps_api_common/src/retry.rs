//! Retry utilities with anyhow integration.
//!
//! Re-exports everything from [`try_procedure`] and provides anyhow-flavored
//! convenience types so that callers using `anyhow::Error` don't need to
//! specify the error type parameter.

// Re-export the core crate
pub use try_procedure::{OpError, Pipeline, RetryOp, RetryPolicy, Retryable, retry_async};

/// Convenience type alias that defaults the error to [`anyhow::Error`].
///
/// All trait definitions in this codebase use `OpResult<T>` (without specifying `E`),
/// which resolves to `Result<T, OpError<anyhow::Error>>`.
pub type OpResult<T, E = anyhow::Error> = Result<T, OpError<E>>;

/// Backwards-compatible alias: the new crate calls it `Pipeline`,
/// but existing code may reference `RetryPipeline`.
pub type RetryPipeline<'a, Ctx> = Pipeline<'a, Ctx, anyhow::Error>;

#[macro_export]
macro_rules! op_fatal {
    ($err:expr, anyhow::Error) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Fatal($err))
    };
    ($msg:literal $(,)?) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Fatal(anyhow::anyhow!($msg)))
    };
    ($err:expr $(,)?) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Fatal(anyhow::anyhow!($err)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Fatal(anyhow::anyhow!($fmt, $($arg)*)))
    };
}

#[macro_export]
macro_rules! op_transient {
    ($err:expr, anyhow::Error) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Transient($err))
    };
    ($msg:literal $(,)?) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Transient(anyhow::anyhow!($msg)))
    };
    ($err:expr $(,)?) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Transient(anyhow::anyhow!($err)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return $crate::retry::OpResult::Err($crate::retry::OpError::Transient(anyhow::anyhow!($fmt, $($arg)*)))
    };
}
