use std::sync::atomic::{AtomicBool, Ordering};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use log::error;
use serde::{Deserialize, Serialize};

/// Whether a 500 returns the underlying error text to the caller.
///
/// Process state rather than a Cargo feature, because a feature cannot express
/// this. `lnvps_api_admin` depends on this crate with `admin` on and the
/// Dockerfile builds it in the same `cargo build` as `lnvps_api`; feature
/// unification then compiles one `lnvps_api_common` with `admin` enabled and
/// links it into *both* binaries, so the public API served admin-verbosity
/// errors — sqlx messages naming tables, columns, constraints and duplicate-key
/// values, database host:port, SSH usernames and file paths — to anonymous
/// callers.
///
/// Defaults to sanitised so a binary that forgets to opt in is safe: the
/// failure mode of forgetting is a less useful error message, not a leak.
static VERBOSE_INTERNAL_ERRORS: AtomicBool = AtomicBool::new(false);

/// Return the underlying error text on a 500 for this process.
///
/// Call from an admin binary's startup, before serving. Never call it from a
/// binary that serves customers.
pub fn set_verbose_internal_errors(verbose: bool) {
    VERBOSE_INTERNAL_ERRORS.store(verbose, Ordering::Relaxed);
}

/// Whether this process returns the underlying error text on a 500.
pub fn verbose_internal_errors() -> bool {
    VERBOSE_INTERNAL_ERRORS.load(Ordering::Relaxed)
}

pub type ApiResult<T> = Result<Json<ApiData<T>>, ApiError>;
pub type ApiPaginatedResult<T> = Result<Json<ApiPaginatedData<T>>, ApiError>;

#[derive(Serialize, Deserialize)]
pub struct ApiData<T: Serialize> {
    pub data: T,
}

impl<T: Serialize> ApiData<T> {
    pub fn ok(data: T) -> ApiResult<T> {
        Ok(Json(ApiData { data }))
    }

    pub fn err(msg: &str) -> ApiResult<T> {
        Err(ApiError::new(msg))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiPaginatedData<T: Serialize> {
    pub data: Vec<T>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

impl<T: Serialize> ApiPaginatedData<T> {
    pub fn ok(data: Vec<T>, total: u64, limit: u64, offset: u64) -> ApiPaginatedResult<T> {
        Ok(Json(ApiPaginatedData {
            data,
            total,
            limit,
            offset,
        }))
    }

    pub fn err(msg: &str) -> ApiPaginatedResult<T> {
        Err(ApiError::new(msg))
    }
}

#[derive(Serialize, Debug)]
pub struct ApiError {
    pub error: String,
    /// HTTP status code to return for this error. Skipped during serialization
    /// (the response body only carries the `error` message).
    #[serde(skip)]
    pub code: StatusCode,
}

impl ApiError {
    /// Create an API error with a user-safe message (HTTP 400 Bad Request).
    ///
    /// `new` is intended for client-caused errors carrying a user-safe
    /// message. For internal failures that should not leak details use
    /// [`ApiError::internal`]; for other client errors use the dedicated
    /// [`ApiError::not_found`], [`ApiError::forbidden`], etc. helpers.
    pub fn new(message: impl ToString) -> Self {
        Self {
            error: message.to_string(),
            code: StatusCode::BAD_REQUEST,
        }
    }

    /// Create an API error with a specific HTTP status code
    pub fn with_status(code: StatusCode, message: impl ToString) -> Self {
        Self {
            error: message.to_string(),
            code,
        }
    }

    /// Create a 400 Bad Request error (explicit alias for [`ApiError::new`])
    pub fn bad_request(message: impl ToString) -> Self {
        Self::with_status(StatusCode::BAD_REQUEST, message)
    }

    /// Create a 401 Unauthorized error
    pub fn unauthorized(message: impl ToString) -> Self {
        Self::with_status(StatusCode::UNAUTHORIZED, message)
    }

    /// Create a 403 Forbidden error
    pub fn forbidden(message: impl ToString) -> Self {
        Self::with_status(StatusCode::FORBIDDEN, message)
    }

    /// Create a 404 Not Found error
    pub fn not_found(message: impl ToString) -> Self {
        Self::with_status(StatusCode::NOT_FOUND, message)
    }

    /// Create a 402 Payment Required error
    pub fn payment_required(message: impl ToString) -> Self {
        Self::with_status(StatusCode::PAYMENT_REQUIRED, message)
    }

    /// Create a 409 Conflict error
    pub fn conflict(message: impl ToString) -> Self {
        Self::with_status(StatusCode::CONFLICT, message)
    }

    /// Create a 501 Not Implemented error
    pub fn not_implemented(message: impl ToString) -> Self {
        Self::with_status(StatusCode::NOT_IMPLEMENTED, message)
    }

    /// Create an API error from an internal error, always logging the full
    /// details and returning them to the caller only where the process has
    /// opted in with [`set_verbose_internal_errors`].
    ///
    /// The detail an admin wants for debugging is the detail a customer must
    /// not see, and which of the two this is cannot be decided at compile time:
    /// see [`VERBOSE_INTERNAL_ERRORS`].
    pub fn internal(err: impl std::fmt::Display) -> Self {
        error!("Internal error: {}", err);
        let error = if verbose_internal_errors() {
            err.to_string()
        } else {
            "An internal error occurred".to_string()
        };
        Self {
            error,
            code: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        // Surface known capacity errors as a user-facing 409 instead of a
        // generic internal server error.
        if let Some(cap) = value.downcast_ref::<crate::CapacityError>() {
            return Self::conflict(cap);
        }
        Self::internal(value)
    }
}

impl From<lnvps_db::DbError> for ApiError {
    fn from(value: lnvps_db::DbError) -> Self {
        // A missing row is a client-side "not found", not an internal error.
        if value.is_row_not_found() {
            return Self::not_found("Resource not found");
        }
        Self::internal(value)
    }
}

impl From<crate::retry::OpError<anyhow::Error>> for ApiError {
    fn from(value: crate::retry::OpError<anyhow::Error>) -> Self {
        Self::internal(value)
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ApiError {
    fn from(value: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::internal(value)
    }
}

impl From<&str> for ApiError {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ApiError {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.code, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_json_format() {
        let error = ApiError::new("Something went wrong");
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(json, r#"{"error":"Something went wrong"}"#);
    }

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(ApiError::new("x").code, StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::bad_request("x").code, StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::unauthorized("x").code, StatusCode::UNAUTHORIZED);
        assert_eq!(
            ApiError::payment_required("x").code,
            StatusCode::PAYMENT_REQUIRED
        );
        assert_eq!(ApiError::forbidden("x").code, StatusCode::FORBIDDEN);
        assert_eq!(ApiError::not_found("x").code, StatusCode::NOT_FOUND);
        assert_eq!(ApiError::conflict("x").code, StatusCode::CONFLICT);
        assert_eq!(
            ApiError::internal("x").code,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ApiError::with_status(StatusCode::IM_A_TEAPOT, "x").code,
            StatusCode::IM_A_TEAPOT
        );
    }

    #[test]
    fn test_db_row_not_found_maps_to_404() {
        // A missing DB row must become a 404, not a 500.
        let err: ApiError = lnvps_db::DbError::SqlxError(sqlx::Error::RowNotFound).into();
        assert_eq!(err.code, StatusCode::NOT_FOUND);

        // Any other DB error stays a 500.
        let err: ApiError = lnvps_db::DbError::Unknown.into();
        assert_eq!(err.code, StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Both verbosity behaviours, and the default, in one test.
    ///
    /// One test rather than three because the switch is process-global: tests
    /// in a crate share a process and run in parallel, so separate tests would
    /// race and pass or fail depending on scheduling.
    #[test]
    fn test_api_error_internal_verbosity() {
        const SECRET: &str = "secret internal details at 192.168.1.1";

        // The default is sanitised, so a binary that never opts in is safe.
        assert!(!verbose_internal_errors());
        assert_eq!(ApiError::internal(SECRET).error, "An internal error occurred");

        set_verbose_internal_errors(true);
        assert_eq!(ApiError::internal(SECRET).error, SECRET);

        // Restored, so this test cannot make an unrelated one see verbose
        // errors and pass for the wrong reason.
        set_verbose_internal_errors(false);
        assert_eq!(ApiError::internal(SECRET).error, "An internal error occurred");
    }
}
