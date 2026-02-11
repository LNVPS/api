use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use log::error;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    /// Create an API error with a user-safe message
    pub fn new(message: impl ToString) -> Self {
        Self {
            error: message.to_string(),
        }
    }

    /// Create an API error from an internal error, logging the full details
    /// but only returning a generic message to the client
    pub fn internal(err: impl std::fmt::Display) -> Self {
        error!("Internal error: {}", err);
        Self {
            error: "An internal error occurred".to_string(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self::internal(value)
    }
}

impl From<lnvps_db::DbError> for ApiError {
    fn from(value: lnvps_db::DbError) -> Self {
        Self::internal(value)
    }
}

impl From<crate::retry::OpError<anyhow::Error>> for ApiError {
    fn from(value: crate::retry::OpError<anyhow::Error>) -> Self {
        Self::internal(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
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
    fn test_api_error_internal_sanitizes() {
        let error = ApiError::internal("secret internal details at 192.168.1.1");
        assert_eq!(error.error, "An internal error occurred");
    }
}
