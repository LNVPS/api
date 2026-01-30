use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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
        Err(msg.into())
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
        Err(msg.into())
    }
}

#[derive(Serialize)]
pub struct ApiError {
    pub message: String,
}

impl ApiError {
    pub fn new(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl<T: ToString> From<T> for ApiError {
    fn from(value: T) -> Self {
        Self::new(value.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self.message)).into_response()
    }
}
