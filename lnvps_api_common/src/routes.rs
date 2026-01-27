use rocket::serde::json::Json;
use rocket::Responder;
use serde::{Deserialize, Serialize};

pub type ApiResult<T> = Result<Json<ApiData<T>>, ApiError>;
pub type ApiPaginatedResult<T> = Result<Json<ApiPaginatedData<T>>, ApiError>;

#[derive(Serialize, Deserialize)]
pub struct ApiData<T: Serialize> {
    pub data: T,
}

impl<T: Serialize> ApiData<T> {
    pub fn ok(data: T) -> ApiResult<T> {
        Ok(Json::from(ApiData { data }))
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
        Ok(Json::from(ApiPaginatedData {
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

#[derive(Responder)]
#[response(status = 500)]
pub struct ApiError {
    pub error: String,
}

impl<T: ToString> From<T> for ApiError {
    fn from(value: T) -> Self {
        Self {
            error: value.to_string(),
        }
    }
}
