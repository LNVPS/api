use crate::db;
use crate::nip98::Nip98Auth;
use crate::provisioner::Provisioner;
use anyhow::Error;
use rocket::serde::json::Json;
use rocket::{get, routes, Responder, Route, State};
use serde::Serialize;

pub fn routes() -> Vec<Route> {
    routes![v1_list_vms]
}

type ApiResult<T> = Result<Json<ApiData<T>>, ApiError>;

#[derive(Serialize)]
struct ApiData<T: Serialize> {
    pub data: T,
}

impl<T: Serialize> ApiData<T> {
    pub fn ok(data: T) -> ApiResult<T> {
        Ok(Json::from(ApiData { data }))
    }
}

#[derive(Responder)]
#[response(status = 500)]
struct ApiError {
    pub error: String,
}

impl From<Error> for ApiError {
    fn from(value: Error) -> Self {
        Self {
            error: value.to_string(),
        }
    }
}

#[get("/api/v1/vms")]
async fn v1_list_vms(auth: Nip98Auth, provisioner: &State<Provisioner>) -> ApiResult<Vec<db::Vm>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = provisioner.upsert_user(&pubkey).await?;
    let vms = provisioner.list_vms(uid).await?;
    ApiData::ok(vms)
}
