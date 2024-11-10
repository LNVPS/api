use crate::db;
use crate::nip98::Nip98Auth;
use crate::provisioner::Provisioner;
use anyhow::Error;
use rocket::serde::json::Json;
use rocket::{get, post, routes, Data, Responder, Route, State};
use serde::{Deserialize, Serialize};
use crate::vm::VMSpec;

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

#[derive(Debug, Serialize, Deserialize)]
struct CreateVmRequest {}

impl From<CreateVmRequest> for VMSpec {
    fn from(value: CreateVmRequest) -> Self {
        todo!()
    }
}

#[get("/api/v1/vms")]
async fn v1_list_vms(auth: Nip98Auth, provisioner: &State<Provisioner>) -> ApiResult<Vec<db::Vm>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = provisioner.upsert_user(&pubkey).await?;
    let vms = provisioner.list_vms(uid).await?;
    ApiData::ok(vms)
}

#[get("/api/v1/vm/templates")]
async fn v1_list_vm_templates(provisioner: &State<Provisioner>) -> ApiResult<Vec<db::VmTemplate>> {
    let vms = provisioner.list_vm_templates().await?;
    ApiData::ok(vms)
}

#[post("/api/v1/vm", data = "<req>", format = "json")]
async fn v1_provision_vm(auth: Nip98Auth, provisioner: &State<Provisioner>, req: Json<CreateVmRequest>) -> ApiResult<db::Vm> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = provisioner.upsert_user(&pubkey).await?;

    let req = req.0;
    let rsp = provisioner.provision(req.into()).await?;
    ApiData::ok(rsp)
}