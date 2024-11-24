use crate::nip98::Nip98Auth;
use crate::provisioner::Provisioner;
use anyhow::Error;
use lnvps_db::{LNVpsDb, Vm, VmTemplate};
use rocket::serde::json::Json;
use rocket::{get, post, routes, Responder, Route, State};
use serde::{Deserialize, Serialize};

pub fn routes() -> Vec<Route> {
    routes![v1_list_vms, v1_list_vm_templates, v1_provision_vm]
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
async fn v1_list_vms(auth: Nip98Auth, db: &State<Box<dyn LNVpsDb>>) -> ApiResult<Vec<Vm>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vms = db.list_user_vms(uid).await?;
    ApiData::ok(vms)
}

#[get("/api/v1/vm/templates")]
async fn v1_list_vm_templates(db: &State<Box<dyn LNVpsDb>>) -> ApiResult<Vec<VmTemplate>> {
    let vms = db.list_vm_templates().await?;
    ApiData::ok(vms)
}

#[post("/api/v1/vm", data = "<req>", format = "json")]
async fn v1_provision_vm(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    provisioner: &State<Box<dyn Provisioner>>,
    req: Json<CreateVmRequest>,
) -> ApiResult<Vm> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let req = req.0;
    let rsp = provisioner.provision(req.into()).await?;
    ApiData::ok(rsp)
}

#[derive(Deserialize)]
pub struct CreateVmRequest {}

impl Into<VmTemplate> for CreateVmRequest {
    fn into(self) -> VmTemplate {
        todo!()
    }
}
