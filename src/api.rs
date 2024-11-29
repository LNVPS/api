use crate::nip98::Nip98Auth;
use crate::provisioner::Provisioner;
use crate::status::{VmState, VmStateCache};
use crate::worker::WorkJob;
use lnvps_db::hydrate::Hydrate;
use lnvps_db::{LNVpsDb, UserSshKey, Vm, VmOsImage, VmPayment, VmTemplate};
use nostr::util::hex;
use rocket::serde::json::Json;
use rocket::{get, patch, post, routes, Responder, Route, State};
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use tokio::sync::mpsc::UnboundedSender;

pub fn routes() -> Vec<Route> {
    routes![
        v1_list_vms,
        v1_get_vm,
        v1_list_vm_templates,
        v1_list_vm_images,
        v1_list_ssh_keys,
        v1_add_ssh_key,
        v1_create_vm_order,
        v1_renew_vm,
        v1_get_payment,
        v1_start_vm,
        v1_stop_vm,
        v1_restart_vm
    ]
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
    pub fn err(msg: &str) -> ApiResult<T> {
        Err(msg.into())
    }
}

#[derive(Responder)]
#[response(status = 500)]
struct ApiError {
    pub error: String,
}

impl<T: ToString> From<T> for ApiError {
    fn from(value: T) -> Self {
        Self {
            error: value.to_string(),
        }
    }
}

#[derive(Serialize)]
struct ApiVmStatus {
    #[serde(flatten)]
    pub vm: Vm,
    pub status: VmState,
}

#[get("/api/v1/vm")]
async fn v1_list_vms(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    vm_state: &State<VmStateCache>,
) -> ApiResult<Vec<ApiVmStatus>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vms = db.list_user_vms(uid).await?;
    let mut ret = vec![];
    for mut vm in vms {
        vm.hydrate_up(db.inner()).await?;
        vm.hydrate_down(db.inner()).await?;
        if let Some(t) = &mut vm.template {
            t.hydrate_up(db.inner()).await?;
        }

        let state = vm_state.get_state(vm.id).await;
        ret.push(ApiVmStatus { vm, status: state });
    }

    ApiData::ok(ret)
}

#[get("/api/v1/vm/<id>")]
async fn v1_get_vm(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    vm_state: &State<VmStateCache>,
    id: u64,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let mut vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM doesnt belong to you");
    }
    vm.hydrate_up(db.inner()).await?;
    vm.hydrate_down(db.inner()).await?;
    if let Some(t) = &mut vm.template {
        t.hydrate_up(db.inner()).await?;
    }
    let state = vm_state.get_state(vm.id).await;
    ApiData::ok(ApiVmStatus { vm, status: state })
}

#[get("/api/v1/image")]
async fn v1_list_vm_images(db: &State<Box<dyn LNVpsDb>>) -> ApiResult<Vec<VmOsImage>> {
    let vms = db.list_os_image().await?;
    let vms: Vec<VmOsImage> = vms.into_iter().filter(|i| i.enabled).collect();
    ApiData::ok(vms)
}

#[get("/api/v1/vm/templates")]
async fn v1_list_vm_templates(db: &State<Box<dyn LNVpsDb>>) -> ApiResult<Vec<VmTemplate>> {
    let mut vms = db.list_vm_templates().await?;
    for vm in &mut vms {
        vm.hydrate_up(db.inner()).await?;
    }
    let ret: Vec<VmTemplate> = vms.into_iter().filter(|v| v.enabled).collect();
    ApiData::ok(ret)
}

#[get("/api/v1/ssh-key")]
async fn v1_list_ssh_keys(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
) -> ApiResult<Vec<UserSshKey>> {
    let uid = db.upsert_user(&auth.event.pubkey.to_bytes()).await?;
    let keys = db.list_user_ssh_key(uid).await?;
    ApiData::ok(keys)
}

#[post("/api/v1/ssh-key", data = "<req>", format = "json")]
async fn v1_add_ssh_key(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    req: Json<CreateSshKey>,
) -> ApiResult<UserSshKey> {
    let uid = db.upsert_user(&auth.event.pubkey.to_bytes()).await?;

    let pk: PublicKey = req.key_data.parse()?;
    let key_name = if !req.name.is_empty() {
        &req.name
    } else {
        pk.comment()
    };
    let mut new_key = UserSshKey {
        name: key_name.to_string(),
        user_id: uid,
        key_data: pk.to_openssh()?,
        ..Default::default()
    };
    let key_id = db.insert_user_ssh_key(&new_key).await?;
    new_key.id = key_id;

    ApiData::ok(new_key)
}

#[post("/api/v1/vm", data = "<req>", format = "json")]
async fn v1_create_vm_order(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    provisioner: &State<Box<dyn Provisioner>>,
    req: Json<CreateVmRequest>,
) -> ApiResult<Vm> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let req = req.0;
    let mut rsp = provisioner
        .provision(uid, req.template_id, req.image_id, req.ssh_key_id)
        .await?;
    rsp.hydrate_up(db.inner()).await?;

    ApiData::ok(rsp)
}

#[get("/api/v1/vm/<id>/renew")]
async fn v1_renew_vm(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    provisioner: &State<Box<dyn Provisioner>>,
    id: u64,
) -> ApiResult<VmPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    let rsp = provisioner.renew(id).await?;
    ApiData::ok(rsp)
}

#[patch("/api/v1/vm/<id>/start")]
async fn v1_start_vm(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    provisioner: &State<Box<dyn Provisioner>>,
    worker: &State<UnboundedSender<WorkJob>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    provisioner.start_vm(id).await?;
    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

#[patch("/api/v1/vm/<id>/stop")]
async fn v1_stop_vm(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    provisioner: &State<Box<dyn Provisioner>>,
    worker: &State<UnboundedSender<WorkJob>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    provisioner.stop_vm(id).await?;
    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

#[patch("/api/v1/vm/<id>/restart")]
async fn v1_restart_vm(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    provisioner: &State<Box<dyn Provisioner>>,
    worker: &State<UnboundedSender<WorkJob>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    provisioner.restart_vm(id).await?;
    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

#[get("/api/v1/payment/<id>")]
async fn v1_get_payment(
    auth: Nip98Auth,
    db: &State<Box<dyn LNVpsDb>>,
    id: &str,
) -> ApiResult<VmPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let id = if let Ok(i) = hex::decode(id) {
        i
    } else {
        return ApiData::err("Invalid payment id");
    };
    let payment = db.get_vm_payment(&id).await?;
    let vm = db.get_vm(payment.vm_id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    ApiData::ok(payment)
}

#[derive(Deserialize)]
struct CreateVmRequest {
    template_id: u64,
    image_id: u64,
    ssh_key_id: u64,
}

impl From<CreateVmRequest> for VmTemplate {
    fn from(val: CreateVmRequest) -> Self {
        VmTemplate {
            id: val.template_id,
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
struct CreateSshKey {
    name: String,
    key_data: String,
}
