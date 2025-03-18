use crate::api::model::{
    AccountPatchRequest, ApiCustomTemplateParams, ApiCustomVmOrder, ApiCustomVmRequest,
    ApiPaymentInfo, ApiPaymentMethod, ApiPrice, ApiTemplatesResponse, ApiUserSshKey,
    ApiVmIpAssignment, ApiVmOsImage, ApiVmPayment, ApiVmStatus, ApiVmTemplate, CreateSshKey,
    CreateVmRequest, VMPatchRequest,
};
use crate::exchange::{Currency, ExchangeRateService};
use crate::host::{get_host_client, FullVmInfo, TimeSeries, TimeSeriesData};
use crate::nip98::Nip98Auth;
use crate::provisioner::{HostCapacityService, LNVpsProvisioner, PricingEngine};
use crate::settings::Settings;
use crate::status::{VmState, VmStateCache};
use crate::worker::WorkJob;
use anyhow::Result;
use futures::future::join_all;
use isocountry::CountryCode;
use lnvps_db::{
    IpRange, LNVpsDb, PaymentMethod, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
};
use nostr::util::hex;
use rocket::serde::json::Json;
use rocket::{get, patch, post, Responder, Route, State};
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::okapi::openapi3::Responses;
use rocket_okapi::response::OpenApiResponderInner;
use rocket_okapi::{openapi, openapi_get_routes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

pub fn routes() -> Vec<Route> {
    openapi_get_routes![
        v1_get_account,
        v1_patch_account,
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
        v1_restart_vm,
        v1_patch_vm,
        v1_time_series,
        v1_custom_template_calc,
        v1_create_custom_vm_order,
        v1_get_payment_methods
    ]
}

type ApiResult<T> = Result<Json<ApiData<T>>, ApiError>;

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, Deserialize, JsonSchema, Responder)]
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

impl OpenApiResponderInner for ApiError {
    fn responses(_gen: &mut OpenApiGenerator) -> rocket_okapi::Result<Responses> {
        Ok(Responses::default())
    }
}

/// Update user account
#[openapi(tag = "Account")]
#[patch("/api/v1/account", format = "json", data = "<req>")]
async fn v1_patch_account(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<AccountPatchRequest>,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let mut user = db.get_user(uid).await?;

    user.email = req.email.clone();
    user.contact_nip17 = req.contact_nip17;
    user.contact_email = req.contact_email;
    user.country_code = req
        .country_code
        .as_ref()
        .and_then(|c| CountryCode::for_alpha3(c).ok())
        .map(|c| c.alpha3().to_string());

    db.update_user(&user).await?;
    ApiData::ok(())
}

/// Get user account detail
#[openapi(tag = "Account")]
#[get("/api/v1/account")]
async fn v1_get_account(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<AccountPatchRequest> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let user = db.get_user(uid).await?;

    ApiData::ok(AccountPatchRequest {
        email: user.email,
        contact_nip17: user.contact_nip17,
        contact_email: user.contact_email,
        country_code: user.country_code,
    })
}

async fn vm_to_status(
    db: &Arc<dyn LNVpsDb>,
    vm: lnvps_db::Vm,
    state: Option<VmState>,
) -> Result<ApiVmStatus> {
    let image = db.get_os_image(vm.image_id).await?;
    let ssh_key = db.get_user_ssh_key(vm.ssh_key_id).await?;
    let ips = db.list_vm_ip_assignments(vm.id).await?;
    let ip_range_ids: HashSet<u64> = ips.iter().map(|i| i.ip_range_id).collect();
    let ip_ranges: Vec<_> = ip_range_ids.iter().map(|i| db.get_ip_range(*i)).collect();
    let ip_ranges: HashMap<u64, IpRange> = join_all(ip_ranges)
        .await
        .into_iter()
        .filter_map(Result::ok)
        .map(|i| (i.id, i))
        .collect();

    let template = ApiVmTemplate::from_vm(db, &vm).await?;
    Ok(ApiVmStatus {
        id: vm.id,
        created: vm.created,
        expires: vm.expires,
        mac_address: vm.mac_address,
        image: image.into(),
        template,
        ssh_key: ssh_key.into(),
        status: state.unwrap_or_default(),
        ip_assignments: ips
            .into_iter()
            .map(|i| {
                let range = ip_ranges
                    .get(&i.ip_range_id)
                    .expect("ip range id not found");
                ApiVmIpAssignment::from(&i, range)
            })
            .collect(),
    })
}

/// List VMs belonging to user
#[openapi(tag = "VM")]
#[get("/api/v1/vm")]
async fn v1_list_vms(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_state: &State<VmStateCache>,
) -> ApiResult<Vec<ApiVmStatus>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vms = db.list_user_vms(uid).await?;
    let mut ret = vec![];
    for vm in vms {
        let vm_id = vm.id;
        ret.push(vm_to_status(db, vm, vm_state.get_state(vm_id).await).await?);
    }

    ApiData::ok(ret)
}

/// Get status of a VM
#[openapi(tag = "VM")]
#[get("/api/v1/vm/<id>")]
async fn v1_get_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_state: &State<VmStateCache>,
    id: u64,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM doesnt belong to you");
    }
    ApiData::ok(vm_to_status(db, vm, vm_state.get_state(id).await).await?)
}

/// Update a VM config
#[openapi(tag = "VM")]
#[patch("/api/v1/vm/<id>", data = "<data>", format = "json")]
async fn v1_patch_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    settings: &State<Settings>,
    id: u64,
    data: Json<VMPatchRequest>,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let mut vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM doesnt belong to you");
    }

    let mut vm_config = false;
    if let Some(k) = data.ssh_key_id {
        let ssh_key = db.get_user_ssh_key(k).await?;
        if ssh_key.user_id != uid {
            return ApiData::err("SSH key doesnt belong to you");
        }
        vm.ssh_key_id = ssh_key.id;
        vm_config = true;
    }

    if let Some(ptr) = &data.reverse_dns {
        let mut ips = db.list_vm_ip_assignments(vm.id).await?;
        for ip in ips.iter_mut() {
            ip.dns_reverse = Some(ptr.to_string());
            provisioner.update_reverse_ip_dns(ip).await?;
            db.update_vm_ip_assignment(ip).await?;
        }
    }

    if vm_config {
        db.update_vm(&vm).await?;
        let info = FullVmInfo::load(vm.id, (*db).clone()).await?;
        let host = db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &settings.provisioner)?;
        client.configure_vm(&info).await?;
    }

    ApiData::ok(())
}

/// List available VM OS images
#[openapi(tag = "Image")]
#[get("/api/v1/image")]
async fn v1_list_vm_images(db: &State<Arc<dyn LNVpsDb>>) -> ApiResult<Vec<ApiVmOsImage>> {
    let images = db.list_os_image().await?;
    let ret = images
        .into_iter()
        .filter(|i| i.enabled)
        .map(|i| i.into())
        .collect();
    ApiData::ok(ret)
}

/// List available VM templates (Offers)
#[openapi(tag = "VM")]
#[get("/api/v1/vm/templates")]
async fn v1_list_vm_templates(
    db: &State<Arc<dyn LNVpsDb>>,
    rates: &State<Arc<dyn ExchangeRateService>>,
) -> ApiResult<ApiTemplatesResponse> {
    let hc = HostCapacityService::new((*db).clone());
    let templates = hc.list_available_vm_templates().await?;

    let cost_plans: HashSet<u64> = templates.iter().map(|t| t.cost_plan_id).collect();
    let regions: HashSet<u64> = templates.iter().map(|t| t.region_id).collect();

    let cost_plans: Vec<_> = cost_plans
        .into_iter()
        .map(|i| db.get_cost_plan(i))
        .collect();
    let regions: Vec<_> = regions.into_iter().map(|r| db.get_host_region(r)).collect();

    let cost_plans: HashMap<u64, lnvps_db::VmCostPlan> = join_all(cost_plans)
        .await
        .into_iter()
        .filter_map(|c| {
            let c = c.ok()?;
            Some((c.id, c))
        })
        .collect();
    let regions: HashMap<u64, lnvps_db::VmHostRegion> = join_all(regions)
        .await
        .into_iter()
        .filter_map(|c| {
            let c = c.ok()?;
            Some((c.id, c))
        })
        .collect();

    let ret = templates
        .iter()
        .filter_map(|i| {
            let cp = cost_plans.get(&i.cost_plan_id)?;
            let hr = regions.get(&i.region_id)?;
            ApiVmTemplate::from_standard_data(i, cp, hr).ok()
        })
        .collect();
    let custom_templates: Vec<VmCustomPricing> =
        join_all(regions.keys().map(|k| db.list_custom_pricing(*k)))
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .collect();
    let custom_template_disks: Vec<VmCustomPricingDisk> = join_all(
        custom_templates
            .iter()
            .map(|t| db.list_custom_pricing_disk(t.id)),
    )
    .await
    .into_iter()
    .filter_map(|r| r.ok())
    .flatten()
    .collect();

    let mut rsp = ApiTemplatesResponse {
        templates: ret,
        custom_template: if custom_templates.is_empty() {
            None
        } else {
            const GB: u64 = 1024 * 1024 * 1024;
            let max_cpu = templates.iter().map(|t| t.cpu).max().unwrap_or(8);
            let max_memory = templates.iter().map(|t| t.memory).max().unwrap_or(GB * 2);
            let max_disk = templates
                .iter()
                .map(|t| t.disk_size)
                .max()
                .unwrap_or(GB * 5);
            Some(
                custom_templates
                    .into_iter()
                    .filter_map(|t| {
                        let region = regions.get(&t.region_id)?;
                        ApiCustomTemplateParams::from(
                            &t,
                            &custom_template_disks,
                            region,
                            max_cpu,
                            max_memory,
                            max_disk,
                        )
                        .ok()
                    })
                    .collect(),
            )
        },
    };
    rsp.expand_pricing(rates).await?;
    ApiData::ok(rsp)
}

/// Get a price for a custom order
#[openapi(tag = "VM")]
#[post("/api/v1/vm/custom-template/price", data = "<req>", format = "json")]
async fn v1_custom_template_calc(
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<ApiCustomVmRequest>,
) -> ApiResult<ApiPrice> {
    // create a fake template from the request to generate the price
    let template: VmCustomTemplate = req.0.into();

    let price = PricingEngine::get_custom_vm_cost_amount(db, 0, &template).await?;
    ApiData::ok(ApiPrice {
        currency: price.currency,
        amount: price.total(),
    })
}

/// Create a new VM order
///
/// After order is created please use /api/v1/vm/{id}/renew to pay for VM,
/// VM's are initially created in "expired" state
///
/// Unpaid VM orders will be deleted after 24hrs
#[openapi(tag = "VM")]
#[post("/api/v1/vm/custom-template", data = "<req>", format = "json")]
async fn v1_create_custom_vm_order(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    req: Json<ApiCustomVmOrder>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    // create a fake template from the request to generate the order
    let template = req.0.spec.clone().into();

    let rsp = provisioner
        .provision_custom(uid, template, req.image_id, req.ssh_key_id, req.0.ref_code)
        .await?;
    ApiData::ok(vm_to_status(db, rsp, None).await?)
}

/// List user SSH keys
#[openapi(tag = "Account")]
#[get("/api/v1/ssh-key")]
async fn v1_list_ssh_keys(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<Vec<ApiUserSshKey>> {
    let uid = db.upsert_user(&auth.event.pubkey.to_bytes()).await?;
    let ret = db
        .list_user_ssh_key(uid)
        .await?
        .into_iter()
        .map(|i| i.into())
        .collect();
    ApiData::ok(ret)
}

/// Add new SSH key to account
#[openapi(tag = "Account")]
#[post("/api/v1/ssh-key", data = "<req>", format = "json")]
async fn v1_add_ssh_key(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<CreateSshKey>,
) -> ApiResult<ApiUserSshKey> {
    let uid = db.upsert_user(&auth.event.pubkey.to_bytes()).await?;

    let pk: PublicKey = req.key_data.parse()?;
    let key_name = if !req.name.is_empty() {
        &req.name
    } else {
        pk.comment()
    };
    let mut new_key = lnvps_db::UserSshKey {
        name: key_name.to_string(),
        user_id: uid,
        key_data: pk.to_openssh()?,
        ..Default::default()
    };
    let key_id = db.insert_user_ssh_key(&new_key).await?;
    new_key.id = key_id;

    ApiData::ok(new_key.into())
}

/// Create a new VM order
///
/// After order is created please use /api/v1/vm/{id}/renew to pay for VM,
/// VM's are initially created in "expired" state
///
/// Unpaid VM orders will be deleted after 24hrs
#[openapi(tag = "VM")]
#[post("/api/v1/vm", data = "<req>", format = "json")]
async fn v1_create_vm_order(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    req: Json<CreateVmRequest>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let req = req.0;
    let rsp = provisioner
        .provision(
            uid,
            req.template_id,
            req.image_id,
            req.ssh_key_id,
            req.ref_code,
        )
        .await?;
    ApiData::ok(vm_to_status(db, rsp, None).await?)
}

/// Renew(Extend) a VM
#[openapi(tag = "VM")]
#[get("/api/v1/vm/<id>/renew?<method>")]
async fn v1_renew_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    id: u64,
    method: Option<&str>,
) -> ApiResult<ApiVmPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    let rsp = provisioner
        .renew(
            id,
            method
                .and_then(|m| PaymentMethod::from_str(m).ok())
                .unwrap_or(PaymentMethod::Lightning),
        )
        .await?;
    ApiData::ok(rsp.into())
}

/// Start a VM
#[openapi(tag = "VM")]
#[patch("/api/v1/vm/<id>/start")]
async fn v1_start_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }
    let host = db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &settings.provisioner)?;
    client.start_vm(&vm).await?;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

/// Stop a VM
#[openapi(tag = "VM")]
#[patch("/api/v1/vm/<id>/stop")]
async fn v1_stop_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    let host = db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &settings.provisioner)?;
    client.stop_vm(&vm).await?;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

/// Restart a VM
#[openapi(tag = "VM")]
#[patch("/api/v1/vm/<id>/restart")]
async fn v1_restart_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    let host = db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &settings.provisioner)?;
    client.stop_vm(&vm).await?;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

#[openapi(tag = "VM")]
#[get("/api/v1/vm/<id>/time-series")]
async fn v1_time_series(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    id: u64,
) -> ApiResult<Vec<TimeSeriesData>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    let host = db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &settings.provisioner)?;
    ApiData::ok(client.get_time_series_data(&vm, TimeSeries::Hourly).await?)
}

#[openapi(tag = "Payment")]
#[get("/api/v1/payment/methods")]
async fn v1_get_payment_methods(settings: &State<Settings>) -> ApiResult<Vec<ApiPaymentInfo>> {
    let mut ret = vec![ApiPaymentInfo {
        name: ApiPaymentMethod::Lightning,
        metadata: HashMap::new(),
        currencies: vec![Currency::BTC],
    }];
    #[cfg(feature = "revolut")]
    if let Some(r) = &settings.revolut {
        ret.push(ApiPaymentInfo {
            name: ApiPaymentMethod::Revolut,
            metadata: HashMap::from([("pubkey".to_string(), r.public_key.to_string())]),
            currencies: vec![Currency::EUR, Currency::USD],
        })
    }

    ApiData::ok(ret)
}

/// Get payment status (for polling)
#[openapi(tag = "Payment")]
#[get("/api/v1/payment/<id>")]
async fn v1_get_payment(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: &str,
) -> ApiResult<ApiVmPayment> {
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

    ApiData::ok(payment.into())
}
