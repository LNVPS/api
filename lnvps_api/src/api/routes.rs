use crate::api::model::ApiVmStatus;
use crate::api::model::{
    AccountPatchRequest, ApiCompany, ApiCustomTemplateParams, ApiCustomVmOrder, ApiCustomVmRequest,
    ApiInvoiceItem, ApiPaymentInfo, ApiPaymentMethod, ApiTemplatesResponse, ApiVmHistory,
    ApiVmPayment, ApiVmUpgradeQuote, ApiVmUpgradeRequest, CreateSshKey, CreateVmRequest,
    VMPatchRequest, vm_to_status,
};
use crate::host::{FullVmInfo, TimeSeries, TimeSeriesData, get_host_client};
use crate::provisioner::{HostCapacityService, LNVpsProvisioner, PricingEngine};
use crate::settings::Settings;
use anyhow::{Result, bail};
use chrono::{DateTime, Datelike, Utc};
use futures::future::join_all;
use futures::{SinkExt, StreamExt};
use isocountry::CountryCode;
use lnurl::Tag;
use lnurl::pay::{LnURLPayInvoice, PayResponse};
use lnvps_api_common::{ApiCurrency, VmHistoryLogger};
use lnvps_api_common::{
    ApiData, ApiResult, ExchangeRateService, Nip98Auth, UpgradeConfig, VmStateCache, WorkJob,
};
use lnvps_api_common::{ApiPrice, ApiUserSshKey, ApiVmOsImage, ApiVmTemplate};
use lnvps_db::{
    LNVpsDb, PaymentMethod, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate, VmHostRegion,
};
use log::{error, info};
use nostr_sdk::{ToBech32, Url};
use rocket::http::ContentType;
use rocket::serde::json::Json;
use rocket::{Route, State, get, patch, post, routes};
use serde::Serialize;
use ssh_key::PublicKey;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;
use payments_rs::currency::{Currency, CurrencyAmount};
use tokio::sync::mpsc::{Sender, UnboundedSender};

pub fn routes() -> Vec<Route> {
    routes![
        openapi_spec,
        swagger_ui,
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
        v1_reinstall_vm,
        v1_patch_vm,
        v1_time_series,
        v1_custom_template_calc,
        v1_create_custom_vm_order,
        v1_get_payment_methods,
        v1_payment_history,
        v1_get_vm_history,
        v1_vm_upgrade_quote,
        v1_vm_upgrade,
        v1_terminal_proxy,
        v1_lnurlp,
        v1_renew_vm_lnurlp,
        v1_get_payment_invoice
    ]
}

/// Update user account
#[patch("/api/v1/account", format = "json", data = "<req>")]
async fn v1_patch_account(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<AccountPatchRequest>,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let mut user = db.get_user(uid).await?;

    // validate nwc string
    #[cfg(feature = "nostr-nwc")]
    if let Some(nwc) = &req.nwc_connection_string {
        match nwc::prelude::NostrWalletConnectURI::parse(nwc) {
            Ok(s) => {
                // test connection
                let client = nwc::NWC::new(s);
                let info = client.get_info().await?;
                if !info.methods.contains(&nwc::prelude::Method::PayInvoice) {
                    return ApiData::err("NWC connection must allow pay_invoice");
                }
            }
            Err(e) => return ApiData::err(&format!("Failed to parse NWC url: {}", e)),
        }
    }

    user.email = req.email.clone().map(|s| s.into());
    user.contact_nip17 = req.contact_nip17;
    user.contact_email = req.contact_email;
    user.country_code = req
        .country_code
        .as_ref()
        .and_then(|c| CountryCode::for_alpha3(c).ok())
        .map(|c| c.alpha3().to_string());
    user.billing_name = req.name.clone();
    user.billing_address_1 = req.address_1.clone();
    user.billing_address_2 = req.address_2.clone();
    user.billing_city = req.city.clone();
    user.billing_state = req.state.clone();
    user.billing_postcode = req.postcode.clone();
    user.billing_tax_id = req.tax_id.clone();
    user.nwc_connection_string = req.nwc_connection_string.clone().map(|s| s.into());

    db.update_user(&user).await?;
    ApiData::ok(())
}

/// Get user account detail
#[get("/api/v1/account")]
async fn v1_get_account(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<AccountPatchRequest> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let user = db.get_user(uid).await?;

    ApiData::ok(user.into())
}

/// List VMs belonging to user
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
#[patch("/api/v1/vm/<id>", data = "<data>", format = "json")]
async fn v1_patch_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    settings: &State<Settings>,
    vm_history: &State<Arc<VmHistoryLogger>>,
    id: u64,
    data: Json<VMPatchRequest>,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let old_vm = db.get_vm(id).await?;
    if old_vm.user_id != uid {
        return ApiData::err("VM doesnt belong to you");
    }

    let mut vm = old_vm.clone();
    let mut vm_config = false;
    let mut host_config = false;
    if let Some(k) = data.ssh_key_id {
        let ssh_key = db.get_user_ssh_key(k).await?;
        if ssh_key.user_id != uid {
            return ApiData::err("SSH key doesnt belong to you");
        }
        vm.ssh_key_id = ssh_key.id;
        vm_config = true;
        host_config = true;
    }

    if let Some(ptr) = &data.reverse_dns {
        let mut ips = db.list_vm_ip_assignments(vm.id).await?;
        for ip in ips.iter_mut() {
            ip.dns_reverse = Some(ptr.to_string());
            provisioner.update_reverse_ip_dns(ip).await?;
            db.update_vm_ip_assignment(ip).await?;
        }
    }

    // Handle auto-renewal setting change
    if let Some(auto_renewal) = data.auto_renewal_enabled {
        vm.auto_renewal_enabled = auto_renewal;
        vm_config = true;
    }

    if vm_config {
        db.update_vm(&vm).await?;
    }
    if host_config {
        let info = FullVmInfo::load(vm.id, (*db).clone()).await?;
        let host = db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &settings.provisioner)?;
        client.configure_vm(&info).await?;

        // Log VM configuration change
        let _ = vm_history
            .log_vm_configuration_changed(vm.id, Some(uid), &old_vm, &vm, None)
            .await;
    }

    ApiData::ok(())
}

/// List available VM OS images
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
#[get("/api/v1/vm/templates")]
async fn v1_list_vm_templates(
    db: &State<Arc<dyn LNVpsDb>>,
    rates: &State<Arc<dyn ExchangeRateService>>,
) -> ApiResult<ApiTemplatesResponse> {
    let hc = HostCapacityService::new((*db).clone());
    let templates = hc.list_available_vm_templates().await?;

    let cost_plans: HashSet<u64> = templates.iter().map(|t| t.cost_plan_id).collect();
    let regions: HashMap<u64, VmHostRegion> = db
        .list_host_region()
        .await?
        .into_iter()
        .map(|h| (h.id, h))
        .collect();

    let cost_plans: Vec<_> = cost_plans
        .into_iter()
        .map(|i| db.get_cost_plan(i))
        .collect();

    let cost_plans: HashMap<u64, lnvps_db::VmCostPlan> = join_all(cost_plans)
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
            let mut api_templates: Vec<ApiCustomTemplateParams> = custom_templates
                .into_iter()
                .filter_map(|t| {
                    let region = regions.get(&t.region_id)?;
                    Some(ApiCustomTemplateParams::from(
                        &t,
                        &custom_template_disks,
                        region,
                    ))
                })
                .collect();

            Some(hc.apply_host_capacity_limits(&mut api_templates).await?)
        },
    };
    rsp.expand_pricing(rates).await?;
    ApiData::ok(rsp)
}

/// Get a price for a custom order
#[post("/api/v1/vm/custom-template/price", data = "<req>", format = "json")]
async fn v1_custom_template_calc(
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<ApiCustomVmRequest>,
) -> ApiResult<ApiPrice> {
    // create a fake template from the request to generate the price
    let template: VmCustomTemplate = req.0.into();

    let price = PricingEngine::get_custom_vm_cost_amount(db, 0, &template).await?;
    ApiData::ok(ApiPrice {
        currency: price.currency.into(),
        amount: price.total(),
    })
}

/// Create a new VM order
///
/// After order is created please use /api/v1/vm/{id}/renew to pay for VM,
/// VM's are initially created in "expired" state
///
/// Unpaid VM orders will be deleted after 24hrs
#[post("/api/v1/vm/custom-template", data = "<req>", format = "json")]
async fn v1_create_custom_vm_order(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    vm_history: &State<Arc<VmHistoryLogger>>,
    req: Json<ApiCustomVmOrder>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    // create a fake template from the request to generate the order
    let template = req.0.spec.clone().into();

    let rsp = provisioner
        .provision_custom(uid, template, req.image_id, req.ssh_key_id, req.0.ref_code)
        .await?;

    // Log VM creation
    let _ = vm_history.log_vm_created(&rsp, Some(uid), None).await;

    ApiData::ok(vm_to_status(db, rsp, None).await?)
}

/// List user SSH keys
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
        key_data: pk.to_openssh()?.into(),
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
#[post("/api/v1/vm", data = "<req>", format = "json")]
async fn v1_create_vm_order(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    vm_history: &State<Arc<VmHistoryLogger>>,
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

    // Log VM creation
    let _ = vm_history.log_vm_created(&rsp, Some(uid), None).await;

    ApiData::ok(vm_to_status(db, rsp, None).await?)
}

/// Renew(Extend) a VM
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
    let user = db.get_user(uid).await?;

    // handle "nwc" payments automatically
    let rsp = if method == Some("nwc") && user.nwc_connection_string.is_some() {
        provisioner
            .auto_renew_via_nwc(id, user.nwc_connection_string.unwrap().as_str())
            .await?
    } else {
        provisioner
            .renew(
                id,
                method
                    .and_then(|m| PaymentMethod::from_str(m).ok())
                    .unwrap_or(PaymentMethod::Lightning),
            )
            .await?
    };

    ApiData::ok(rsp.into())
}

/// Extend a VM by LNURL payment
#[get("/api/v1/vm/<id>/renew-lnurlp?<amount>")]
async fn v1_renew_vm_lnurlp(
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    id: u64,
    amount: u64,
) -> Result<Json<LnURLPayInvoice>, &'static str> {
    let vm = db.get_vm(id).await.map_err(|_e| "VM not found")?;
    if vm.deleted {
        return Err("VM not found");
    }
    if amount < 1000 {
        return Err("Amount must be greater than 1000");
    }

    let rsp = provisioner
        .renew_amount(
            id,
            CurrencyAmount::millisats(amount),
            PaymentMethod::Lightning,
        )
        .await
        .map_err(|_| "Error generating invoice")?;

    // external_data is pr for lightning payment method
    Ok(Json(LnURLPayInvoice::new(rsp.external_data.into())))
}

/// LNURL ad-hoc extend vm
#[get("/.well-known/lnurlp/<id>")]
async fn v1_lnurlp(
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    id: u64,
) -> Result<Json<PayResponse>, &'static str> {
    let vm = db.get_vm(id).await.map_err(|_e| "VM not found")?;
    if vm.deleted {
        return Err("VM not found");
    }

    let meta = vec![vec!["text/plain".to_string(), format!("Extend VM {}", id)]];
    let rsp = PayResponse {
        callback: Url::parse(&settings.public_url)
            .map_err(|_| "Invalid public url")?
            .join(&format!("/api/v1/vm/{}/renew-lnurlp", id))
            .map_err(|_| "Could not get callback url")?
            .to_string(),
        max_sendable: 1_000_000_000,
        min_sendable: 1_000, // TODO: calc min by using 1s extend time
        tag: Tag::PayRequest,
        metadata: serde_json::to_string(&meta).map_err(|_e| "Failed to serialize metadata")?,
        comment_allowed: None,
        allows_nostr: None,
        nostr_pubkey: None,
    };
    Ok(Json(rsp))
}

/// Start a VM
#[patch("/api/v1/vm/<id>/start")]
async fn v1_start_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    vm_history: &State<Arc<VmHistoryLogger>>,
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

    // Log VM start
    let _ = vm_history.log_vm_started(id, Some(uid), None).await;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

/// Stop a VM
#[patch("/api/v1/vm/<id>/stop")]
async fn v1_stop_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    vm_history: &State<Arc<VmHistoryLogger>>,
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

    // Log VM stop
    let _ = vm_history.log_vm_stopped(id, Some(uid), None).await;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

/// Restart a VM
#[patch("/api/v1/vm/<id>/restart")]
async fn v1_restart_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    vm_history: &State<Arc<VmHistoryLogger>>,
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

    // Log VM restart
    let _ = vm_history.log_vm_restarted(id, Some(uid), None).await;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

/// Re-install a VM
#[patch("/api/v1/vm/<id>/re-install")]
async fn v1_reinstall_vm(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    worker: &State<UnboundedSender<WorkJob>>,
    vm_history: &State<Arc<VmHistoryLogger>>,
    id: u64,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if uid != vm.user_id {
        return ApiData::err("VM does not belong to you");
    }

    let old_image_id = vm.image_id;
    let host = db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &settings.provisioner)?;
    let info = FullVmInfo::load(vm.id, (*db).clone()).await?;
    client.reinstall_vm(&info).await?;

    // Log VM reinstall (assuming same image ID for now)
    let _ = vm_history
        .log_vm_reinstalled(id, Some(uid), old_image_id, old_image_id, None)
        .await;

    worker.send(WorkJob::CheckVm { vm_id: id })?;
    ApiData::ok(())
}

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

#[get("/api/v1/vm/<id>/console?<auth>")]
async fn v1_terminal_proxy(
    auth: &str,
    db: &State<Arc<dyn LNVpsDb>>,
    settings: &State<Settings>,
    id: u64,
    ws: ws::WebSocket,
) -> Result<ws::Channel<'static>, &'static str> {
    return Err("Disabled");
    let auth = Nip98Auth::from_base64(auth).map_err(|e| "Missing or invalid auth param")?;
    if auth
        .check(&format!("/api/v1/vm/{id}/console"), "GET")
        .is_err()
    {
        return Err("Invalid auth event");
    }
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await.map_err(|_| "Insert failed")?;
    let vm = db.get_vm(id).await.map_err(|_| "VM not found")?;
    if uid != vm.user_id {
        return Err("VM does not belong to you");
    }

    let host = db
        .get_host(vm.host_id)
        .await
        .map_err(|_| "VM host not found")?;
    let client =
        get_host_client(&host, &settings.provisioner).map_err(|_| "Failed to get host client")?;

    let mut ws_upstream = client.connect_terminal(&vm).await.map_err(|e| {
        error!("Failed to start terminal proxy: {}", e);
        "Failed to open terminal proxy"
    })?;
    let ws = ws.config(Default::default());
    Ok(ws.channel(move |mut stream| {
        use ws::*;

        Box::pin(async move {
            async fn process_client<E>(
                msg: Result<Message, E>,
                ws_upstream: &mut Sender<Vec<u8>>,
            ) -> Result<()>
            where
                E: Display,
            {
                match msg {
                    Ok(m) => {
                        let m_up = match m {
                            Message::Text(t) => t.as_bytes().to_vec(),
                            _ => panic!("todo"),
                        };
                        if let Err(e) = ws_upstream.send(m_up).await {
                            bail!("Failed to send msg to upstream: {}", e);
                        }
                    }
                    Err(e) => {
                        bail!("Failed to read from client: {}", e);
                    }
                }
                Ok(())
            }

            async fn process_upstream<E>(
                msg: Result<Vec<u8>, E>,
                tx_client: &mut stream::DuplexStream,
            ) -> Result<()>
            where
                E: Display,
            {
                match msg {
                    Ok(m) => {
                        let down = String::from_utf8_lossy(&m).into_owned();
                        let m_down = Message::Text(down);
                        if let Err(e) = tx_client.send(m_down).await {
                            bail!("Failed to msg to client: {}", e);
                        }
                    }
                    Err(e) => {
                        bail!("Failed to read from upstream: {}", e);
                    }
                }
                Ok(())
            }

            loop {
                tokio::select! {
                    Some(msg) = stream.next() => {
                        if let Err(e) = process_client(msg, &mut ws_upstream.tx).await {
                            error!("{}", e);
                            break;
                        }
                    },
                    Some(r) = ws_upstream.rx.recv() => {
                        let msg: Result<Vec<u8>, anyhow::Error> = Ok(r);
                        if let Err(e) = process_upstream(msg, &mut stream).await {
                            error!("{}", e);
                            break;
                        }
                    }
                }
            }
            info!("Websocket closed");
            Ok(())
        })
    }))
}

#[get("/api/v1/payment/methods")]
async fn v1_get_payment_methods(settings: &State<Settings>) -> ApiResult<Vec<ApiPaymentInfo>> {
    let mut ret = vec![ApiPaymentInfo {
        name: ApiPaymentMethod::Lightning,
        metadata: HashMap::new(),
        currencies: vec![ApiCurrency::BTC],
    }];
    #[cfg(feature = "nostr-nwc")]
    ret.push(ApiPaymentInfo {
        name: ApiPaymentMethod::NWC,
        metadata: HashMap::new(),
        currencies: vec![ApiCurrency::BTC],
    });
    #[cfg(feature = "revolut")]
    if let Some(r) = &settings.revolut {
        ret.push(ApiPaymentInfo {
            name: ApiPaymentMethod::Revolut,
            metadata: HashMap::from([("pubkey".to_string(), r.public_key.to_string())]),
            currencies: vec![ApiCurrency::EUR, ApiCurrency::USD],
        })
    }

    ApiData::ok(ret)
}

/// Get payment status (for polling)
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

/// Print payment invoice
#[get("/api/v1/payment/<id>/invoice?<auth>")]
async fn v1_get_payment_invoice(
    db: &State<Arc<dyn LNVpsDb>>,
    id: &str,
    auth: &str,
) -> Result<(ContentType, Vec<u8>), &'static str> {
    let auth = Nip98Auth::from_base64(auth).map_err(|e| "Missing or invalid auth param")?;
    if auth
        .check(&format!("/api/v1/payment/{id}/invoice"), "GET")
        .is_err()
    {
        return Err("Invalid auth event");
    }
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await.map_err(|_| "Insert failed")?;
    let id = if let Ok(i) = hex::decode(id) {
        i
    } else {
        return Err("Invalid payment id");
    };

    let payment = db
        .get_vm_payment(&id)
        .await
        .map_err(|_| "Payment not found")?;
    let vm = db.get_vm(payment.vm_id).await.map_err(|_| "VM not found")?;
    if vm.user_id != uid {
        return Err("VM does not belong to you");
    }

    if !payment.is_paid {
        return Err("Payment is not paid, can't generate invoice");
    }

    #[derive(Serialize)]
    struct PaymentInfo {
        year: i32,
        current_date: DateTime<Utc>,
        vm: ApiVmStatus,
        payment: ApiVmPayment,
        invoice_item: ApiInvoiceItem,
        user: AccountPatchRequest,
        npub: String,
        total: u64,
        total_formatted: String,
        company: Option<ApiCompany>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upgrade_details: Option<UpgradeDetails>,
    }

    #[derive(Serialize)]
    struct UpgradeDetails {
        #[serde(skip_serializing_if = "Option::is_none")]
        cpu_upgrade: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_upgrade: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disk_upgrade: Option<u64>,
    }

    let host = db
        .get_host(vm.host_id)
        .await
        .map_err(|_| "Host not found")?;
    let region = db
        .get_host_region(host.region_id)
        .await
        .map_err(|_| "Region not found")?;
    let company = if let Some(c) = region.company_id {
        Some(db.get_company(c).await.map_err(|_| "Company not found")?)
    } else {
        None
    };
    let user = db.get_user(uid).await.map_err(|_| "User not found")?;
    #[cfg(debug_assertions)]
    let template =
        mustache::compile_path("lnvps_api/invoice.html").map_err(|_| "Invalid template")?;
    #[cfg(not(debug_assertions))]
    let template = mustache::compile_str(include_str!("../../invoice.html"))
        .map_err(|_| "Invalid template")?;

    // Parse upgrade details if this is an upgrade payment
    let upgrade_details = if payment.payment_type == lnvps_db::PaymentType::Upgrade {
        payment
            .upgrade_params
            .as_ref()
            .and_then(|s| serde_json::from_str::<UpgradeConfig>(s).ok())
            .map(|c| UpgradeDetails {
                cpu_upgrade: c.new_cpu,
                memory_upgrade: c.new_memory.map(|m| m / crate::GB),
                disk_upgrade: c.new_disk.map(|m| m / crate::GB),
            })
    } else {
        None
    };

    let now = Utc::now();
    let invoice_item = ApiInvoiceItem::from_vm_payment(&payment)
        .map_err(|_| "Failed to create formatted invoice item")?;

    let mut html = Cursor::new(Vec::new());
    template
        .render(
            &mut html,
            &PaymentInfo {
                year: now.year(),
                current_date: now,
                vm: vm_to_status(db, vm, None)
                    .await
                    .map_err(|_| "Failed to get VM state")?,
                total: payment.amount + payment.tax,
                total_formatted: CurrencyAmount::from_u64(
                    payment.currency.parse().map_err(|_| "Invalid currency")?,
                    payment.amount + payment.tax,
                )
                .to_string(),
                payment: payment.into(),
                invoice_item,
                npub: nostr_sdk::PublicKey::from_slice(&user.pubkey)
                    .map_err(|_| "Invalid pubkey")?
                    .to_bech32()
                    .unwrap(),
                user: user.into(),
                company: company.map(|c| c.into()),
                upgrade_details,
            },
        )
        .map_err(|_| "Failed to generate invoice")?;
    Ok((ContentType::HTML, html.into_inner()))
}

/// List payment history of a VM
#[get("/api/v1/vm/<id>/payments")]
async fn v1_payment_history(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<Vec<ApiVmPayment>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    let payments = db.list_vm_payment(id).await?;
    ApiData::ok(payments.into_iter().map(|i| i.into()).collect())
}

/// List action history of a VM
#[get("/api/v1/vm/<id>/history?<limit>&<offset>")]
async fn v1_get_vm_history(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiResult<Vec<ApiVmHistory>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    let history = match (limit, offset) {
        (Some(limit), Some(offset)) => db.list_vm_history_paginated(id, limit, offset).await?,
        _ => db.list_vm_history(id).await?,
    };

    ApiData::ok(
        history
            .into_iter()
            .map(|h| ApiVmHistory::from_with_owner(h, vm.user_id))
            .collect(),
    )
}

/// Get a quote for upgrading a VM
#[post(
    "/api/v1/vm/<id>/upgrade/quote?<method>",
    data = "<req>",
    format = "json"
)]
async fn v1_vm_upgrade_quote(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    id: u64,
    req: Json<ApiVmUpgradeRequest>,
    method: Option<&str>,
) -> ApiResult<ApiVmUpgradeQuote> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    // Create UpgradeConfig from request
    let cfg = UpgradeConfig {
        new_cpu: req.cpu,
        new_memory: req.memory,
        new_disk: req.disk,
    };

    // Calculate the upgrade cost and new renewal cost
    match provisioner
        .calculate_upgrade_cost(
            id,
            &cfg,
            method
                .and_then(|m| PaymentMethod::from_str(m).ok())
                .unwrap_or(PaymentMethod::Lightning),
        )
        .await
    {
        Ok(quote) => ApiData::ok(ApiVmUpgradeQuote {
            cost_difference: quote.upgrade.amount.into(),
            new_renewal_cost: quote.renewal.amount.into(),
            discount: quote.discount.amount.into(),
        }),
        Err(e) => ApiData::err(e.to_string().as_str()),
    }
}

/// Upgrade a VM (requires payment first)
#[post("/api/v1/vm/<id>/upgrade?<method>", data = "<req>", format = "json")]
async fn v1_vm_upgrade(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    provisioner: &State<Arc<LNVpsProvisioner>>,
    id: u64,
    req: Json<ApiVmUpgradeRequest>,
    method: Option<&str>,
) -> ApiResult<ApiVmPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;
    let vm = db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    // Create UpgradeConfig from request
    let cfg = UpgradeConfig {
        new_cpu: req.cpu,
        new_memory: req.memory,
        new_disk: req.disk,
    };

    // Create upgrade payment
    let payment = provisioner
        .create_upgrade_payment(
            id,
            &cfg,
            method
                .and_then(|m| PaymentMethod::from_str(m).ok())
                .unwrap_or(PaymentMethod::Lightning),
        )
        .await?;

    // Note: The actual upgrade happens after payment is confirmed
    ApiData::ok(payment.into())
}

/// Serve OpenAPI 3.0 specification
#[get("/api/v1/openapi.json")]
fn openapi_spec() -> (ContentType, &'static str) {
    (ContentType::JSON, include_str!("openapi.json"))
}

/// Redirect to Swagger UI
#[get("/swagger")]
fn swagger_ui() -> (ContentType, &'static str) {
    (
        ContentType::HTML,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LNVPS API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
<script>
  window.onload = () => {
    window.ui = SwaggerUIBundle({
      url: '/api/v1/openapi.json',
      dom_id: '#swagger-ui',
    });
  };
</script>
</body>
</html>"#,
    )
}
