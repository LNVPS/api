use crate::api::model::ApiVmStatus;
use crate::api::model::{
    AccountPatchRequest, ApiCompany, ApiCustomTemplateParams, ApiCustomVmOrder, ApiCustomVmRequest,
    ApiInvoiceItem, ApiPaymentInfo, ApiPaymentMethod, ApiTemplatesResponse, ApiVmHistory,
    ApiVmPayment, ApiVmUpgradeQuote, ApiVmUpgradeRequest, CreateSshKey, CreateVmRequest,
    VMPatchRequest, vm_to_status,
};
use crate::api::{AmountQuery, AuthQuery, PaymentMethodQuery, RouterState};
use crate::host::{FullVmInfo, TimeSeries, TimeSeriesData, get_host_client};
use crate::provisioner::{HostCapacityService, PricingEngine};
use anyhow::Result;
use axum::extract::ws::WebSocket;
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::response::Html;
use axum::routing::{any, get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Datelike, Utc};
use futures::future::join_all;
use isocountry::CountryCode;
use lnurl::Tag;
use lnurl::pay::{LnURLPayInvoice, PayResponse};
use lnvps_api_common::{ApiCurrency, ApiError, PageQuery};
use lnvps_api_common::{ApiData, ApiResult, Nip98Auth, UpgradeConfig, WorkJob};
use lnvps_api_common::{ApiPrice, ApiUserSshKey, ApiVmOsImage, ApiVmTemplate};
use lnvps_db::{
    PaymentMethod, Vm, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate, VmHostRegion,
};
use log::error;
use nostr_sdk::{ToBech32, Url};
use payments_rs::currency::CurrencyAmount;
use serde::Serialize;
use ssh_key::PublicKey;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::str::FromStr;

pub fn routes() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/account",
            get(v1_get_account).patch(v1_patch_account),
        )
        .route("/api/v1/vm", get(v1_list_vms))
        .route("/api/v1/vm/{id}", get(v1_get_vm).patch(v1_patch_vm))
        .route("/api/v1/image", get(v1_list_vm_images))
        .route("/api/v1/vm/templates", get(v1_list_vm_templates))
        .route(
            "/api/v1/vm/custom-template/price",
            post(v1_custom_template_calc),
        )
        .route(
            "/api/v1/vm/custom-template",
            post(v1_create_custom_vm_order),
        )
        .route(
            "/api/v1/ssh-key",
            get(v1_list_ssh_keys).post(v1_add_ssh_key),
        )
        .route("/api/v1/vm", post(v1_create_vm_order))
        .route("/api/v1/vm/{id}/renew", get(v1_renew_vm))
        .route("/api/v1/vm/{id}/renew-lnurlp", get(v1_renew_vm_lnurlp))
        .route("/.well-known/lnurlp/<id>", get(v1_lnurlp))
        .route("/api/v1/vm/{id}/start", patch(v1_start_vm))
        .route("/api/v1/vm/{id}/stop", patch(v1_stop_vm))
        .route("/api/v1/vm/{id}/restart", patch(v1_restart_vm))
        .route("/api/v1/vm/{id}/re-install", patch(v1_reinstall_vm))
        .route("/api/v1/vm/{id}/time-series", get(v1_time_series))
        .route(
            "/api/v1/vm/{id}/console",
            any(
                async move |ws: WebSocketUpgrade,
                            Path(id): Path<u64>,
                            Query(q): Query<AuthQuery>,
                            State(this): State<RouterState>| {
                    ws.on_upgrade(async move |s| {
                        if let Err(e) = v1_terminal_proxy(id, q.auth, this, s).await {
                            error!("Failed to proxy terminal proxy: {}", e);
                        }
                    })
                },
            ),
        )
        .route("/api/v1/payment/methods", get(v1_get_payment_methods))
        .route("/api/v1/payment/{id}", get(v1_get_payment))
        .route("/api/v1/payment/{id}/invoice", get(v1_get_payment_invoice))
        .route("/api/v1/vm/{id}/payments", get(v1_payment_history))
        .route("/api/v1/vm/{id}/history", get(v1_get_vm_history))
        .route("/api/v1/vm/{id}/upgrade/quote", post(v1_vm_upgrade_quote))
        .route("/api/v1/vm/{id}/upgrade", post(v1_vm_upgrade))
}

/// Update user account
async fn v1_patch_account(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    req: Json<AccountPatchRequest>,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    // validate nwc string
    #[cfg(feature = "nostr-nwc")]
    if let Some(Some(nwc)) = &req.nwc_connection_string {
        match nwc::prelude::NostrWalletConnectURI::parse(nwc) {
            Ok(s) => {
                // test connection
                let client = nwc::NWC::new(s);
                let info = client.get_info().await
                    .map_err(|e| ApiError::new(format!("Failed to connect to NWC: {}", e)))?;
                if !info.methods.contains(&nwc::prelude::Method::PayInvoice) {
                    return ApiData::err("NWC connection must allow pay_invoice");
                }
            }
            Err(e) => return ApiData::err(&format!("Failed to parse NWC url: {}", e)),
        }
    }

    // Update fields only if they are present in the request
    if let Some(email) = &req.email {
        user.email = email.clone().map(|s| s.into());
    }
    user.contact_nip17 = req.contact_nip17;
    user.contact_email = req.contact_email;
    if let Some(country_code) = &req.country_code {
        user.country_code = country_code
            .as_ref()
            .and_then(|c| CountryCode::for_alpha3(c).ok())
            .map(|c| c.alpha3().to_string());
    }
    if let Some(name) = &req.name {
        user.billing_name = name.clone();
    }
    if let Some(address_1) = &req.address_1 {
        user.billing_address_1 = address_1.clone();
    }
    if let Some(address_2) = &req.address_2 {
        user.billing_address_2 = address_2.clone();
    }
    if let Some(city) = &req.city {
        user.billing_city = city.clone();
    }
    if let Some(state) = &req.state {
        user.billing_state = state.clone();
    }
    if let Some(postcode) = &req.postcode {
        user.billing_postcode = postcode.clone();
    }
    if let Some(tax_id) = &req.tax_id {
        user.billing_tax_id = tax_id.clone();
    }
    if let Some(nwc_connection_string) = &req.nwc_connection_string {
        user.nwc_connection_string = nwc_connection_string.clone().map(|s| s.into());
    }

    this.db.update_user(&user).await?;
    ApiData::ok(())
}

/// Get user account detail
async fn v1_get_account(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<AccountPatchRequest> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let user = this.db.get_user(uid).await?;

    ApiData::ok(user.into())
}

/// List VMs belonging to user
async fn v1_list_vms(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiVmStatus>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vms = this.db.list_user_vms(uid).await?;
    let mut ret = vec![];
    for vm in vms {
        let vm_id = vm.id;
        ret.push(vm_to_status(&this.db, vm, this.state.get_state(vm_id).await).await?);
    }

    ApiData::ok(ret)
}

/// Get status of a VM
async fn v1_get_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiVmStatus> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;
    ApiData::ok(vm_to_status(&this.db, vm, this.state.get_state(id).await).await?)
}

/// Update a VM config
async fn v1_patch_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(data): Json<VMPatchRequest>,
) -> ApiResult<()> {
    let (uid, old_vm) = get_user_vm(&auth, &this, id).await?;

    let mut vm = old_vm.clone();
    let mut vm_config = false;
    let mut host_config = false;
    if let Some(k) = data.ssh_key_id {
        let ssh_key = this.db.get_user_ssh_key(k).await?;
        if ssh_key.user_id != uid {
            return ApiData::err("SSH key doesnt belong to you");
        }
        vm.ssh_key_id = ssh_key.id;
        vm_config = true;
        host_config = true;
    }

    if let Some(ptr) = &data.reverse_dns {
        let mut ips = this.db.list_vm_ip_assignments(vm.id).await?;
        for ip in ips.iter_mut() {
            ip.dns_reverse = Some(ptr.to_string());
            this.provisioner.network.update_reverse_ip_dns(ip).await?;
            this.db.update_vm_ip_assignment(ip).await?;
        }
    }

    // Handle auto-renewal setting change
    if let Some(auto_renewal) = data.auto_renewal_enabled {
        vm.auto_renewal_enabled = auto_renewal;
        vm_config = true;
    }

    if vm_config {
        this.db.update_vm(&vm).await?;
    }
    if host_config {
        let info = FullVmInfo::load(vm.id, this.db.clone()).await?;
        let host = this.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &this.settings.provisioner)?;
        client.configure_vm(&info).await?;

        // Log VM configuration change
        let _ = this
            .history
            .log_vm_configuration_changed(vm.id, Some(uid), &old_vm, &vm, None)
            .await;
    }

    ApiData::ok(())
}

/// List available VM OS images
async fn v1_list_vm_images(State(this): State<RouterState>) -> ApiResult<Vec<ApiVmOsImage>> {
    let images = this.db.list_os_image().await?;
    let ret = images
        .into_iter()
        .filter(|i| i.enabled)
        .map(|i| i.into())
        .collect();
    ApiData::ok(ret)
}

/// List available VM templates (Offers)
async fn v1_list_vm_templates(State(this): State<RouterState>) -> ApiResult<ApiTemplatesResponse> {
    let hc = HostCapacityService::new(this.db.clone());
    let templates = hc.list_available_vm_templates().await?;

    let cost_plans: HashSet<u64> = templates.iter().map(|t| t.cost_plan_id).collect();
    let regions: HashMap<u64, VmHostRegion> = this
        .db
        .list_host_region()
        .await?
        .into_iter()
        .map(|h| (h.id, h))
        .collect();

    let cost_plans: Vec<_> = cost_plans
        .into_iter()
        .map(|i| this.db.get_cost_plan(i))
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
        join_all(regions.keys().map(|k| this.db.list_custom_pricing(*k)))
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .collect();
    let custom_template_disks: Vec<VmCustomPricingDisk> = join_all(
        custom_templates
            .iter()
            .map(|t| this.db.list_custom_pricing_disk(t.id)),
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
            let api_templates: Vec<ApiCustomTemplateParams> = custom_templates
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

            Some(hc.apply_host_capacity_limits(&api_templates).await?)
        },
    };
    rsp.expand_pricing(&this.rates).await?;
    ApiData::ok(rsp)
}

/// Get a price for a custom order
async fn v1_custom_template_calc(
    State(this): State<RouterState>,
    Json(req): Json<ApiCustomVmRequest>,
) -> ApiResult<ApiPrice> {
    // create a fake template from the request to generate the price
    let template: VmCustomTemplate = req.into();

    let price = PricingEngine::get_custom_vm_cost_amount(&this.db, 0, &template).await?;
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
async fn v1_create_custom_vm_order(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<ApiCustomVmOrder>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    // create a fake template from the request to generate the order
    let template = req.spec.clone().into();

    let rsp = this
        .provisioner
        .provision_custom(uid, template, req.image_id, req.ssh_key_id, req.ref_code)
        .await?;

    // Log VM creation
    this.history
        .log_vm_created(&rsp, Some(uid), None)
        .await
        .ok();

    ApiData::ok(vm_to_status(&this.db, rsp, None).await?)
}

/// List user SSH keys
async fn v1_list_ssh_keys(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiUserSshKey>> {
    let uid = this.db.upsert_user(&auth.event.pubkey.to_bytes()).await?;
    let ret = this
        .db
        .list_user_ssh_key(uid)
        .await?
        .into_iter()
        .map(|i| i.into())
        .collect();
    ApiData::ok(ret)
}

/// Add new SSH key to account
async fn v1_add_ssh_key(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<CreateSshKey>,
) -> ApiResult<ApiUserSshKey> {
    let uid = this.db.upsert_user(&auth.event.pubkey.to_bytes()).await?;

    let pk: PublicKey = req.key_data.parse()
        .map_err(|_| ApiError::new("Invalid SSH public key format"))?;
    let key_name = if !req.name.is_empty() {
        &req.name
    } else {
        pk.comment()
    };
    let mut new_key = lnvps_db::UserSshKey {
        name: key_name.to_string(),
        user_id: uid,
        key_data: pk.to_openssh()
            .map_err(|_| ApiError::new("Failed to encode SSH key"))?
            .into(),
        ..Default::default()
    };
    let key_id = this.db.insert_user_ssh_key(&new_key).await?;
    new_key.id = key_id;

    ApiData::ok(new_key.into())
}

/// Create a new VM order
///
/// After order is created please use /api/v1/vm/{id}/renew to pay for VM,
/// VM's are initially created in "expired" state
///
/// Unpaid VM orders will be deleted after 24hrs
async fn v1_create_vm_order(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<CreateVmRequest>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let rsp = this
        .provisioner
        .provision(
            uid,
            req.template_id,
            req.image_id,
            req.ssh_key_id,
            req.ref_code,
        )
        .await?;

    // Log VM creation
    this.history
        .log_vm_created(&rsp, Some(uid), None)
        .await
        .ok();

    ApiData::ok(vm_to_status(&this.db, rsp, None).await?)
}

/// Renew(Extend) a VM
async fn v1_renew_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
) -> ApiResult<ApiVmPayment> {
    let (uid, _) = get_user_vm(&auth, &this, id).await?;
    let user = this.db.get_user(uid).await?;
    let intervals = q.intervals.unwrap_or(1);

    // handle "nwc" payments automatically
    let rsp = if q.method.as_deref() == Some("nwc") && user.nwc_connection_string.is_some() {
        this.provisioner
            .auto_renew_via_nwc(id, user.nwc_connection_string.unwrap().as_str())
            .await?
    } else {
        this.provisioner
            .renew_intervals(
                id,
                q.method
                    .and_then(|m| PaymentMethod::from_str(&m).ok())
                    .unwrap_or(PaymentMethod::Lightning),
                intervals,
            )
            .await?
    };

    ApiData::ok(rsp.into())
}

/// Extend a VM by LNURL payment
async fn v1_renew_vm_lnurlp(
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<AmountQuery>,
) -> Result<Json<LnURLPayInvoice>, &'static str> {
    let vm = this.db.get_vm(id).await.map_err(|_e| "VM not found")?;
    if vm.deleted {
        return Err("VM not found");
    }
    if q.amount < 1000 {
        return Err("Amount must be greater than 1000");
    }

    let rsp = this
        .provisioner
        .renew_amount(
            id,
            CurrencyAmount::millisats(q.amount),
            PaymentMethod::Lightning,
        )
        .await
        .map_err(|_| "Error generating invoice")?;

    // external_data is pr for lightning payment method
    Ok(Json(LnURLPayInvoice::new(rsp.external_data.into())))
}

/// LNURL ad-hoc extend vm
async fn v1_lnurlp(
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> Result<Json<PayResponse>, &'static str> {
    let vm = this.db.get_vm(id).await.map_err(|_e| "VM not found")?;
    if vm.deleted {
        return Err("VM not found");
    }

    let meta = vec![vec!["text/plain".to_string(), format!("Extend VM {}", id)]];
    let rsp = PayResponse {
        callback: Url::parse(&this.settings.public_url)
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
async fn v1_start_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    client.start_vm(&vm).await?;

    // Log VM start
    this.history.log_vm_started(id, Some(uid), None).await.ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

/// Stop a VM
async fn v1_stop_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    client.stop_vm(&vm).await?;

    // Log VM stop
    this.history.log_vm_stopped(id, Some(uid), None).await.ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

/// Restart a VM
async fn v1_restart_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    client.stop_vm(&vm).await?;

    // Log VM restart
    this.history
        .log_vm_restarted(id, Some(uid), None)
        .await
        .ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

/// Re-install a VM
async fn v1_reinstall_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let old_image_id = vm.image_id;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    let info = FullVmInfo::load(vm.id, this.db.clone()).await?;
    client.reinstall_vm(&info).await?;

    // Log VM reinstall (assuming same image ID for now)
    this.history
        .log_vm_reinstalled(id, Some(uid), old_image_id, old_image_id, None)
        .await
        .ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

async fn v1_time_series(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<TimeSeriesData>> {
    let (_, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    ApiData::ok(client.get_time_series_data(&vm, TimeSeries::Hourly).await?)
}

#[allow(unused)]
async fn v1_terminal_proxy(
    id: u64,
    auth: String,
    this: RouterState,
    mut ws: WebSocket,
) -> Result<(), &'static str> {
    return Err("Disabled");
    let auth = Nip98Auth::from_base64(&auth).map_err(|e| "Missing or invalid auth param")?;
    if auth
        .check(&format!("/api/v1/vm/{id}/console"), "GET")
        .is_err()
    {
        return Err("Invalid auth event");
    }
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this
        .db
        .upsert_user(&pubkey)
        .await
        .map_err(|_| "Insert failed")?;
    let vm = this.db.get_vm(id).await.map_err(|_| "VM not found")?;
    if uid != vm.user_id {
        return Err("VM does not belong to you");
    }

    let host = this
        .db
        .get_host(vm.host_id)
        .await
        .map_err(|_| "VM host not found")?;
    let client = get_host_client(&host, &this.settings.provisioner)
        .map_err(|_| "Failed to get host client")?;

    let mut ws_upstream = client.connect_terminal(&vm).await.map_err(|e| {
        error!("Failed to start terminal proxy: {}", e);
        "Failed to open terminal proxy"
    })?;

    todo!()
}

async fn v1_get_payment_methods(State(this): State<RouterState>) -> ApiResult<Vec<ApiPaymentInfo>> {
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
    if let Some(r) = &this.settings.revolut {
        ret.push(ApiPaymentInfo {
            name: ApiPaymentMethod::Revolut,
            metadata: HashMap::from([("pubkey".to_string(), r.public_key.to_string())]),
            currencies: vec![ApiCurrency::EUR, ApiCurrency::USD],
        })
    }

    ApiData::ok(ret)
}

/// Get payment status (for polling)
async fn v1_get_payment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<ApiVmPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let id = if let Ok(i) = hex::decode(&id) {
        i
    } else {
        return ApiData::err("Invalid payment id");
    };

    let payment = this.db.get_vm_payment(&id).await?;
    let vm = this.db.get_vm(payment.vm_id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    ApiData::ok(payment.into())
}

/// Print payment invoice
async fn v1_get_payment_invoice(
    State(this): State<RouterState>,
    Path(id): Path<String>,
    Query(q): Query<AuthQuery>,
) -> Result<Html<String>, &'static str> {
    let auth = Nip98Auth::from_base64(&q.auth).map_err(|_e| "Missing or invalid auth param")?;
    if auth
        .check(&format!("/api/v1/payment/{id}/invoice"), "GET")
        .is_err()
    {
        return Err("Invalid auth event");
    }
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this
        .db
        .upsert_user(&pubkey)
        .await
        .map_err(|_| "Insert failed")?;
    let id = if let Ok(i) = hex::decode(id) {
        i
    } else {
        return Err("Invalid payment id");
    };

    let payment = this
        .db
        .get_vm_payment(&id)
        .await
        .map_err(|_| "Payment not found")?;
    let vm = this
        .db
        .get_vm(payment.vm_id)
        .await
        .map_err(|_| "VM not found")?;
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

    let host = this
        .db
        .get_host(vm.host_id)
        .await
        .map_err(|_| "Host not found")?;
    let region = this
        .db
        .get_host_region(host.region_id)
        .await
        .map_err(|_| "Region not found")?;
    let company = if let Some(c) = region.company_id {
        Some(
            this.db
                .get_company(c)
                .await
                .map_err(|_| "Company not found")?,
        )
    } else {
        None
    };
    let user = this.db.get_user(uid).await.map_err(|_| "User not found")?;
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
                vm: vm_to_status(&this.db, vm, None)
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
    Ok(Html(String::from_utf8(html.into_inner()).unwrap()))
}

/// List payment history of a VM
async fn v1_payment_history(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<ApiVmPayment>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    let payments = this.db.list_vm_payment(id).await?;
    ApiData::ok(payments.into_iter().map(|i| i.into()).collect())
}

/// List action history of a VM
async fn v1_get_vm_history(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Vec<ApiVmHistory>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return ApiData::err("VM does not belong to you");
    }

    let history = match (q.limit, q.offset) {
        (Some(limit), Some(offset)) => this.db.list_vm_history_paginated(id, limit, offset).await?,
        _ => this.db.list_vm_history(id).await?,
    };

    ApiData::ok(
        history
            .into_iter()
            .map(|h| ApiVmHistory::from_with_owner(h, vm.user_id))
            .collect(),
    )
}

/// Get a quote for upgrading a VM
async fn v1_vm_upgrade_quote(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiVmUpgradeRequest>,
) -> ApiResult<ApiVmUpgradeQuote> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
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
    match this
        .provisioner
        .calculate_upgrade_cost(
            id,
            &cfg,
            q.method
                .and_then(|m| PaymentMethod::from_str(&m).ok())
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
async fn v1_vm_upgrade(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiVmUpgradeRequest>,
) -> ApiResult<ApiVmPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
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
    let payment = this
        .provisioner
        .create_upgrade_payment(
            id,
            &cfg,
            q.method
                .and_then(|m| PaymentMethod::from_str(&m).ok())
                .unwrap_or(PaymentMethod::Lightning),
        )
        .await?;

    // Note: The actual upgrade happens after payment is confirmed
    ApiData::ok(payment.into())
}

async fn get_user_vm(auth: &Nip98Auth, this: &RouterState, id: u64) -> Result<(u64, Vm), ApiError> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if uid != vm.user_id {
        return Err(ApiError::new("VM does not belong to you"));
    }
    Ok((uid, vm))
}
