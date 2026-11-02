use crate::api::model::{ApiCredit, ApiPrice, ApiVmPayment};
use crate::api::{PaymentMethodQuery, RouterState};
use crate::subscription::VmAddonChange;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiError, ApiResult, Nip98Auth};
use lnvps_db::{PaymentMethod, Vm, VmAddonKind};
use payments_rs::currency::CurrencyAmount;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/vm/{id}/addons",
            get(v1_list_vm_addons).put(v1_change_vm_addon),
        )
        .route("/api/v1/vm/{id}/addons/quote", post(v1_quote_vm_addon))
}

#[derive(Serialize)]
pub struct ApiVmAddon {
    pub kind: VmAddonKind,
    pub quantity: u32,
    pub max_quantity: u32,
    pub monthly_price: ApiPrice,
    pub interval_price: ApiPrice,
}

#[derive(Deserialize)]
pub struct ApiVmAddonRequest {
    pub kind: VmAddonKind,
    pub quantity: u32,
}

#[derive(Serialize)]
pub struct ApiVmAddonQuote {
    pub kind: VmAddonKind,
    pub current: u32,
    pub quantity: u32,
    pub interval_price: ApiPrice,
    pub due_now: ApiPrice,
    pub tax: ApiPrice,
    pub processing_fee: ApiPrice,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit: Option<ApiCredit>,
}

#[derive(Serialize)]
pub struct ApiVmAddonChange {
    pub applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<ApiVmPayment>,
}

async fn owned_vm(auth: &Nip98Auth, this: &RouterState, id: u64) -> Result<(u64, Vm), ApiError> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }
    if vm.deleted {
        return Err(ApiError::not_found("VM not found"));
    }
    Ok((uid, vm))
}

async fn v1_list_vm_addons(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<ApiVmAddon>> {
    let (_, vm) = owned_vm(&auth, &this, id).await?;
    let pe = this.sub_handler.pricing_engine();
    let subscription = this
        .db
        .get_subscription_by_line_item_id(vm.subscription_line_item_id)
        .await?;
    let held = this.db.list_vm_addons(vm.id).await?;
    let mut out = Vec::new();
    for kind in [VmAddonKind::Snapshot] {
        let Ok(price) = pe.vm_addon_price(vm.id, kind).await else {
            continue;
        };
        let quantity = held
            .iter()
            .find(|a| a.kind == kind)
            .map(|a| a.quantity)
            .unwrap_or(0);
        let interval = pe
            .vm_addon_interval_amount(&price, 1, &subscription)
            .await?;
        out.push(ApiVmAddon {
            kind,
            quantity,
            max_quantity: price.max_quantity,
            monthly_price: CurrencyAmount::from_u64(
                price
                    .currency
                    .parse()
                    .map_err(|_| ApiError::new("Invalid currency"))?,
                price.monthly_amount,
            )
            .into(),
            interval_price: CurrencyAmount::from_u64(
                subscription
                    .currency
                    .parse()
                    .map_err(|_| ApiError::new("Invalid currency"))?,
                interval,
            )
            .into(),
        });
    }
    ApiData::ok(out)
}

async fn v1_quote_vm_addon(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiVmAddonRequest>,
) -> ApiResult<ApiVmAddonQuote> {
    let (_, vm) = owned_vm(&auth, &this, id).await?;
    let method = q
        .method
        .and_then(|m| PaymentMethod::from_str(&m).ok())
        .unwrap_or(PaymentMethod::Lightning);
    let quote = this
        .sub_handler
        .pricing_engine()
        .calculate_vm_addon_cost(vm.id, req.kind, req.quantity, method)
        .await
        .map_err(ApiError::new)?;
    let currency = quote.charge.amount.currency();
    let (processing_fee, credit) = if quote.is_free() {
        (0, None)
    } else {
        this.sub_handler
            .quote_vm_upgrade_credit(
                vm.id,
                method,
                quote.charge.amount.value(),
                quote.tax.amount,
                quote.processing_fee,
                currency,
            )
            .await?
    };
    ApiData::ok(ApiVmAddonQuote {
        kind: req.kind,
        current: quote.current,
        quantity: quote.quantity,
        interval_price: quote.interval_amount.into(),
        due_now: quote.charge.amount.into(),
        tax: CurrencyAmount::from_u64(currency, quote.tax.amount).into(),
        processing_fee: CurrencyAmount::from_u64(currency, processing_fee).into(),
        credit: credit.map(|c| ApiCredit {
            amount: c.amount,
            currency: c.currency.to_string(),
        }),
    })
}

async fn v1_change_vm_addon(
    auth: Nip98Auth,
    client: lnvps_api_common::ClientInfo,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiVmAddonRequest>,
) -> ApiResult<ApiVmAddonChange> {
    let (uid, vm) = owned_vm(&auth, &this, id).await?;
    let (method, mode) = crate::api::resolve_payment_mode(&this, uid, &q).await?;
    let change = this
        .sub_handler
        .change_vm_addon(vm.id, req.kind, req.quantity, method, mode)
        .await
        .map_err(ApiError::new)?;
    match change {
        VmAddonChange::Applied => ApiData::ok(ApiVmAddonChange {
            applied: true,
            payment: None,
        }),
        VmAddonChange::Payment(payment) => {
            crate::api::record_swap_client(
                &this,
                uid,
                payment.payment_method,
                &payment.id,
                payment.external_data.as_str(),
                &client,
            )
            .await;
            let credit = crate::api::credit_line(&this.db, &payment).await;
            let mut out = ApiVmPayment::from_subscription_payment(*payment, vm.id)?;
            out.credit = credit;
            ApiData::ok(ApiVmAddonChange {
                applied: out.is_paid,
                payment: Some(out),
            })
        }
    }
}
