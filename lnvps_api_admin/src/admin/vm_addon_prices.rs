use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult,
    deserialize_from_str_optional,
};
use lnvps_db::{AdminAction, AdminResource, VmAddonKind, VmAddonPrice};
use payments_rs::currency::Currency;

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vm_addon_prices",
            get(admin_list_vm_addon_prices).post(admin_create_vm_addon_price),
        )
        .route(
            "/api/admin/v1/vm_addon_prices/{id}",
            get(admin_get_vm_addon_price)
                .patch(admin_update_vm_addon_price)
                .delete(admin_delete_vm_addon_price),
        )
}

#[derive(serde::Serialize, Debug)]
pub struct AdminVmAddonPrice {
    pub id: u64,
    pub region_id: u64,
    pub kind: VmAddonKind,
    pub currency: String,
    pub monthly_amount: u64,
    pub max_quantity: u32,
    pub enabled: bool,
    pub created: DateTime<Utc>,
}

impl From<VmAddonPrice> for AdminVmAddonPrice {
    fn from(p: VmAddonPrice) -> Self {
        Self {
            id: p.id,
            region_id: p.region_id,
            kind: p.kind,
            currency: p.currency,
            monthly_amount: p.monthly_amount,
            max_quantity: p.max_quantity,
            enabled: p.enabled,
            created: p.created,
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ListQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
}

#[derive(serde::Deserialize, Debug)]
pub struct CreateVmAddonPriceRequest {
    pub region_id: u64,
    pub kind: VmAddonKind,
    pub currency: String,
    pub monthly_amount: u64,
    pub max_quantity: u32,
    pub enabled: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub struct UpdateVmAddonPriceRequest {
    pub currency: Option<String>,
    pub monthly_amount: Option<u64>,
    pub max_quantity: Option<u32>,
    pub enabled: Option<bool>,
}

fn parse_price_currency(currency: &str) -> Result<String, ApiError> {
    let c: Currency = currency
        .trim()
        .parse()
        .map_err(|_| ApiError::bad_request(format!("Unknown currency {currency}")))?;
    if c.is_crypto() && c != Currency::BTC {
        return Err(ApiError::bad_request(format!(
            "{c} cannot be used as a list price"
        )));
    }
    Ok(c.to_string())
}

async fn admin_list_vm_addon_prices(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<ListQuery>,
) -> ApiPaginatedResult<AdminVmAddonPrice> {
    auth.require_permission(AdminResource::VmAddonPrice, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this.db.list_vm_addon_prices(limit, offset).await?;
    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

async fn admin_get_vm_addon_price(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminVmAddonPrice> {
    auth.require_permission(AdminResource::VmAddonPrice, AdminAction::View)?;
    ApiData::ok(this.db.get_vm_addon_price(id).await?.into())
}

async fn admin_create_vm_addon_price(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateVmAddonPriceRequest>,
) -> ApiResult<AdminVmAddonPrice> {
    auth.require_permission(AdminResource::VmAddonPrice, AdminAction::Create)?;
    this.db.get_host_region(req.region_id).await?;
    if this
        .db
        .get_vm_addon_price_for_region(req.region_id, req.kind)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request(format!(
            "Region {} already has a {} price",
            req.region_id, req.kind
        )));
    }
    let id = this
        .db
        .insert_vm_addon_price(&VmAddonPrice {
            id: 0,
            region_id: req.region_id,
            kind: req.kind,
            currency: parse_price_currency(&req.currency)?,
            monthly_amount: req.monthly_amount,
            max_quantity: req.max_quantity,
            enabled: req.enabled.unwrap_or(true),
            created: Utc::now(),
        })
        .await?;
    ApiData::ok(this.db.get_vm_addon_price(id).await?.into())
}

async fn admin_update_vm_addon_price(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateVmAddonPriceRequest>,
) -> ApiResult<AdminVmAddonPrice> {
    auth.require_permission(AdminResource::VmAddonPrice, AdminAction::Update)?;
    let mut price = this.db.get_vm_addon_price(id).await?;
    if let Some(c) = req.currency {
        price.currency = parse_price_currency(&c)?;
    }
    if let Some(a) = req.monthly_amount {
        price.monthly_amount = a;
    }
    if let Some(m) = req.max_quantity {
        price.max_quantity = m;
    }
    if let Some(e) = req.enabled {
        price.enabled = e;
    }
    this.db.update_vm_addon_price(&price).await?;
    ApiData::ok(this.db.get_vm_addon_price(id).await?.into())
}

async fn admin_delete_vm_addon_price(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::VmAddonPrice, AdminAction::Delete)?;
    this.db.delete_vm_addon_price(id).await?;
    ApiData::ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_price_currency;

    #[test]
    fn list_prices_take_fiat_milli_fiat_or_btc() {
        assert_eq!(parse_price_currency("eur").unwrap(), "EUR");
        assert_eq!(parse_price_currency("MEUR").unwrap(), "MEUR");
        assert_eq!(parse_price_currency("BTC").unwrap(), "BTC");
        assert!(parse_price_currency("XMR").is_err());
        assert!(parse_price_currency("nope").is_err());
    }
}
