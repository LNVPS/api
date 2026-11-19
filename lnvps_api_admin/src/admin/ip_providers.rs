use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, parse_gateway,
};
use lnvps_db::{
    AdminAction, AdminResource, IpProvider, IpProviderKind, IpProviderRegion, IpWhenNoIp, LNVpsDb,
};
use payments_rs::currency::Currency;
use serde::{Deserialize, Serialize};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/ip_providers",
            get(admin_list_ip_providers).post(admin_create_ip_provider),
        )
        .route(
            "/api/admin/v1/ip_providers/{id}",
            get(admin_get_ip_provider)
                .patch(admin_update_ip_provider)
                .delete(admin_delete_ip_provider),
        )
        .route(
            "/api/admin/v1/ip_providers/{id}/regions",
            get(admin_list_ip_provider_regions).post(admin_create_ip_provider_region),
        )
        .route(
            "/api/admin/v1/ip_providers/{id}/regions/{rule_id}",
            get(admin_get_ip_provider_region)
                .patch(admin_update_ip_provider_region)
                .delete(admin_delete_ip_provider_region),
        )
}

#[derive(Serialize, Debug)]
pub struct AdminIpProvider {
    pub id: u64,
    pub name: String,
    pub kind: IpProviderKind,
    pub enabled: bool,
    pub url: String,
    pub has_token: bool,
    pub subsidiary: String,
    pub rir: String,
    pub gateway: String,
    pub access_policy_id: Option<u64>,
    pub approval_required: bool,
    pub monthly_spend_cap: u64,
    pub currency: String,
    pub enable_ranges_on_delivery: bool,
}

impl From<IpProvider> for AdminIpProvider {
    fn from(p: IpProvider) -> Self {
        Self {
            id: p.id,
            name: p.name,
            kind: p.kind,
            enabled: p.enabled,
            url: p.url,
            has_token: !p.token.as_str().is_empty(),
            subsidiary: p.subsidiary,
            rir: p.rir,
            gateway: p.gateway,
            access_policy_id: p.access_policy_id,
            approval_required: p.approval_required,
            monthly_spend_cap: p.monthly_spend_cap,
            currency: p.currency,
            enable_ranges_on_delivery: p.enable_ranges_on_delivery,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct AdminIpProviderRegion {
    pub id: u64,
    pub provider_id: u64,
    pub region_id: u64,
    pub country: Option<String>,
    pub destination: Option<String>,
    pub prefix_len: u16,
    pub quantity: u32,
    pub auto_threshold: Option<u64>,
    pub enabled: bool,
    pub when_no_ip: IpWhenNoIp,
    pub sell_without_capacity: bool,
    pub wait_refund_hours: u32,
}

impl From<IpProviderRegion> for AdminIpProviderRegion {
    fn from(r: IpProviderRegion) -> Self {
        Self {
            id: r.id,
            provider_id: r.provider_id,
            region_id: r.region_id,
            country: r.country,
            destination: r.destination,
            prefix_len: r.prefix_len,
            quantity: r.quantity,
            auto_threshold: r.auto_threshold,
            enabled: r.enabled,
            when_no_ip: r.when_no_ip,
            sell_without_capacity: r.sell_without_capacity,
            wait_refund_hours: r.wait_refund_hours,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateIpProviderRequest {
    pub name: String,
    pub kind: IpProviderKind,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub token: String,
    pub subsidiary: Option<String>,
    pub rir: Option<String>,
    pub gateway: String,
    pub access_policy_id: Option<u64>,
    pub approval_required: Option<bool>,
    pub monthly_spend_cap: u64,
    pub currency: String,
    pub enable_ranges_on_delivery: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
pub struct UpdateIpProviderRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub url: Option<String>,
    pub token: Option<String>,
    pub subsidiary: Option<String>,
    pub rir: Option<String>,
    pub gateway: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub access_policy_id: Option<Option<u64>>,
    pub approval_required: Option<bool>,
    pub monthly_spend_cap: Option<u64>,
    pub currency: Option<String>,
    pub enable_ranges_on_delivery: Option<bool>,
}

fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(d)?))
}

#[derive(Deserialize, Debug)]
pub struct CreateIpProviderRegionRequest {
    pub region_id: u64,
    pub country: Option<String>,
    pub destination: Option<String>,
    pub prefix_len: Option<u16>,
    pub quantity: Option<u32>,
    pub auto_threshold: Option<u64>,
    pub enabled: Option<bool>,
    pub when_no_ip: Option<IpWhenNoIp>,
    pub sell_without_capacity: Option<bool>,
    pub wait_refund_hours: Option<u32>,
}

#[derive(Deserialize, Debug, Default)]
pub struct UpdateIpProviderRegionRequest {
    #[serde(default, deserialize_with = "double_option")]
    pub country: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub destination: Option<Option<String>>,
    pub prefix_len: Option<u16>,
    pub quantity: Option<u32>,
    #[serde(default, deserialize_with = "double_option")]
    pub auto_threshold: Option<Option<u64>>,
    pub enabled: Option<bool>,
    pub when_no_ip: Option<IpWhenNoIp>,
    pub sell_without_capacity: Option<bool>,
    pub wait_refund_hours: Option<u32>,
}

pub fn validate_name(name: &str) -> Result<String, ApiError> {
    let n = name.trim();
    if n.is_empty() {
        return Err(ApiError::bad_request("Name cannot be empty"));
    }
    Ok(n.to_string())
}

pub fn validate_currency(c: &str) -> Result<String, ApiError> {
    let parsed: Currency = c
        .trim()
        .parse()
        .map_err(|_| ApiError::bad_request(format!("Unknown currency {c}")))?;
    if parsed.is_crypto() {
        return Err(ApiError::bad_request(
            "Spend cap must be in a fiat currency",
        ));
    }
    Ok(parsed.to_string())
}

pub fn validate_rir(rir: &str) -> Result<String, ApiError> {
    let r = rir.trim().to_lowercase();
    if r == "ripe" || r == "arin" {
        Ok(r)
    } else {
        Err(ApiError::bad_request("rir must be ripe or arin"))
    }
}

pub fn validate_gateway(g: &str) -> Result<String, ApiError> {
    parse_gateway(g.trim())
        .map(|_| g.trim().to_string())
        .map_err(|_| ApiError::bad_request("Invalid gateway, expected an IP address"))
}

pub fn validate_rule(prefix_len: u16, quantity: u32) -> Result<(), ApiError> {
    if prefix_len != 32 && !(24..=30).contains(&prefix_len) {
        return Err(ApiError::bad_request(
            "prefix_len must be 32 or between 24 and 30",
        ));
    }
    if quantity == 0 {
        return Err(ApiError::bad_request("quantity must be at least 1"));
    }
    if prefix_len != 32 && quantity != 1 {
        return Err(ApiError::bad_request(
            "address blocks are ordered one at a time, quantity must be 1",
        ));
    }
    Ok(())
}

async fn validate_order_and_wait(db: &dyn LNVpsDb, provider_id: u64) -> Result<(), ApiError> {
    let p = db.get_ip_provider(provider_id).await?;
    if p.gateway.trim().is_empty() {
        return Err(ApiError::bad_request(
            "order_and_wait needs the provider to have a gateway for the ranges it registers",
        ));
    }
    Ok(())
}

fn clean(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

async fn check_policy(db: &dyn LNVpsDb, id: Option<u64>) -> Result<(), ApiError> {
    if let Some(id) = id {
        db.get_access_policy(id)
            .await
            .map_err(|_| ApiError::bad_request(format!("Access policy {id} not found")))?;
    }
    Ok(())
}

async fn admin_list_ip_providers(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiPaginatedResult<AdminIpProvider> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    let rows: Vec<AdminIpProvider> = this
        .db
        .list_ip_providers()
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let total = rows.len() as u64;
    ApiPaginatedData::ok(rows, total, total, 0)
}

async fn admin_get_ip_provider(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminIpProvider> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    ApiData::ok(this.db.get_ip_provider(id).await?.into())
}

async fn admin_create_ip_provider(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateIpProviderRequest>,
) -> ApiResult<AdminIpProvider> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Create)?;
    let name = validate_name(&req.name)?;
    if req.kind != IpProviderKind::Mock && req.token.trim().is_empty() {
        return Err(ApiError::bad_request("Token cannot be empty"));
    }
    if this.db.get_ip_provider_by_name(&name).await?.is_some() {
        return Err(ApiError::bad_request(format!(
            "An IP provider named {name} already exists"
        )));
    }
    check_policy(this.db.as_ref(), req.access_policy_id).await?;
    let p = IpProvider {
        id: 0,
        name,
        kind: req.kind,
        enabled: req.enabled.unwrap_or(false),
        url: req.url.trim().to_string(),
        token: req.token.as_str().into(),
        subsidiary: req.subsidiary.unwrap_or_else(|| "IE".to_string()),
        rir: validate_rir(req.rir.as_deref().unwrap_or("ripe"))?,
        gateway: validate_gateway(&req.gateway)?,
        access_policy_id: req.access_policy_id,
        approval_required: req.approval_required.unwrap_or(true),
        monthly_spend_cap: req.monthly_spend_cap,
        currency: validate_currency(&req.currency)?,
        enable_ranges_on_delivery: req.enable_ranges_on_delivery.unwrap_or(true),
    };
    let id = this.db.insert_ip_provider(&p).await?;
    ApiData::ok(this.db.get_ip_provider(id).await?.into())
}

async fn admin_update_ip_provider(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateIpProviderRequest>,
) -> ApiResult<AdminIpProvider> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Update)?;
    let mut p = this.db.get_ip_provider(id).await?;
    if let Some(name) = &req.name {
        let name = validate_name(name)?;
        if let Some(other) = this.db.get_ip_provider_by_name(&name).await? {
            if other.id != id {
                return Err(ApiError::bad_request(format!(
                    "An IP provider named {name} already exists"
                )));
            }
        }
        p.name = name;
    }
    if let Some(v) = req.enabled {
        p.enabled = v;
    }
    if let Some(v) = &req.url {
        p.url = v.trim().to_string();
    }
    if let Some(t) = &req.token {
        if t.trim().is_empty() {
            return Err(ApiError::bad_request("Token cannot be empty"));
        }
        p.token = t.as_str().into();
    }
    if let Some(v) = req.subsidiary {
        p.subsidiary = v;
    }
    if let Some(v) = &req.rir {
        p.rir = validate_rir(v)?;
    }
    if let Some(v) = &req.gateway {
        p.gateway = validate_gateway(v)?;
    }
    if let Some(v) = req.access_policy_id {
        check_policy(this.db.as_ref(), v).await?;
        p.access_policy_id = v;
    }
    if let Some(v) = req.approval_required {
        p.approval_required = v;
    }
    if let Some(v) = req.monthly_spend_cap {
        p.monthly_spend_cap = v;
    }
    if let Some(v) = &req.currency {
        p.currency = validate_currency(v)?;
    }
    if let Some(v) = req.enable_ranges_on_delivery {
        p.enable_ranges_on_delivery = v;
    }
    this.db.update_ip_provider(&p).await?;
    ApiData::ok(this.db.get_ip_provider(id).await?.into())
}

async fn admin_delete_ip_provider(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Delete)?;
    this.db
        .delete_ip_provider(id)
        .await
        .map_err(|e| ApiError::conflict(e.to_string()))?;
    ApiData::ok(())
}

async fn admin_list_ip_provider_regions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<AdminIpProviderRegion>> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    this.db.get_ip_provider(id).await?;
    ApiData::ok(
        this.db
            .list_ip_provider_regions(Some(id), None)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    )
}

async fn rule_of(
    db: &dyn LNVpsDb,
    provider_id: u64,
    rule_id: u64,
) -> Result<IpProviderRegion, ApiError> {
    let rule = db.get_ip_provider_region(rule_id).await?;
    if rule.provider_id != provider_id {
        return Err(ApiError::not_found("Rule not found for this provider"));
    }
    Ok(rule)
}

async fn admin_get_ip_provider_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, rule_id)): Path<(u64, u64)>,
) -> ApiResult<AdminIpProviderRegion> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    ApiData::ok(rule_of(this.db.as_ref(), id, rule_id).await?.into())
}

async fn admin_create_ip_provider_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<CreateIpProviderRegionRequest>,
) -> ApiResult<AdminIpProviderRegion> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Create)?;
    this.db.get_ip_provider(id).await?;
    this.db
        .get_host_region(req.region_id)
        .await
        .map_err(|_| ApiError::bad_request(format!("Region {} not found", req.region_id)))?;
    if !this
        .db
        .list_ip_provider_regions(Some(id), Some(req.region_id))
        .await?
        .is_empty()
    {
        return Err(ApiError::bad_request(
            "This provider already has a rule for that region",
        ));
    }
    let prefix_len = req.prefix_len.unwrap_or(32);
    let quantity = req.quantity.unwrap_or(1);
    validate_rule(prefix_len, quantity)?;
    if req.when_no_ip == Some(IpWhenNoIp::OrderAndWait) {
        validate_order_and_wait(this.db.as_ref(), id).await?;
    }
    let rule = IpProviderRegion {
        id: 0,
        provider_id: id,
        region_id: req.region_id,
        country: clean(req.country),
        destination: clean(req.destination),
        prefix_len,
        quantity,
        auto_threshold: req.auto_threshold,
        enabled: req.enabled.unwrap_or(true),
        when_no_ip: req.when_no_ip.unwrap_or_default(),
        sell_without_capacity: req.sell_without_capacity.unwrap_or(false),
        wait_refund_hours: req.wait_refund_hours.unwrap_or(0),
    };
    let rid = this.db.insert_ip_provider_region(&rule).await?;
    ApiData::ok(this.db.get_ip_provider_region(rid).await?.into())
}

async fn admin_update_ip_provider_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, rule_id)): Path<(u64, u64)>,
    Json(req): Json<UpdateIpProviderRegionRequest>,
) -> ApiResult<AdminIpProviderRegion> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Update)?;
    let mut r = rule_of(this.db.as_ref(), id, rule_id).await?;
    if let Some(v) = req.country {
        r.country = clean(v);
    }
    if let Some(v) = req.destination {
        r.destination = clean(v);
    }
    if let Some(v) = req.prefix_len {
        r.prefix_len = v;
    }
    if let Some(v) = req.quantity {
        r.quantity = v;
    }
    if let Some(v) = req.auto_threshold {
        r.auto_threshold = v;
    }
    if let Some(v) = req.enabled {
        r.enabled = v;
    }
    if let Some(v) = req.when_no_ip {
        r.when_no_ip = v;
    }
    if let Some(v) = req.sell_without_capacity {
        r.sell_without_capacity = v;
    }
    if let Some(v) = req.wait_refund_hours {
        r.wait_refund_hours = v;
    }
    validate_rule(r.prefix_len, r.quantity)?;
    if r.when_no_ip == IpWhenNoIp::OrderAndWait {
        validate_order_and_wait(this.db.as_ref(), id).await?;
    }
    this.db.update_ip_provider_region(&r).await?;
    ApiData::ok(this.db.get_ip_provider_region(rule_id).await?.into())
}

async fn admin_delete_ip_provider_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, rule_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Delete)?;
    rule_of(this.db.as_ref(), id, rule_id).await?;
    this.db.delete_ip_provider_region(rule_id).await?;
    ApiData::ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> IpProvider {
        IpProvider {
            id: 1,
            name: "ovh".to_string(),
            kind: IpProviderKind::Ovh,
            enabled: true,
            url: "https://eu.api.ovh.com".to_string(),
            token: "app:SUPERSECRET:consumer".into(),
            subsidiary: "IE".to_string(),
            rir: "ripe".to_string(),
            gateway: "203.0.113.254".to_string(),
            access_policy_id: None,
            approval_required: true,
            monthly_spend_cap: 5000,
            currency: "EUR".to_string(),
            enable_ranges_on_delivery: true,
        }
    }

    #[test]
    fn the_token_is_never_serialised() {
        let json = serde_json::to_string(&AdminIpProvider::from(provider())).unwrap();
        assert!(!json.contains("SUPERSECRET"), "{json}");
        assert!(!json.contains("\"token\""), "{json}");
        assert!(json.contains("\"has_token\":true"));
    }

    #[test]
    fn has_token_is_false_when_empty() {
        let mut p = provider();
        p.token = "".into();
        assert!(!AdminIpProvider::from(p).has_token);
    }

    #[test]
    fn rule_validation() {
        assert!(validate_rule(32, 5).is_ok());
        assert!(validate_rule(29, 1).is_ok());
        assert!(validate_rule(29, 2).is_err());
        assert!(validate_rule(32, 0).is_err());
        assert!(validate_rule(16, 1).is_err());
        assert!(validate_rule(31, 1).is_err());
    }

    #[test]
    fn field_validation() {
        assert!(validate_name("  ").is_err());
        assert_eq!(validate_name(" ovh ").unwrap(), "ovh");
        assert_eq!(validate_currency("eur").unwrap(), "EUR");
        assert!(validate_currency("BTC").is_err());
        assert!(validate_currency("nope").is_err());
        assert_eq!(validate_rir("RIPE").unwrap(), "ripe");
        assert!(validate_rir("apnic").is_err());
        assert!(validate_gateway("203.0.113.254").is_ok());
        assert!(validate_gateway("not an ip").is_err());
    }

    #[test]
    fn update_distinguishes_clearing_from_absent() {
        let absent: UpdateIpProviderRequest = serde_json::from_str("{}").unwrap();
        assert!(absent.access_policy_id.is_none());
        let cleared: UpdateIpProviderRequest =
            serde_json::from_str(r#"{"access_policy_id":null}"#).unwrap();
        assert_eq!(cleared.access_policy_id, Some(None));
        let set: UpdateIpProviderRequest =
            serde_json::from_str(r#"{"access_policy_id":3}"#).unwrap();
        assert_eq!(set.access_policy_id, Some(Some(3)));
    }
}
