use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCostResourceType, AdminResourceCostDetail, CreateResourceCostRequest,
    UpdateResourceCostRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{AdminAction, AdminResource, ResourceCost};
use serde::Deserialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/resource_costs",
            get(admin_list_resource_costs).post(admin_create_resource_cost),
        )
        .route(
            "/api/admin/v1/resource_costs/{id}",
            get(admin_get_resource_cost)
                .patch(admin_update_resource_cost)
                .delete(admin_delete_resource_cost),
        )
}

/// Optional filters for listing cost records.
#[derive(Deserialize)]
pub struct CostFilter {
    pub resource_type: Option<AdminCostResourceType>,
    pub resource_id: Option<u64>,
}

async fn admin_list_resource_costs(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(page): Query<PageQuery>,
    Query(filter): Query<CostFilter>,
) -> ApiPaginatedResult<AdminResourceCostDetail> {
    auth.require_permission(AdminResource::ResourceCost, AdminAction::View)?;

    let limit = page.limit.unwrap_or(50).min(100);
    let offset = page.offset.unwrap_or(0);

    let (rows, total) = this
        .db
        .admin_list_resource_costs(
            limit,
            offset,
            filter.resource_type.map(Into::into),
            filter.resource_id,
        )
        .await?;

    let out = rows.into_iter().map(AdminResourceCostDetail::from).collect();
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_resource_cost(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminResourceCostDetail> {
    auth.require_permission(AdminResource::ResourceCost, AdminAction::View)?;

    let cost = this.db.admin_get_resource_cost(id).await?;
    ApiData::ok(cost.into())
}

fn validate(cost_type: lnvps_db::CostType, interval_amount: Option<u64>, currency: &str) -> Result<(), &'static str> {
    if currency.trim().is_empty() {
        return Err("Currency cannot be empty");
    }
    if cost_type == lnvps_db::CostType::Recurring && interval_amount.is_none() {
        return Err("Recurring costs require an interval");
    }
    Ok(())
}

async fn admin_create_resource_cost(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateResourceCostRequest>,
) -> ApiResult<AdminResourceCostDetail> {
    auth.require_permission(AdminResource::ResourceCost, AdminAction::Create)?;

    let cost_type: lnvps_db::CostType = req.cost_type.into();
    if let Err(e) = validate(cost_type, req.interval_amount, &req.currency) {
        return ApiData::err(e);
    }

    let resource_type: lnvps_db::CostResourceType = req.resource_type.into();
    let label = req.label.map(|l| l.trim().to_string()).filter(|l| !l.is_empty());
    if resource_type == lnvps_db::CostResourceType::Generic && label.is_none() {
        return ApiData::err("Generic costs require a label");
    }

    let cost = ResourceCost {
        id: 0,
        resource_type,
        resource_id: if resource_type == lnvps_db::CostResourceType::Generic {
            0
        } else {
            req.resource_id
        },
        label,
        cost_type,
        amount: req.amount,
        currency: req.currency.trim().to_string(),
        interval_amount: req.interval_amount,
        interval_type: req.interval_type.map(Into::into),
        billing_start: req.billing_start,
        billing_end: req.billing_end,
        created: chrono::Utc::now(),
        updated: chrono::Utc::now(),
    };

    let id = this.db.admin_create_resource_cost(&cost).await?;
    let created = this.db.admin_get_resource_cost(id).await?;
    ApiData::ok(created.into())
}

async fn admin_update_resource_cost(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateResourceCostRequest>,
) -> ApiResult<AdminResourceCostDetail> {
    auth.require_permission(AdminResource::ResourceCost, AdminAction::Update)?;

    let mut cost = this.db.admin_get_resource_cost(id).await?;

    if let Some(ct) = req.cost_type {
        cost.cost_type = ct.into();
    }
    if let Some(amount) = req.amount {
        cost.amount = amount;
    }
    if let Some(currency) = req.currency {
        cost.currency = currency.trim().to_string();
    }
    if let Some(label) = req.label {
        cost.label = label.map(|l| l.trim().to_string()).filter(|l| !l.is_empty());
    }
    if cost.resource_type == lnvps_db::CostResourceType::Generic && cost.label.is_none() {
        return ApiData::err("Generic costs require a label");
    }
    if let Some(v) = req.interval_amount {
        cost.interval_amount = v;
    }
    if let Some(v) = req.interval_type {
        cost.interval_type = v.map(Into::into);
    }
    if let Some(v) = req.billing_start {
        cost.billing_start = v;
    }
    if let Some(v) = req.billing_end {
        cost.billing_end = v;
    }

    if let Err(e) = validate(cost.cost_type, cost.interval_amount, &cost.currency) {
        return ApiData::err(e);
    }

    this.db.admin_update_resource_cost(&cost).await?;
    let updated = this.db.admin_get_resource_cost(id).await?;
    ApiData::ok(updated.into())
}

async fn admin_delete_resource_cost(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::ResourceCost, AdminAction::Delete)?;

    this.db.admin_delete_resource_cost(id).await?;
    ApiData::ok(())
}
