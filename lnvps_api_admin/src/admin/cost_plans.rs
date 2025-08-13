use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCostPlanInfo, AdminCreateCostPlanRequest, AdminUpdateCostPlanRequest,
};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VmCostPlan};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

impl AdminCostPlanInfo {
    pub async fn from_cost_plan(
        db: &Arc<dyn LNVpsDb>,
        cost_plan: &VmCostPlan,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Count VM templates using this cost plan
        let all_templates = db.list_vm_templates().await.unwrap_or_default();
        let template_count = all_templates
            .iter()
            .filter(|template| template.cost_plan_id == cost_plan.id)
            .count() as u64;

        let mut info = AdminCostPlanInfo::from(cost_plan.clone());
        info.template_count = template_count;
        Ok(info)
    }
}

/// List cost plans
#[get("/api/admin/v1/cost_plans?<limit>&<offset>")]
pub async fn admin_list_cost_plans(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminCostPlanInfo> {
    // Check permission - using VmTemplate resource as cost plans are tightly coupled to templates
    auth.require_permission(AdminResource::VmTemplate, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let all_cost_plans = db.list_cost_plans().await?;
    let total = all_cost_plans.len() as u64;

    let cost_plans = all_cost_plans
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<_>>();

    let mut cost_plan_infos = Vec::new();
    for cost_plan in cost_plans {
        match AdminCostPlanInfo::from_cost_plan(db, &cost_plan).await {
            Ok(info) => cost_plan_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(cost_plan_infos, total, limit, offset)
}

/// Get cost plan details
#[get("/api/admin/v1/cost_plans/<id>")]
pub async fn admin_get_cost_plan(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminCostPlanInfo> {
    // Check permission - using VmTemplate resource as cost plans are tightly coupled to templates
    auth.require_permission(AdminResource::VmTemplate, AdminAction::View)?;

    let cost_plan = db.get_cost_plan(id).await?;
    let info = AdminCostPlanInfo::from_cost_plan(db, &cost_plan).await?;
    ApiData::ok(info)
}

/// Create cost plan
#[post("/api/admin/v1/cost_plans", data = "<request>")]
pub async fn admin_create_cost_plan(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<AdminCreateCostPlanRequest>,
) -> ApiResult<AdminCostPlanInfo> {
    // Check permission - using VmTemplate resource as cost plans are tightly coupled to templates
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Create)?;

    let req = request.into_inner();
    let cost_plan = req.to_cost_plan()?;

    let cost_plan_id = db.insert_cost_plan(&cost_plan).await?;
    let created_cost_plan = db.get_cost_plan(cost_plan_id).await?;
    let info = AdminCostPlanInfo::from_cost_plan(db, &created_cost_plan).await?;
    ApiData::ok(info)
}

/// Update cost plan
#[patch("/api/admin/v1/cost_plans/<id>", data = "<request>")]
pub async fn admin_update_cost_plan(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    request: Json<AdminUpdateCostPlanRequest>,
) -> ApiResult<AdminCostPlanInfo> {
    // Check permission - using VmTemplate resource as cost plans are tightly coupled to templates
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Update)?;

    let req = request.into_inner();

    // Get existing cost plan
    let mut cost_plan = db.get_cost_plan(id).await?;

    // Update fields if provided
    if let Some(name) = req.name {
        if name.trim().is_empty() {
            return Err(anyhow::anyhow!("Cost plan name cannot be empty").into());
        }
        cost_plan.name = name.trim().to_string();
    }
    if let Some(amount) = req.amount {
        if amount < 0.0 {
            return Err(anyhow::anyhow!("Cost plan amount cannot be negative").into());
        }
        cost_plan.amount = amount;
    }
    if let Some(currency) = req.currency {
        if currency.trim().is_empty() {
            return Err(anyhow::anyhow!("Currency cannot be empty").into());
        }
        cost_plan.currency = currency.trim().to_uppercase();
    }
    if let Some(interval_amount) = req.interval_amount {
        if interval_amount == 0 {
            return Err(anyhow::anyhow!("Interval amount cannot be zero").into());
        }
        cost_plan.interval_amount = interval_amount;
    }
    if let Some(interval_type) = req.interval_type {
        cost_plan.interval_type = interval_type.into();
    }

    db.update_cost_plan(&cost_plan).await?;
    let info = AdminCostPlanInfo::from_cost_plan(db, &cost_plan).await?;
    ApiData::ok(info)
}

/// Delete cost plan
#[delete("/api/admin/v1/cost_plans/<id>")]
pub async fn admin_delete_cost_plan(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<serde_json::Value> {
    // Check permission - using VmTemplate resource as cost plans are tightly coupled to templates
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Delete)?;

    // Check if cost plan exists
    let _cost_plan = db.get_cost_plan(id).await?;

    // Check if cost plan is being used by any VM templates
    let all_templates = db.list_vm_templates().await?;
    let template_count = all_templates
        .iter()
        .filter(|template| template.cost_plan_id == id)
        .count();

    if template_count > 0 {
        return Err(anyhow::anyhow!(
            "Cannot delete cost plan: {} VM templates are using this cost plan",
            template_count
        )
        .into());
    }

    db.delete_cost_plan(id).await?;
    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Cost plan deleted successfully"
    }))
}
