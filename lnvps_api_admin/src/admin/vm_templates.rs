use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCreateVmTemplateRequest, AdminUpdateVmTemplateRequest, AdminVmTemplateInfo,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VmTemplate};
use std::sync::Arc;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vm_templates",
            get(admin_list_vm_templates).post(admin_create_vm_template),
        )
        .route(
            "/api/admin/v1/vm_templates/{id}",
            get(admin_get_vm_template)
                .patch(admin_update_vm_template)
                .delete(admin_delete_vm_template),
        )
}

impl AdminVmTemplateInfo {
    pub async fn from_vm_template(
        db: &Arc<dyn LNVpsDb>,
        template: &VmTemplate,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let region = db.get_host_region(template.region_id).await.ok();
        let cost_plan = db.get_cost_plan(template.cost_plan_id).await.ok();

        // Count active VMs using this template
        let all_vms = db.list_vms().await.unwrap_or_default();
        let active_vm_count = all_vms
            .iter()
            .filter(|vm| vm.template_id == Some(template.id) && !vm.deleted)
            .count() as i64;

        Ok(AdminVmTemplateInfo {
            id: template.id,
            name: template.name.clone(),
            enabled: template.enabled,
            created: template.created,
            expires: template.expires,
            cpu: template.cpu,
            memory: template.memory,
            disk_size: template.disk_size,
            disk_type: template.disk_type.into(),
            disk_interface: template.disk_interface.into(),
            cost_plan_id: template.cost_plan_id,
            region_id: template.region_id,
            region_name: region.map(|r| r.name),
            cost_plan_name: cost_plan.map(|cp| cp.name),
            active_vm_count,
        })
    }
}

/// List VM templates
async fn admin_list_vm_templates(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let (templates, total) = this
        .db
        .list_vm_templates_paginated(limit as i64, offset as i64)
        .await?;
    let mut template_infos = Vec::new();
    for template in templates {
        match AdminVmTemplateInfo::from_vm_template(&this.db, &template).await {
            Ok(info) => template_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(template_infos, total as u64, limit, offset)
}

/// Get VM template details
async fn admin_get_vm_template(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::View)?;

    let template = this.db.get_vm_template(id).await?;
    let info = AdminVmTemplateInfo::from_vm_template(&this.db, &template).await?;
    ApiData::ok(info)
}

/// Create VM template
async fn admin_create_vm_template(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<AdminCreateVmTemplateRequest>,
) -> ApiResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Create)?;

    // Validate that region exists
    let _region = this.db.get_host_region(req.region_id).await?;

    // Handle cost plan creation or validation
    let cost_plan_id = if let Some(existing_cost_plan_id) = req.cost_plan_id {
        // Validate that the provided cost plan exists
        let _cost_plan = this.db.get_cost_plan(existing_cost_plan_id).await?;
        existing_cost_plan_id
    } else {
        // Auto-create a new cost plan for this template
        let cost_plan_amount = req.cost_plan_amount.ok_or_else(|| {
            anyhow::anyhow!("cost_plan_amount is required when cost_plan_id is not provided")
        })?;

        let cost_plan_name = req
            .cost_plan_name
            .unwrap_or_else(|| format!("{} Cost Plan", req.name));
        let cost_plan_currency = req.cost_plan_currency.unwrap_or_else(|| "USD".to_string());
        let cost_plan_interval_amount = req.cost_plan_interval_amount.unwrap_or(1);
        let cost_plan_interval_type = req
            .cost_plan_interval_type
            .unwrap_or(lnvps_api_common::ApiVmCostPlanIntervalType::Month);

        if cost_plan_interval_amount == 0 {
            return Err(anyhow::anyhow!("Cost plan interval amount cannot be zero").into());
        }

        let new_cost_plan = lnvps_db::VmCostPlan {
            id: 0, // Will be set by database
            name: cost_plan_name.trim().to_string(),
            created: Utc::now(),
            amount: cost_plan_amount,
            currency: cost_plan_currency.trim().to_uppercase(),
            interval_amount: cost_plan_interval_amount,
            interval_type: cost_plan_interval_type.into(),
        };

        this.db.insert_cost_plan(&new_cost_plan).await?
    };

    let template = VmTemplate {
        id: 0, // Will be set by database
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        expires: req.expires,
        cpu: req.cpu,
        cpu_mfg: Default::default(),
        cpu_arch: Default::default(),
        cpu_features: Default::default(),
        memory: req.memory,
        disk_size: req.disk_size,
        disk_type: req.disk_type.into(),
        disk_interface: req.disk_interface.into(),
        cost_plan_id,
        region_id: req.region_id,
    };

    let template_id = this.db.insert_vm_template(&template).await?;
    let created_template = this.db.get_vm_template(template_id).await?;
    let info = AdminVmTemplateInfo::from_vm_template(&this.db, &created_template).await?;
    ApiData::ok(info)
}

/// Update VM template
async fn admin_update_vm_template(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateVmTemplateRequest>,
) -> ApiResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Update)?;

    // Get existing template
    let mut template = this.db.get_vm_template(id).await?;

    // Update fields if provided
    if let Some(name) = req.name {
        template.name = name;
    }
    if let Some(enabled) = req.enabled {
        template.enabled = enabled;
    }
    if let Some(expires) = req.expires {
        template.expires = expires;
    }
    if let Some(cpu) = req.cpu {
        template.cpu = cpu;
    }
    if let Some(memory) = req.memory {
        template.memory = memory;
    }
    if let Some(disk_size) = req.disk_size {
        template.disk_size = disk_size;
    }
    if let Some(disk_type) = req.disk_type {
        template.disk_type = disk_type.into();
    }
    if let Some(disk_interface) = req.disk_interface {
        template.disk_interface = disk_interface.into();
    }
    if let Some(cost_plan_id) = req.cost_plan_id {
        // Validate that cost plan exists
        let _cost_plan = this.db.get_cost_plan(cost_plan_id).await?;
        template.cost_plan_id = cost_plan_id;
    }

    // Update the associated cost plan if any cost plan fields are provided
    let has_cost_plan_updates = req.cost_plan_name.is_some()
        || req.cost_plan_amount.is_some()
        || req.cost_plan_currency.is_some()
        || req.cost_plan_interval_amount.is_some()
        || req.cost_plan_interval_type.is_some();

    if has_cost_plan_updates {
        // Get the current cost plan for this template
        let mut cost_plan = this.db.get_cost_plan(template.cost_plan_id).await?;

        // Update cost plan fields if provided
        if let Some(cost_plan_name) = req.cost_plan_name {
            if cost_plan_name.trim().is_empty() {
                return Err(anyhow::anyhow!("Cost plan name cannot be empty").into());
            }
            cost_plan.name = cost_plan_name.trim().to_string();
        }
        if let Some(cost_plan_amount) = req.cost_plan_amount {
            cost_plan.amount = cost_plan_amount;
        }
        if let Some(cost_plan_currency) = req.cost_plan_currency {
            if cost_plan_currency.trim().is_empty() {
                return Err(anyhow::anyhow!("Cost plan currency cannot be empty").into());
            }
            cost_plan.currency = cost_plan_currency.trim().to_uppercase();
        }
        if let Some(cost_plan_interval_amount) = req.cost_plan_interval_amount {
            if cost_plan_interval_amount == 0 {
                return Err(anyhow::anyhow!("Cost plan interval amount cannot be zero").into());
            }
            cost_plan.interval_amount = cost_plan_interval_amount;
        }
        if let Some(cost_plan_interval_type) = req.cost_plan_interval_type {
            cost_plan.interval_type = cost_plan_interval_type.into();
        }

        // Update the cost plan
        this.db.update_cost_plan(&cost_plan).await?;
    }
    if let Some(region_id) = req.region_id {
        // Validate that region exists
        let _region = this.db.get_host_region(region_id).await?;
        template.region_id = region_id;
    }

    this.db.update_vm_template(&template).await?;
    let info = AdminVmTemplateInfo::from_vm_template(&this.db, &template).await?;
    ApiData::ok(info)
}

/// Delete VM template
async fn admin_delete_vm_template(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<serde_json::Value> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Delete)?;

    // Check if template exists
    let template = this.db.get_vm_template(id).await?;

    // Check if template is being used by any VMs
    let vm_count = this.db.check_vm_template_usage(id).await?;
    if vm_count > 0 {
        return Err(anyhow::anyhow!(
            "Cannot delete VM template: {} VMs are using this template",
            vm_count
        )
        .into());
    }

    // Check if the cost plan is used by other templates
    let all_templates = this.db.list_vm_templates().await?;
    let cost_plan_usage_count = all_templates
        .iter()
        .filter(|t| t.cost_plan_id == template.cost_plan_id && t.id != id)
        .count();

    // Delete the template first
    this.db.delete_vm_template(id).await?;

    // If this was the only template using the cost plan, delete the cost plan too
    if cost_plan_usage_count == 0 {
        match this.db.delete_cost_plan(template.cost_plan_id).await {
            Ok(_) => ApiData::ok(serde_json::json!({
                "success": true,
                "message": "VM template and associated cost plan deleted successfully"
            })),
            Err(_) => {
                // Cost plan deletion failed, but template was deleted successfully
                ApiData::ok(serde_json::json!({
                    "success": true,
                    "message": "VM template deleted successfully (cost plan cleanup failed)"
                }))
            }
        }
    } else {
        ApiData::ok(serde_json::json!({
            "success": true,
            "message": "VM template deleted successfully"
        }))
    }
}
