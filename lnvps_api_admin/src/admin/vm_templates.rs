use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCreateVmTemplateRequest, AdminUpdateVmTemplateRequest, AdminVmTemplateInfo,
};
use chrono::Utc;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VmTemplate};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

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
#[get("/api/admin/v1/vm_templates?<limit>&<offset>")]
pub async fn admin_list_vm_templates(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let (templates, total) = db
        .list_vm_templates_paginated(limit as i64, offset as i64)
        .await?;
    let mut template_infos = Vec::new();
    for template in templates {
        match AdminVmTemplateInfo::from_vm_template(db, &template).await {
            Ok(info) => template_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(template_infos, total as u64, limit, offset)
}

/// Get VM template details
#[get("/api/admin/v1/vm_templates/<id>")]
pub async fn admin_get_vm_template(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::View)?;

    let template = db.get_vm_template(id).await?;
    let info = AdminVmTemplateInfo::from_vm_template(db, &template).await?;
    ApiData::ok(info)
}

/// Create VM template
#[post("/api/admin/v1/vm_templates", data = "<request>")]
pub async fn admin_create_vm_template(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<AdminCreateVmTemplateRequest>,
) -> ApiResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Create)?;

    let req = request.into_inner();

    // Get disk type and interface from request
    let disk_type = req.disk_type;
    let disk_interface = req.disk_interface;

    // Validate that cost plan exists
    let _cost_plan = db.get_cost_plan(req.cost_plan_id).await?;

    // Validate that region exists
    let _region = db.get_host_region(req.region_id).await?;

    let template = VmTemplate {
        id: 0, // Will be set by database
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        expires: req.expires,
        cpu: req.cpu,
        memory: req.memory,
        disk_size: req.disk_size,
        disk_type: disk_type.into(),
        disk_interface: disk_interface.into(),
        cost_plan_id: req.cost_plan_id,
        region_id: req.region_id,
    };

    let template_id = db.insert_vm_template(&template).await?;
    let created_template = db.get_vm_template(template_id).await?;
    let info = AdminVmTemplateInfo::from_vm_template(db, &created_template).await?;
    ApiData::ok(info)
}

/// Update VM template
#[patch("/api/admin/v1/vm_templates/<id>", data = "<request>")]
pub async fn admin_update_vm_template(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    request: Json<AdminUpdateVmTemplateRequest>,
) -> ApiResult<AdminVmTemplateInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Update)?;

    let req = request.into_inner();

    // Get existing template
    let mut template = db.get_vm_template(id).await?;

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
        let _cost_plan = db.get_cost_plan(cost_plan_id).await?;
        template.cost_plan_id = cost_plan_id;
    }
    if let Some(region_id) = req.region_id {
        // Validate that region exists
        let _region = db.get_host_region(region_id).await?;
        template.region_id = region_id;
    }

    db.update_vm_template(&template).await?;
    let info = AdminVmTemplateInfo::from_vm_template(db, &template).await?;
    ApiData::ok(info)
}

/// Delete VM template
#[delete("/api/admin/v1/vm_templates/<id>")]
pub async fn admin_delete_vm_template(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<serde_json::Value> {
    // Check permission
    auth.require_permission(AdminResource::VmTemplate, AdminAction::Delete)?;

    // Check if template exists
    let _template = db.get_vm_template(id).await?;

    // Check if template is being used by any VMs
    let vm_count = db.check_vm_template_usage(id).await?;
    if vm_count > 0 {
        return Err(anyhow::anyhow!(
            "Cannot delete VM template: {} VMs are using this template",
            vm_count
        )
        .into());
    }

    db.delete_vm_template(id).await?;
    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "VM template deleted successfully"
    }))
}
