use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCustomPricingDisk, AdminCustomPricingInfo, CopyCustomPricingRequest,
    CreateCustomPricingRequest, UpdateCustomPricingRequest,
};
use chrono::Utc;
use lnvps_api_common::{
    ApiData, ApiDiskInterface, ApiDiskType, ApiPaginatedData, ApiPaginatedResult, ApiResult,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VmCustomPricing, VmCustomPricingDisk};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

impl AdminCustomPricingInfo {
    pub async fn from_custom_pricing(
        db: &Arc<dyn LNVpsDb>,
        pricing: &VmCustomPricing,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let region = db.get_host_region(pricing.region_id).await.ok();
        let disk_pricing = db
            .list_custom_pricing_disk(pricing.id)
            .await
            .unwrap_or_default();
        let template_count = db
            .count_custom_templates_by_pricing(pricing.id)
            .await
            .unwrap_or(0);

        let disk_pricing_info = disk_pricing
            .into_iter()
            .map(|dp| AdminCustomPricingDisk {
                id: dp.id,
                kind: ApiDiskType::from(dp.kind),
                interface: ApiDiskInterface::from(dp.interface),
                cost: dp.cost,
            })
            .collect();

        Ok(AdminCustomPricingInfo {
            id: pricing.id,
            name: pricing.name.clone(),
            enabled: pricing.enabled,
            created: pricing.created,
            expires: pricing.expires,
            region_id: pricing.region_id,
            region_name: region.map(|r| r.name),
            currency: pricing.currency.clone(),
            cpu_cost: pricing.cpu_cost,
            memory_cost: pricing.memory_cost,
            ip4_cost: pricing.ip4_cost,
            ip6_cost: pricing.ip6_cost,
            disk_pricing: disk_pricing_info,
            template_count,
        })
    }
}

/// List custom pricing models
#[get("/api/admin/v1/custom_pricing?<limit>&<offset>&<region_id>&<enabled>")]
pub async fn admin_list_custom_pricing(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
    region_id: Option<u64>,
    enabled: Option<bool>,
) -> ApiPaginatedResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    // For now, get all and filter manually - ideally this would be done in the database
    let all_regions = if let Some(region_id) = region_id {
        vec![region_id]
    } else {
        db.list_host_region()
            .await?
            .into_iter()
            .map(|r| r.id)
            .collect()
    };

    let mut all_pricing = Vec::new();
    for region in all_regions {
        let region_pricing = db.list_custom_pricing(region).await?;
        all_pricing.extend(region_pricing);
    }

    // Apply enabled filter if provided
    if let Some(enabled_filter) = enabled {
        all_pricing.retain(|p| p.enabled == enabled_filter);
    }

    let total = all_pricing.len() as u64;

    // Apply pagination
    let paginated_pricing: Vec<_> = all_pricing
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    let mut pricing_infos = Vec::new();
    for pricing in paginated_pricing {
        match AdminCustomPricingInfo::from_custom_pricing(db, &pricing).await {
            Ok(info) => pricing_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(pricing_infos, total, limit, offset)
}

/// Get custom pricing model details
#[get("/api/admin/v1/custom_pricing/<id>")]
pub async fn admin_get_custom_pricing(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::View)?;

    let pricing = db.get_custom_pricing(id).await?;
    let info = AdminCustomPricingInfo::from_custom_pricing(db, &pricing).await?;
    ApiData::ok(info)
}

/// Create custom pricing model
#[post("/api/admin/v1/custom_pricing", data = "<request>")]
pub async fn admin_create_custom_pricing(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<CreateCustomPricingRequest>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Create)?;

    let req = request.into_inner();

    // Validate that region exists
    let _region = db.get_host_region(req.region_id).await?;

    let pricing = VmCustomPricing {
        id: 0, // Will be set by database
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        expires: req.expires,
        region_id: req.region_id,
        currency: req.currency,
        cpu_cost: req.cpu_cost,
        memory_cost: req.memory_cost,
        ip4_cost: req.ip4_cost,
        ip6_cost: req.ip6_cost,
    };

    let pricing_id = db.insert_custom_pricing(&pricing).await?;

    // Insert disk pricing configurations
    for disk_config in req.disk_pricing {
        let disk_type = disk_config.kind;
        let disk_interface = disk_config.interface;

        let disk_pricing = VmCustomPricingDisk {
            id: 0, // Will be set by database
            pricing_id,
            kind: disk_type.into(),
            interface: disk_interface.into(),
            cost: disk_config.cost,
        };

        db.insert_custom_pricing_disk(&disk_pricing).await?;
    }

    let created_pricing = db.get_custom_pricing(pricing_id).await?;
    let info = AdminCustomPricingInfo::from_custom_pricing(db, &created_pricing).await?;
    ApiData::ok(info)
}

/// Update custom pricing model
#[patch("/api/admin/v1/custom_pricing/<id>", data = "<request>")]
pub async fn admin_update_custom_pricing(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    request: Json<UpdateCustomPricingRequest>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Update)?;

    let req = request.into_inner();

    // Get existing pricing
    let mut pricing = db.get_custom_pricing(id).await?;

    // Update fields if provided
    if let Some(name) = req.name {
        pricing.name = name;
    }
    if let Some(enabled) = req.enabled {
        pricing.enabled = enabled;
    }
    if let Some(expires) = req.expires {
        pricing.expires = expires;
    }
    if let Some(region_id) = req.region_id {
        // Validate that region exists
        let _region = db.get_host_region(region_id).await?;
        pricing.region_id = region_id;
    }
    if let Some(currency) = req.currency {
        pricing.currency = currency;
    }
    if let Some(cpu_cost) = req.cpu_cost {
        pricing.cpu_cost = cpu_cost;
    }
    if let Some(memory_cost) = req.memory_cost {
        pricing.memory_cost = memory_cost;
    }
    if let Some(ip4_cost) = req.ip4_cost {
        pricing.ip4_cost = ip4_cost;
    }
    if let Some(ip6_cost) = req.ip6_cost {
        pricing.ip6_cost = ip6_cost;
    }

    db.update_custom_pricing(&pricing).await?;

    // Update disk pricing if provided
    if let Some(disk_pricing_configs) = req.disk_pricing {
        // Delete existing disk pricing configurations
        db.delete_custom_pricing_disks(id).await?;

        // Insert new configurations
        for disk_config in disk_pricing_configs {
            let disk_type = disk_config.kind;
            let disk_interface = disk_config.interface;

            let disk_pricing = VmCustomPricingDisk {
                id: 0, // Will be set by database
                pricing_id: id,
                kind: disk_type.into(),
                interface: disk_interface.into(),
                cost: disk_config.cost,
            };

            db.insert_custom_pricing_disk(&disk_pricing).await?;
        }
    }

    let info = AdminCustomPricingInfo::from_custom_pricing(db, &pricing).await?;
    ApiData::ok(info)
}

/// Delete custom pricing model
#[delete("/api/admin/v1/custom_pricing/<id>")]
pub async fn admin_delete_custom_pricing(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<serde_json::Value> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Delete)?;

    // Check if pricing model exists
    let mut pricing = db.get_custom_pricing(id).await?;

    // Check if pricing model is being used by any custom templates
    let template_count = db.count_custom_templates_by_pricing(id).await?;
    if template_count > 0 {
        // Instead of deleting, disable the pricing model to preserve billing consistency
        pricing.enabled = false;
        db.update_custom_pricing(&pricing).await?;

        return ApiData::ok(serde_json::json!({
            "success": true,
            "message": format!("Custom pricing model disabled instead of deleted: {} templates are using this pricing model", template_count)
        }));
    }

    // Delete disk pricing configurations first
    db.delete_custom_pricing_disks(id).await?;

    // Delete the pricing model
    db.delete_custom_pricing(id).await?;

    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Custom pricing model deleted successfully"
    }))
}

/// Copy custom pricing model
#[post("/api/admin/v1/custom_pricing/<id>/copy", data = "<request>")]
pub async fn admin_copy_custom_pricing(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    request: Json<CopyCustomPricingRequest>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Create)?;

    let req = request.into_inner();

    // Get source pricing model
    let source_pricing = db.get_custom_pricing(id).await?;
    let source_disk_pricing = db.list_custom_pricing_disk(id).await?;

    let target_region_id = req.region_id.unwrap_or(source_pricing.region_id);

    // Validate that target region exists
    let _region = db.get_host_region(target_region_id).await?;

    // Create new pricing model
    let new_pricing = VmCustomPricing {
        id: 0, // Will be set by database
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        expires: source_pricing.expires,
        region_id: target_region_id,
        currency: source_pricing.currency,
        cpu_cost: source_pricing.cpu_cost,
        memory_cost: source_pricing.memory_cost,
        ip4_cost: source_pricing.ip4_cost,
        ip6_cost: source_pricing.ip6_cost,
    };

    let new_pricing_id = db.insert_custom_pricing(&new_pricing).await?;

    // Copy disk pricing configurations
    for disk_config in source_disk_pricing {
        let new_disk_pricing = VmCustomPricingDisk {
            id: 0, // Will be set by database
            pricing_id: new_pricing_id,
            kind: disk_config.kind,
            interface: disk_config.interface,
            cost: disk_config.cost,
        };

        db.insert_custom_pricing_disk(&new_disk_pricing).await?;
    }

    let created_pricing = db.get_custom_pricing(new_pricing_id).await?;
    let info = AdminCustomPricingInfo::from_custom_pricing(db, &created_pricing).await?;
    ApiData::ok(info)
}
