use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCustomPricingDisk, AdminCustomPricingInfo, CopyCustomPricingRequest,
    CreateCustomPricingRequest, UpdateCustomPricingRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use lnvps_api_common::{
    ApiData, ApiDiskInterface, ApiDiskType, ApiPaginatedData, ApiPaginatedResult, ApiResult,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VmCustomPricing, VmCustomPricingDisk};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/custom_pricing",
            get(admin_list_custom_pricing).post(admin_create_custom_pricing),
        )
        .route(
            "/api/admin/v1/custom_pricing/{id}",
            get(admin_get_custom_pricing)
                .patch(admin_update_custom_pricing)
                .delete(admin_delete_custom_pricing),
        )
        .route(
            "/api/admin/v1/custom_pricing/{id}/copy",
            post(admin_copy_custom_pricing),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CustomPricingQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    region_id: Option<u64>,
    enabled: Option<bool>,
}

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
                min_disk_size: dp.min_disk_size,
                max_disk_size: dp.max_disk_size,
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
            min_cpu: pricing.min_cpu,
            max_cpu: pricing.max_cpu,
            min_memory: pricing.min_memory,
            max_memory: pricing.max_memory,
            disk_pricing: disk_pricing_info,
            template_count,
        })
    }
}

/// List custom pricing models
async fn admin_list_custom_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<CustomPricingQuery>,
) -> ApiPaginatedResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // For now, get all and filter manually - ideally this would be done in the database
    let all_regions = if let Some(region_id) = params.region_id {
        vec![region_id]
    } else {
        this.db
            .list_host_region()
            .await?
            .into_iter()
            .map(|r| r.id)
            .collect()
    };

    let mut all_pricing = Vec::new();
    for region in all_regions {
        let region_pricing = this.db.list_custom_pricing(region).await?;
        all_pricing.extend(region_pricing);
    }

    // Apply enabled filter if provided
    if let Some(enabled_filter) = params.enabled {
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
        match AdminCustomPricingInfo::from_custom_pricing(&this.db, &pricing).await {
            Ok(info) => pricing_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(pricing_infos, total, limit, offset)
}

/// Get custom pricing model details
async fn admin_get_custom_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::View)?;

    let pricing = this.db.get_custom_pricing(id).await?;
    let info = AdminCustomPricingInfo::from_custom_pricing(&this.db, &pricing).await?;
    ApiData::ok(info)
}

/// Create custom pricing model
async fn admin_create_custom_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateCustomPricingRequest>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Create)?;

    // Validate that region exists
    let _region = this.db.get_host_region(req.region_id).await?;

    let pricing = VmCustomPricing {
        id: 0, // Will be set by database
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        expires: req.expires,
        region_id: req.region_id,
        currency: req.currency,
        cpu_mfg: Default::default(),
        cpu_arch: Default::default(),
        cpu_features: Default::default(),
        cpu_cost: req.cpu_cost,
        memory_cost: req.memory_cost,
        ip4_cost: req.ip4_cost,
        ip6_cost: req.ip6_cost,
        min_cpu: req.min_cpu,
        max_cpu: req.max_cpu,
        min_memory: req.min_memory,
        max_memory: req.max_memory,
    };

    let pricing_id = this.db.insert_custom_pricing(&pricing).await?;

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
            min_disk_size: disk_config.min_disk_size,
            max_disk_size: disk_config.max_disk_size,
        };

        this.db.insert_custom_pricing_disk(&disk_pricing).await?;
    }

    let created_pricing = this.db.get_custom_pricing(pricing_id).await?;
    let info = AdminCustomPricingInfo::from_custom_pricing(&this.db, &created_pricing).await?;
    ApiData::ok(info)
}

/// Update custom pricing model
async fn admin_update_custom_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateCustomPricingRequest>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Update)?;

    // Get existing pricing
    let mut pricing = this.db.get_custom_pricing(id).await?;

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
        let _region = this.db.get_host_region(region_id).await?;
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
    if let Some(min_cpu) = req.min_cpu {
        pricing.min_cpu = min_cpu;
    }
    if let Some(max_cpu) = req.max_cpu {
        pricing.max_cpu = max_cpu;
    }
    if let Some(min_memory) = req.min_memory {
        pricing.min_memory = min_memory;
    }
    if let Some(max_memory) = req.max_memory {
        pricing.max_memory = max_memory;
    }

    this.db.update_custom_pricing(&pricing).await?;

    // Update disk pricing if provided
    if let Some(disk_pricing_configs) = req.disk_pricing {
        // Delete existing disk pricing configurations
        this.db.delete_custom_pricing_disks(id).await?;

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
                min_disk_size: disk_config.min_disk_size,
                max_disk_size: disk_config.max_disk_size,
            };

            this.db.insert_custom_pricing_disk(&disk_pricing).await?;
        }
    }

    let info = AdminCustomPricingInfo::from_custom_pricing(&this.db, &pricing).await?;
    ApiData::ok(info)
}

/// Delete custom pricing model
async fn admin_delete_custom_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<serde_json::Value> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Delete)?;

    // Check if pricing model exists
    let mut pricing = this.db.get_custom_pricing(id).await?;

    // Check if pricing model is being used by any custom templates
    let template_count = this.db.count_custom_templates_by_pricing(id).await?;
    if template_count > 0 {
        // Instead of deleting, disable the pricing model to preserve billing consistency
        pricing.enabled = false;
        this.db.update_custom_pricing(&pricing).await?;

        return ApiData::ok(serde_json::json!({
            "success": true,
            "message": format!("Custom pricing model disabled instead of deleted: {} templates are using this pricing model", template_count)
        }));
    }

    // Delete disk pricing configurations first
    this.db.delete_custom_pricing_disks(id).await?;

    // Delete the pricing model
    this.db.delete_custom_pricing(id).await?;

    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Custom pricing model deleted successfully"
    }))
}

/// Copy custom pricing model
async fn admin_copy_custom_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<CopyCustomPricingRequest>,
) -> ApiResult<AdminCustomPricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Create)?;

    // Get source pricing model
    let source_pricing = this.db.get_custom_pricing(id).await?;
    let source_disk_pricing = this.db.list_custom_pricing_disk(id).await?;

    let target_region_id = req.region_id.unwrap_or(source_pricing.region_id);

    // Validate that target region exists
    let _region = this.db.get_host_region(target_region_id).await?;

    // Create new pricing model
    let new_pricing = VmCustomPricing {
        id: 0, // Will be set by database
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        expires: source_pricing.expires,
        region_id: target_region_id,
        currency: source_pricing.currency,
        cpu_mfg: Default::default(),
        cpu_arch: Default::default(),
        cpu_features: Default::default(),
        cpu_cost: source_pricing.cpu_cost,
        memory_cost: source_pricing.memory_cost,
        ip4_cost: source_pricing.ip4_cost,
        ip6_cost: source_pricing.ip6_cost,
        min_cpu: source_pricing.min_cpu,
        max_cpu: source_pricing.max_cpu,
        min_memory: source_pricing.min_memory,
        max_memory: source_pricing.max_memory,
    };

    let new_pricing_id = this.db.insert_custom_pricing(&new_pricing).await?;

    // Copy disk pricing configurations
    for disk_config in source_disk_pricing {
        let new_disk_pricing = VmCustomPricingDisk {
            id: 0, // Will be set by database
            pricing_id: new_pricing_id,
            kind: disk_config.kind,
            interface: disk_config.interface,
            cost: disk_config.cost,
            min_disk_size: disk_config.min_disk_size,
            max_disk_size: disk_config.max_disk_size,
        };

        this.db
            .insert_custom_pricing_disk(&new_disk_pricing)
            .await?;
    }

    let created_pricing = this.db.get_custom_pricing(new_pricing_id).await?;
    let info = AdminCustomPricingInfo::from_custom_pricing(&this.db, &created_pricing).await?;
    ApiData::ok(info)
}
