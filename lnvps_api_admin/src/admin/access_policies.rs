use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminAccessPolicyDetail, CreateAccessPolicyRequest, UpdateAccessPolicyRequest};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, NetworkAccessPolicy, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

/// List all access policies with pagination
#[get("/api/admin/v1/access_policies_full?<limit>&<offset>")]
pub async fn admin_list_access_policies_full(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminAccessPolicyDetail> {
    // Check permission
    auth.require_permission(AdminResource::AccessPolicy, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    let (db_access_policies, total) = db.admin_list_access_policies_paginated(limit, offset).await?;

    // Convert to API format with enriched data
    let mut access_policies = Vec::new();
    for access_policy in db_access_policies {
        let ip_range_count = db
            .admin_count_access_policy_ip_ranges(access_policy.id)
            .await
            .unwrap_or(0);

        // Get router name if set
        let router_name = if let Some(router_id) = access_policy.router_id {
            match db.get_router(router_id).await {
                Ok(router) => Some(router.name),
                Err(_) => None,
            }
        } else {
            None
        };

        let mut admin_access_policy = AdminAccessPolicyDetail::from(access_policy);
        admin_access_policy.ip_range_count = ip_range_count;
        admin_access_policy.router_name = router_name;
        access_policies.push(admin_access_policy);
    }

    ApiPaginatedData::ok(access_policies, total, limit, offset)
}

/// Get a specific access policy by ID
#[get("/api/admin/v1/access_policies_full/<id>")]
pub async fn admin_get_access_policy_full(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminAccessPolicyDetail> {
    // Check permission
    auth.require_permission(AdminResource::AccessPolicy, AdminAction::View)?;

    let access_policy = db.admin_get_access_policy(id).await?;
    let ip_range_count = db.admin_count_access_policy_ip_ranges(id).await.unwrap_or(0);

    // Get router name if set
    let router_name = if let Some(router_id) = access_policy.router_id {
        match db.get_router(router_id).await {
            Ok(router) => Some(router.name),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut admin_access_policy = AdminAccessPolicyDetail::from(access_policy);
    admin_access_policy.ip_range_count = ip_range_count;
    admin_access_policy.router_name = router_name;

    ApiData::ok(admin_access_policy)
}

/// Create a new access policy
#[post("/api/admin/v1/access_policies_full", data = "<req>")]
pub async fn admin_create_access_policy_full(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<CreateAccessPolicyRequest>,
) -> ApiResult<AdminAccessPolicyDetail> {
    // Check permission
    auth.require_permission(AdminResource::AccessPolicy, AdminAction::Create)?;

    // Validate required fields
    if req.name.trim().is_empty() {
        return ApiData::err("Access policy name is required");
    }

    // Validate router exists if provided
    if let Some(router_id) = req.router_id {
        if let Err(_) = db.get_router(router_id).await {
            return ApiData::err("Specified router does not exist");
        }
    }

    // Create access policy object
    let access_policy = req.to_access_policy()?;

    let access_policy_id = db.admin_create_access_policy(&access_policy).await?;

    // Fetch the created access policy to return
    let created_access_policy = db.admin_get_access_policy(access_policy_id).await?;
    
    // Get router name if set
    let router_name = if let Some(router_id) = created_access_policy.router_id {
        match db.get_router(router_id).await {
            Ok(router) => Some(router.name),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut admin_access_policy = AdminAccessPolicyDetail::from(created_access_policy);
    admin_access_policy.router_name = router_name;
    admin_access_policy.ip_range_count = 0; // New policy has no IP ranges

    ApiData::ok(admin_access_policy)
}

/// Update access policy information
#[patch("/api/admin/v1/access_policies_full/<id>", data = "<req>")]
pub async fn admin_update_access_policy_full(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: Json<UpdateAccessPolicyRequest>,
) -> ApiResult<AdminAccessPolicyDetail> {
    // Check permission
    auth.require_permission(AdminResource::AccessPolicy, AdminAction::Update)?;

    let mut access_policy = db.admin_get_access_policy(id).await?;

    // Update access policy fields if provided
    if let Some(name) = &req.name {
        if name.trim().is_empty() {
            return ApiData::err("Access policy name cannot be empty");
        }
        access_policy.name = name.trim().to_string();
    }

    if let Some(admin_kind) = &req.kind {
        access_policy.kind = NetworkAccessPolicy::from(*admin_kind);
    }

    if let Some(router_id) = &req.router_id {
        if let Some(router_id) = router_id {
            // Validate router exists
            if let Err(_) = db.get_router(*router_id).await {
                return ApiData::err("Specified router does not exist");
            }
        }
        access_policy.router_id = *router_id;
    }

    if let Some(interface) = &req.interface {
        access_policy.interface = interface.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    }

    // Update access policy in database
    db.admin_update_access_policy(&access_policy).await?;

    // Return updated access policy
    let ip_range_count = db.admin_count_access_policy_ip_ranges(id).await.unwrap_or(0);
    
    // Get router name if set
    let router_name = if let Some(router_id) = access_policy.router_id {
        match db.get_router(router_id).await {
            Ok(router) => Some(router.name),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut admin_access_policy = AdminAccessPolicyDetail::from(access_policy);
    admin_access_policy.ip_range_count = ip_range_count;
    admin_access_policy.router_name = router_name;

    ApiData::ok(admin_access_policy)
}

/// Delete an access policy
#[delete("/api/admin/v1/access_policies_full/<id>")]
pub async fn admin_delete_access_policy_full(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::AccessPolicy, AdminAction::Delete)?;

    // This will fail if there are IP ranges using this access policy
    db.admin_delete_access_policy(id).await?;

    ApiData::ok(())
}