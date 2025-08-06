use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminRouterDetail, AdminRouterKind, CreateRouterRequest, UpdateRouterRequest,
};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{get, post, put, delete, State};
use std::sync::Arc;

#[get("/api/admin/v1/routers?<limit>&<offset>")]
pub async fn admin_list_routers(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    
    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let (routers, total) = db.admin_list_routers_paginated(limit, offset).await?;

    // Convert to admin models and populate access policy counts
    let mut admin_routers = Vec::new();
    for router in routers {
        let mut admin_router = AdminRouterDetail::from(router.clone());
        admin_router.access_policy_count = db.admin_count_router_access_policies(router.id).await
            .unwrap_or(0);
        admin_routers.push(admin_router);
    }

    ApiPaginatedData::ok(admin_routers, total, limit, offset)
}

#[get("/api/admin/v1/routers/<router_id>")]
pub async fn admin_get_router(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    router_id: u64,
) -> ApiResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    
    let router = db.admin_get_router(router_id).await?;

    let mut admin_router = AdminRouterDetail::from(router.clone());
    admin_router.access_policy_count = db.admin_count_router_access_policies(router.id).await
        .unwrap_or(0);

    ApiData::ok(admin_router)
}

#[post("/api/admin/v1/routers", data = "<request>")]
pub async fn admin_create_router(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<CreateRouterRequest>,
) -> ApiResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::Create)?;
    
    let router = request.to_router()?;

    let router_id = db.admin_create_router(&router).await?;

    let created_router = db.admin_get_router(router_id).await?;

    let admin_router = AdminRouterDetail::from(created_router);

    ApiData::ok(admin_router)
}

#[put("/api/admin/v1/routers/<router_id>", data = "<request>")]
pub async fn admin_update_router(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    router_id: u64,
    request: Json<UpdateRouterRequest>,
) -> ApiResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::Update)?;
    
    // Fetch the existing router
    let mut router = db.admin_get_router(router_id).await?;

    // Update fields that are provided
    if let Some(name) = &request.name {
        router.name = name.trim().to_string();
    }
    if let Some(enabled) = request.enabled {
        router.enabled = enabled;
    }
    if let Some(kind) = &request.kind {
        router.kind = match kind {
            AdminRouterKind::Mikrotik => lnvps_db::RouterKind::Mikrotik,
            AdminRouterKind::OvhAdditionalIp => lnvps_db::RouterKind::OvhAdditionalIp,
        };
    }
    if let Some(url) = &request.url {
        router.url = url.trim().to_string();
    }
    if let Some(token) = &request.token {
        router.token = token.clone();
    }

    db.admin_update_router(&router).await?;

    let updated_router = db.admin_get_router(router_id).await?;

    let mut admin_router = AdminRouterDetail::from(updated_router.clone());
    admin_router.access_policy_count = db.admin_count_router_access_policies(updated_router.id).await
        .unwrap_or(0);

    ApiData::ok(admin_router)
}

#[delete("/api/admin/v1/routers/<router_id>")]
pub async fn admin_delete_router(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    router_id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::Delete)?;
    
    db.admin_delete_router(router_id).await?;

    ApiData::ok(())
}