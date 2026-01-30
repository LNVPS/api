use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminRouterDetail, AdminRouterKind, CreateRouterRequest, UpdateRouterRequest,
};
use crate::admin::{PageQuery, RouterState};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/routers",
            get(admin_list_routers).post(admin_create_router),
        )
        .route(
            "/api/admin/v1/routers/{id}",
            get(admin_get_router)
                .patch(admin_update_router)
                .delete(admin_delete_router),
        )
}

async fn admin_list_routers(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let (routers, total) = this.db.admin_list_routers_paginated(limit, offset).await?;

    // Convert to admin models and populate access policy counts
    let mut admin_routers = Vec::new();
    for router in routers {
        let mut admin_router = AdminRouterDetail::from(router.clone());
        admin_router.access_policy_count = this
            .db
            .admin_count_router_access_policies(router.id)
            .await
            .unwrap_or(0);
        admin_routers.push(admin_router);
    }

    ApiPaginatedData::ok(admin_routers, total, limit, offset)
}

async fn admin_get_router(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
) -> ApiResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::View)?;

    let router = this.db.admin_get_router(router_id).await?;

    let mut admin_router = AdminRouterDetail::from(router.clone());
    admin_router.access_policy_count = this
        .db
        .admin_count_router_access_policies(router.id)
        .await
        .unwrap_or(0);

    ApiData::ok(admin_router)
}

async fn admin_create_router(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<CreateRouterRequest>,
) -> ApiResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::Create)?;

    let router = request.to_router()?;

    let router_id = this.db.admin_create_router(&router).await?;

    let created_router = this.db.admin_get_router(router_id).await?;

    let admin_router = AdminRouterDetail::from(created_router);

    ApiData::ok(admin_router)
}

async fn admin_update_router(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
    Json(request): Json<UpdateRouterRequest>,
) -> ApiResult<AdminRouterDetail> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::Update)?;

    // Fetch the existing router
    let mut router = this.db.admin_get_router(router_id).await?;

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
        router.token = token.as_str().into();
    }

    this.db.admin_update_router(&router).await?;

    let updated_router = this.db.admin_get_router(router_id).await?;

    let mut admin_router = AdminRouterDetail::from(updated_router.clone());
    admin_router.access_policy_count = this
        .db
        .admin_count_router_access_policies(updated_router.id)
        .await
        .unwrap_or(0);

    ApiData::ok(admin_router)
}

async fn admin_delete_router(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Router, AdminAction::Delete)?;

    this.db.admin_delete_router(router_id).await?;

    ApiData::ok(())
}
