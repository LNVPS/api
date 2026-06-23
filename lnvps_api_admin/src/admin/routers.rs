use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminRouterBgpRoute, AdminRouterBgpSession, AdminRouterDetail, AdminRouterTunnel,
    AdminRouterTunnelTraffic, CreateRouterRequest, JobResponse, SetDefaultRouteRequest,
    ToggleBgpSessionRequest, UpdateRouterRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, TimeDelta, Utc};
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery, WorkJob,
};
use lnvps_db::{AdminAction, AdminResource};
use log::{error, info};
use serde::Deserialize;

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
        .route(
            "/api/admin/v1/routers/{id}/tunnels",
            get(admin_list_router_tunnels),
        )
        .route(
            "/api/admin/v1/routers/{id}/tunnels/{name}/traffic",
            get(admin_get_tunnel_traffic),
        )
        .route(
            "/api/admin/v1/routers/{id}/bgp/sessions",
            get(admin_list_bgp_sessions),
        )
        .route(
            "/api/admin/v1/routers/{id}/bgp/routes",
            get(admin_list_bgp_routes),
        )
        .route(
            "/api/admin/v1/routers/{id}/bgp/sessions/toggle",
            post(admin_toggle_bgp_session),
        )
        .route(
            "/api/admin/v1/routers/{id}/routes/default",
            post(admin_set_default_route).delete(admin_clear_default_route),
        )
}

/// Time-range filter for traffic history (defaults to the last 24 hours)
#[derive(Deserialize)]
struct TrafficQuery {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

async fn admin_list_router_tunnels(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
) -> ApiResult<Vec<AdminRouterTunnel>> {
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    let tunnels = this.db.list_router_tunnels(router_id).await?;
    ApiData::ok(tunnels.into_iter().map(AdminRouterTunnel::from).collect())
}

async fn admin_get_tunnel_traffic(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((router_id, name)): Path<(u64, String)>,
    Query(q): Query<TrafficQuery>,
) -> ApiResult<Vec<AdminRouterTunnelTraffic>> {
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    let to = q.to.unwrap_or_else(Utc::now);
    let from = q.from.unwrap_or_else(|| to - TimeDelta::hours(24));
    let samples = this
        .db
        .list_router_tunnel_traffic(router_id, &name, from, to)
        .await?;
    ApiData::ok(
        samples
            .into_iter()
            .map(AdminRouterTunnelTraffic::from)
            .collect(),
    )
}

async fn admin_list_bgp_sessions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
) -> ApiResult<Vec<AdminRouterBgpSession>> {
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    let sessions = this.db.list_router_bgp_sessions(router_id).await?;
    ApiData::ok(
        sessions
            .into_iter()
            .map(AdminRouterBgpSession::from)
            .collect(),
    )
}

async fn admin_list_bgp_routes(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
) -> ApiResult<Vec<AdminRouterBgpRoute>> {
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    let routes = this.db.list_router_bgp_routes(router_id).await?;
    ApiData::ok(routes.into_iter().map(AdminRouterBgpRoute::from).collect())
}

async fn admin_set_default_route(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
    Json(request): Json<SetDefaultRouteRequest>,
) -> ApiResult<JobResponse> {
    auth.require_permission(AdminResource::Router, AdminAction::Update)?;
    let next_hop = request.next_hop.trim().to_string();
    if next_hop.parse::<std::net::IpAddr>().is_err() {
        return ApiData::err("next_hop must be a valid IP address");
    }
    let job = WorkJob::SetRouterDefaultRoute {
        router_id,
        next_hop,
    };
    match this.work_commander.send(job).await {
        Ok(stream_id) => {
            info!("Set default route job queued with stream ID: {}", stream_id);
            ApiData::ok(JobResponse { job_id: stream_id })
        }
        Err(e) => {
            error!("Failed to queue set default route job: {}", e);
            ApiData::err("Failed to queue set default route job")
        }
    }
}

async fn admin_clear_default_route(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
) -> ApiResult<JobResponse> {
    auth.require_permission(AdminResource::Router, AdminAction::Update)?;
    let job = WorkJob::ClearRouterDefaultRoute { router_id };
    match this.work_commander.send(job).await {
        Ok(stream_id) => {
            info!(
                "Clear default route job queued with stream ID: {}",
                stream_id
            );
            ApiData::ok(JobResponse { job_id: stream_id })
        }
        Err(e) => {
            error!("Failed to queue clear default route job: {}", e);
            ApiData::err("Failed to queue clear default route job")
        }
    }
}

async fn admin_toggle_bgp_session(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(router_id): Path<u64>,
    Json(request): Json<ToggleBgpSessionRequest>,
) -> ApiResult<JobResponse> {
    auth.require_permission(AdminResource::Router, AdminAction::Update)?;
    let job = WorkJob::ToggleBgpSession {
        router_id,
        session_id: request.session_id,
        enabled: request.enabled,
    };
    match this.work_commander.send(job).await {
        Ok(stream_id) => {
            info!("BGP toggle job queued with stream ID: {}", stream_id);
            ApiData::ok(JobResponse { job_id: stream_id })
        }
        Err(e) => {
            error!("Failed to queue BGP toggle job: {}", e);
            ApiData::err("Failed to queue BGP toggle job")
        }
    }
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
        router.kind = lnvps_db::RouterKind::from(*kind);
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
