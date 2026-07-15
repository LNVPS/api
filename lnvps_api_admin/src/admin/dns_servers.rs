use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminDnsServerDetail, CreateDnsServerRequest, UpdateDnsServerRequest};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, DnsZone, PageQuery, get_dns_server,
};
use lnvps_db::{AdminAction, AdminResource};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/dns_servers",
            get(admin_list_dns_servers).post(admin_create_dns_server),
        )
        .route(
            "/api/admin/v1/dns_servers/{id}",
            get(admin_get_dns_server)
                .patch(admin_update_dns_server)
                .delete(admin_delete_dns_server),
        )
        .route(
            "/api/admin/v1/dns_servers/{id}/zones",
            get(admin_list_dns_server_zones),
        )
}

async fn detail_with_count(this: &RouterState, dns: lnvps_db::DnsServer) -> AdminDnsServerDetail {
    let mut detail = AdminDnsServerDetail::from(dns.clone());
    detail.ip_range_count = this
        .db
        .count_dns_server_ip_ranges(dns.id)
        .await
        .unwrap_or(0);
    detail
}

async fn admin_list_dns_servers(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminDnsServerDetail> {
    auth.require_permission(AdminResource::DnsServer, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let (servers, total) = this.db.list_dns_servers_paginated(limit, offset).await?;

    let mut out = Vec::new();
    for server in servers {
        out.push(detail_with_count(&this, server).await);
    }

    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_dns_server(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(dns_server_id): Path<u64>,
) -> ApiResult<AdminDnsServerDetail> {
    auth.require_permission(AdminResource::DnsServer, AdminAction::View)?;

    let server = this.db.get_dns_server(dns_server_id).await?;
    ApiData::ok(detail_with_count(&this, server).await)
}

async fn admin_create_dns_server(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<CreateDnsServerRequest>,
) -> ApiResult<AdminDnsServerDetail> {
    auth.require_permission(AdminResource::DnsServer, AdminAction::Create)?;

    if request.name.trim().is_empty() {
        return ApiData::err("Name cannot be empty");
    }
    if request.token.trim().is_empty() {
        return ApiData::err("Token cannot be empty");
    }

    let dns = request.to_dns_server();
    let id = this.db.insert_dns_server(&dns).await?;
    let created = this.db.get_dns_server(id).await?;

    ApiData::ok(detail_with_count(&this, created).await)
}

async fn admin_update_dns_server(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(dns_server_id): Path<u64>,
    Json(request): Json<UpdateDnsServerRequest>,
) -> ApiResult<AdminDnsServerDetail> {
    auth.require_permission(AdminResource::DnsServer, AdminAction::Update)?;

    let mut dns = this.db.get_dns_server(dns_server_id).await?;

    if let Some(name) = &request.name {
        dns.name = name.trim().to_string();
    }
    if let Some(enabled) = request.enabled {
        dns.enabled = enabled;
    }
    if let Some(kind) = &request.kind {
        dns.kind = lnvps_db::DnsServerKind::from(*kind);
    }
    if let Some(url) = &request.url {
        dns.url = url.trim().to_string();
    }
    if let Some(token) = &request.token {
        dns.token = token.as_str().into();
    }

    this.db.update_dns_server(&dns).await?;
    let updated = this.db.get_dns_server(dns_server_id).await?;

    ApiData::ok(detail_with_count(&this, updated).await)
}

async fn admin_list_dns_server_zones(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(dns_server_id): Path<u64>,
) -> ApiResult<Vec<DnsZone>> {
    auth.require_permission(AdminResource::DnsServer, AdminAction::View)?;

    let server = get_dns_server(&this.db, dns_server_id).await?;
    let zones = server.list_zones().await?;
    ApiData::ok(zones)
}

async fn admin_delete_dns_server(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(dns_server_id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::DnsServer, AdminAction::Delete)?;

    this.db.delete_dns_server(dns_server_id).await?;
    ApiData::ok(())
}
