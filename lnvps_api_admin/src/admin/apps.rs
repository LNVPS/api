use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminAppClusterInfo, AdminAppInfo, AdminCreateAppClusterRequest, AdminCreateAppRequest,
    AdminUpdateAppClusterRequest, AdminUpdateAppRequest,
};
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiResult};
use lnvps_db::{AdminAction, AdminResource, App, AppCluster};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/apps",
            get(admin_list_apps).post(admin_create_app),
        )
        .route(
            "/api/admin/v1/apps/{id}",
            get(admin_get_app)
                .patch(admin_update_app)
                .delete(admin_delete_app),
        )
        .route(
            "/api/admin/v1/app_clusters",
            get(admin_list_app_clusters).post(admin_create_app_cluster),
        )
        .route(
            "/api/admin/v1/app_clusters/{id}",
            get(admin_get_app_cluster)
                .patch(admin_update_app_cluster)
                .delete(admin_delete_app_cluster),
        )
}

/// Validate a catalog app's user-provided fields. `compose` is only checked for
/// non-emptiness here; the full compose schema (services/ports/env) is validated
/// by the operator when it reconciles a deployment.
fn validate_app_fields(
    name: &str,
    display_name: &str,
    compose: &str,
    currency: &str,
) -> Result<(), lnvps_api_common::ApiError> {
    if name.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("name is required"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        return Err(lnvps_api_common::ApiError::new(
            "name must be a DNS-safe slug (lowercase letters, digits, hyphens)",
        ));
    }
    if display_name.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("display_name is required"));
    }
    if compose.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("compose is required"));
    }
    if currency.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("currency is required"));
    }
    Ok(())
}

async fn admin_list_apps(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<AdminAppInfo>> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;
    let apps = this.db.list_apps(false).await?;
    ApiData::ok(apps.into_iter().map(Into::into).collect())
}

async fn admin_get_app(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAppInfo> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;
    let app = this.db.get_app(id).await?;
    ApiData::ok(app.into())
}

async fn admin_create_app(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<AdminCreateAppRequest>,
) -> ApiResult<AdminAppInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Create)?;
    validate_app_fields(&req.name, &req.display_name, &req.compose, &req.currency)?;

    let app = App {
        id: 0,
        name: req.name.trim().to_string(),
        display_name: req.display_name,
        description: req.description,
        icon: req.icon,
        compose: req.compose,
        amount: req.amount,
        currency: req.currency.trim().to_uppercase(),
        interval_amount: req.interval_amount,
        interval_type: req.interval_type.into(),
        setup_amount: req.setup_amount,
        enabled: req.enabled,
        created: chrono::Utc::now(),
    };
    let id = this.db.insert_app(&app).await?;
    ApiData::ok(this.db.get_app(id).await?.into())
}

async fn admin_update_app(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateAppRequest>,
) -> ApiResult<AdminAppInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Update)?;
    let mut app = this.db.get_app(id).await?;

    if let Some(name) = req.name {
        app.name = name.trim().to_string();
    }
    if let Some(display_name) = req.display_name {
        app.display_name = display_name;
    }
    if let Some(description) = req.description {
        app.description = description.filter(|s| !s.trim().is_empty());
    }
    if let Some(icon) = req.icon {
        app.icon = icon.filter(|s| !s.trim().is_empty());
    }
    if let Some(compose) = req.compose {
        app.compose = compose;
    }
    if let Some(amount) = req.amount {
        app.amount = amount;
    }
    if let Some(currency) = req.currency {
        app.currency = currency.trim().to_uppercase();
    }
    if let Some(interval_amount) = req.interval_amount {
        app.interval_amount = interval_amount;
    }
    if let Some(interval_type) = req.interval_type {
        app.interval_type = interval_type.into();
    }
    if let Some(setup_amount) = req.setup_amount {
        app.setup_amount = setup_amount;
    }
    if let Some(enabled) = req.enabled {
        app.enabled = enabled;
    }

    validate_app_fields(&app.name, &app.display_name, &app.compose, &app.currency)?;
    this.db.update_app(&app).await?;
    ApiData::ok(this.db.get_app(id).await?.into())
}

async fn admin_delete_app(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<bool> {
    auth.require_permission(AdminResource::App, AdminAction::Delete)?;
    this.db.get_app(id).await?;

    // Refuse to delete an app that still has deployments (would orphan them /
    // violate the FK). Operators should disable it instead.
    let has_deployments = this
        .db
        .list_all_app_deployments()
        .await?
        .into_iter()
        .any(|d| d.app_id == id);
    if has_deployments {
        return Err(lnvps_api_common::ApiError::new(
            "cannot delete an app with existing deployments; disable it instead",
        ));
    }

    this.db.delete_app(id).await?;
    ApiData::ok(true)
}

// ----- App clusters -----

async fn admin_list_app_clusters(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<AdminAppClusterInfo>> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;
    let clusters = this.db.list_app_clusters(false).await?;
    ApiData::ok(clusters.into_iter().map(Into::into).collect())
}

async fn admin_get_app_cluster(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAppClusterInfo> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;
    ApiData::ok(this.db.get_app_cluster(id).await?.into())
}

async fn admin_create_app_cluster(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<AdminCreateAppClusterRequest>,
) -> ApiResult<AdminAppClusterInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Create)?;
    if req.name.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("name is required"));
    }
    if req.ingress_domain.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new(
            "ingress_domain is required",
        ));
    }
    // Region must exist (drives billing company); surfaces a clear error early.
    this.db.get_host_region(req.region_id).await?;

    let cluster = AppCluster {
        id: 0,
        name: req.name.trim().to_string(),
        region_id: req.region_id,
        ingress_domain: req.ingress_domain.trim().to_string(),
        enabled: req.enabled,
        created: chrono::Utc::now(),
    };
    let id = this.db.insert_app_cluster(&cluster).await?;
    ApiData::ok(this.db.get_app_cluster(id).await?.into())
}

async fn admin_update_app_cluster(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateAppClusterRequest>,
) -> ApiResult<AdminAppClusterInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Update)?;
    let mut cluster = this.db.get_app_cluster(id).await?;

    if let Some(name) = req.name {
        cluster.name = name.trim().to_string();
    }
    if let Some(region_id) = req.region_id {
        this.db.get_host_region(region_id).await?;
        cluster.region_id = region_id;
    }
    if let Some(ingress_domain) = req.ingress_domain {
        cluster.ingress_domain = ingress_domain.trim().to_string();
    }
    if let Some(enabled) = req.enabled {
        cluster.enabled = enabled;
    }

    this.db.update_app_cluster(&cluster).await?;
    ApiData::ok(this.db.get_app_cluster(id).await?.into())
}

async fn admin_delete_app_cluster(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<bool> {
    auth.require_permission(AdminResource::App, AdminAction::Delete)?;
    this.db.get_app_cluster(id).await?;

    let has_deployments = this
        .db
        .list_all_app_deployments()
        .await?
        .into_iter()
        .any(|d| d.cluster_id == id);
    if has_deployments {
        return Err(lnvps_api_common::ApiError::new(
            "cannot delete a cluster with existing deployments; disable it instead",
        ));
    }

    this.db.delete_app_cluster(id).await?;
    ApiData::ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_app_fields() {
        // Happy path.
        assert!(validate_app_fields("nostr-relay", "Relay", "services: {}", "USD").is_ok());
        assert!(validate_app_fields("relay2", "R", "x", "btc").is_ok());

        // Bad name: empty / uppercase / bad chars / leading-trailing hyphen.
        assert!(validate_app_fields("", "R", "c", "USD").is_err());
        assert!(validate_app_fields("Relay", "R", "c", "USD").is_err());
        assert!(validate_app_fields("re lay", "R", "c", "USD").is_err());
        assert!(validate_app_fields("-relay", "R", "c", "USD").is_err());
        assert!(validate_app_fields("relay-", "R", "c", "USD").is_err());

        // Missing other required fields.
        assert!(validate_app_fields("relay", "  ", "c", "USD").is_err());
        assert!(validate_app_fields("relay", "R", "   ", "USD").is_err());
        assert!(validate_app_fields("relay", "R", "c", "  ").is_err());
    }
}
