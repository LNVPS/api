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

/// Validate a catalog app's user-provided fields, including a full parse of the
/// `compose` document using the shared `lnvps_compose` parser — the same code
/// the operator uses to render Kubernetes objects — so an invalid or unsafe
/// compose (bad ingress protocol, traversal mount path, unknown `depends_on`,
/// …) is rejected at catalog-edit time instead of failing later at deploy.
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
    if let Err(e) = lnvps_compose::Compose::parse(compose) {
        return Err(lnvps_api_common::ApiError::new(format!(
            "invalid compose: {e}"
        )));
    }
    if currency.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("currency is required"));
    }
    Ok(())
}

/// Parse the compose and compute the app's resource footprint (already
/// validated by `validate_app_fields`).
fn compose_footprint(
    compose: &str,
) -> Result<lnvps_compose::Footprint, lnvps_api_common::ApiError> {
    let c = lnvps_compose::Compose::parse(compose)
        .map_err(|e| lnvps_api_common::ApiError::new(format!("invalid compose: {e}")))?;
    c.footprint()
        .map_err(|e| lnvps_api_common::ApiError::new(format!("invalid compose resources: {e}")))
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
    let footprint = compose_footprint(&req.compose)?;

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
        cpu_milli: footprint.cpu_milli,
        memory_bytes: footprint.memory_bytes,
        storage_bytes: footprint.storage_bytes,
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
    // Recompute the footprint from the (possibly updated) compose.
    let footprint = compose_footprint(&app.compose)?;
    app.cpu_milli = footprint.cpu_milli;
    app.memory_bytes = footprint.memory_bytes;
    app.storage_bytes = footprint.storage_bytes;
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
        capacity_cpu_milli: req.capacity_cpu_milli,
        capacity_memory_bytes: req.capacity_memory_bytes,
        capacity_storage_bytes: req.capacity_storage_bytes,
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
    if let Some(v) = req.capacity_cpu_milli {
        cluster.capacity_cpu_milli = v;
    }
    if let Some(v) = req.capacity_memory_bytes {
        cluster.capacity_memory_bytes = v;
    }
    if let Some(v) = req.capacity_storage_bytes {
        cluster.capacity_storage_bytes = v;
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

    const VALID_COMPOSE: &str = "services:\n  relay:\n    image: example/relay:latest\n";

    #[test]
    fn test_validate_app_fields() {
        // Happy path (valid compose).
        assert!(validate_app_fields("nostr-relay", "Relay", VALID_COMPOSE, "USD").is_ok());
        assert!(validate_app_fields("relay2", "R", VALID_COMPOSE, "btc").is_ok());

        // Bad name: empty / uppercase / bad chars / leading-trailing hyphen.
        assert!(validate_app_fields("", "R", VALID_COMPOSE, "USD").is_err());
        assert!(validate_app_fields("Relay", "R", VALID_COMPOSE, "USD").is_err());
        assert!(validate_app_fields("re lay", "R", VALID_COMPOSE, "USD").is_err());
        assert!(validate_app_fields("-relay", "R", VALID_COMPOSE, "USD").is_err());
        assert!(validate_app_fields("relay-", "R", VALID_COMPOSE, "USD").is_err());

        // Missing other required fields.
        assert!(validate_app_fields("relay", "  ", VALID_COMPOSE, "USD").is_err());
        assert!(validate_app_fields("relay", "R", "   ", "USD").is_err());
        assert!(validate_app_fields("relay", "R", VALID_COMPOSE, "  ").is_err());

        // Invalid compose is rejected by the shared parser.
        assert!(validate_app_fields("relay", "R", "services: {}", "USD").is_err());
        assert!(
            validate_app_fields(
                "relay",
                "R",
                "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 5, protocol: tcp, expose: ingress }\n",
                "USD"
            )
            .is_err()
        );
    }
}
