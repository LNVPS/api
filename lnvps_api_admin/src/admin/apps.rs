use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminAppClusterInfo, AdminAppDeploymentInfo, AdminAppInfo, AdminCreateAppClusterRequest,
    AdminCreateAppRequest, AdminUpdateAppClusterRequest, AdminUpdateAppDeploymentRequest,
    AdminUpdateAppRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{
    AdminAction, AdminResource, App, AppCluster, AppDeploymentDesiredState, AppDeploymentFilter,
    AppDeploymentStatus,
};
use serde::Deserialize;

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
            "/api/admin/v1/app-deployments",
            get(admin_list_app_deployments),
        )
        .route(
            "/api/admin/v1/app-deployments/{id}",
            get(admin_get_app_deployment)
                .patch(admin_update_app_deployment)
                .delete(admin_delete_app_deployment),
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
    match lnvps_compose::Compose::parse(compose) {
        Err(e) => {
            return Err(lnvps_api_common::ApiError::new(format!(
                "invalid compose: {e}"
            )));
        }
        // Authoring-time only: every `${...}` must be declared. Checked here
        // rather than in `parse` so the operator can still render an app that
        // was stored before this rule existed (see validate_declarations).
        Ok(c) => {
            if let Err(e) = c.validate_declarations() {
                return Err(lnvps_api_common::ApiError::new(format!(
                    "invalid compose: {e}"
                )));
            }
        }
    }
    if currency.trim().is_empty() {
        return Err(lnvps_api_common::ApiError::new("currency is required"));
    }
    Ok(())
}

/// Trim and require a non-empty `category`.
///
/// Kept out of `validate_app_fields` because that helper takes what both
/// create and patch always have; `category` is required on create but merely
/// optional-to-send on patch, and both paths funnel through here so a blank
/// string cannot reach the column on either. Returning the trimmed value
/// rather than validating in place is what makes it impossible to store the
/// untrimmed one by accident.
fn validate_category(category: String) -> Result<String, lnvps_api_common::ApiError> {
    let category = category.trim();
    if category.is_empty() {
        return Err(lnvps_api_common::ApiError::new("category is required"));
    }
    Ok(category.to_string())
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

/// Query parameters for the catalog app listing. `app` has no soft-delete, so
/// there is no `include_deleted` here — `enabled` is the only visibility filter.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AppQuery {
    #[serde(flatten)]
    page: PageQuery,
    /// Filter by catalog-enabled flag; omit for all.
    enabled: Option<bool>,
    /// Case-insensitive substring match against name, display_name, description.
    search: Option<String>,
}

async fn admin_list_apps(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<AppQuery>,
) -> ApiPaginatedResult<AdminAppInfo> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;

    let limit = params.page.limit.unwrap_or(50).min(100);
    let offset = params.page.offset.unwrap_or(0);

    let (apps, total) = this
        .db
        .admin_list_apps_filtered(limit, offset, params.enabled, params.search.as_deref())
        .await?;
    ApiPaginatedData::ok(
        apps.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
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
    let category = validate_category(req.category)?;
    let footprint = compose_footprint(&req.compose)?;

    let app = App {
        id: 0,
        name: req.name.trim().to_string(),
        display_name: req.display_name,
        description: req.description,
        icon: req.icon,
        repo_url: req.repo_url.filter(|s| !s.trim().is_empty()),
        category,
        seo_title: req.seo_title.filter(|s| !s.trim().is_empty()),
        seo_description: req.seo_description.filter(|s| !s.trim().is_empty()),
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
    if let Some(repo_url) = req.repo_url {
        app.repo_url = repo_url.filter(|s| !s.trim().is_empty());
    }
    if let Some(category) = req.category {
        // `Some(None)` is an explicit null, which cannot be honoured on a
        // NOT NULL column — refuse it rather than no-op.
        let category = category
            .ok_or_else(|| lnvps_api_common::ApiError::new("category cannot be null"))?;
        app.category = validate_category(category)?;
    }
    if let Some(seo_title) = req.seo_title {
        app.seo_title = seo_title.filter(|s| !s.trim().is_empty());
    }
    if let Some(seo_description) = req.seo_description {
        app.seo_description = seo_description.filter(|s| !s.trim().is_empty());
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

// ----- App deployments -----

/// Query parameters for the deployment listing. All filters are optional and
/// combine with AND.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AppDeploymentQuery {
    #[serde(flatten)]
    page: PageQuery,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    app_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    cluster_id: Option<u64>,
    /// Matches deployments on any cluster in this region.
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    region_id: Option<u64>,
    /// Observed status: `pending`, `running`, `stopped`, `error`, `deleting`.
    status: Option<AppDeploymentStatus>,
    /// Desired run state: `running` or `stopped`.
    desired_state: Option<AppDeploymentDesiredState>,
    /// Case-insensitive substring match against name, hostname, custom_domain.
    search: Option<String>,
    /// Include soft-deleted deployments (default `false`). Deletion is a soft
    /// delete, so this is the only way to inspect a torn-down deployment.
    include_deleted: bool,
}

/// List app deployments across all users and clusters, for admin oversight and
/// support. Excludes the encrypted per-deployment config.
async fn admin_list_app_deployments(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<AppDeploymentQuery>,
) -> ApiPaginatedResult<AdminAppDeploymentInfo> {
    auth.require_permission(AdminResource::AppDeployment, AdminAction::View)?;

    let limit = params.page.limit.unwrap_or(50).min(100);
    let offset = params.page.offset.unwrap_or(0);

    let filter = AppDeploymentFilter {
        user_id: params.user_id,
        app_id: params.app_id,
        cluster_id: params.cluster_id,
        region_id: params.region_id,
        status: params.status,
        desired_state: params.desired_state,
        search: params.search,
        include_deleted: params.include_deleted,
    };
    let (deployments, total) = this
        .db
        .admin_list_app_deployments_filtered(limit, offset, &filter)
        .await?;
    ApiPaginatedData::ok(
        deployments.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

/// Decrypt and parse a deployment's stored config JSON into a flat map.
fn deployment_config_map(
    d: &lnvps_db::AppDeployment,
) -> Option<std::collections::BTreeMap<String, String>> {
    d.config.as_ref().and_then(|c| {
        serde_json::from_str::<std::collections::BTreeMap<String, String>>(c.as_str()).ok()
    })
}

/// Get a single app deployment, including its decrypted config (may hold
/// secret values — admin-only, `app_deployment::view`).
async fn admin_get_app_deployment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAppDeploymentInfo> {
    auth.require_permission(AdminResource::AppDeployment, AdminAction::View)?;
    let d = this.db.get_app_deployment(id).await?;
    let mut info = AdminAppDeploymentInfo::from(d.clone());
    info.config = deployment_config_map(&d);
    ApiData::ok(info)
}

/// Admin update of a deployment's name, custom_domain and/or config (partial;
/// `app_deployment::update`). Validation matches the customer PATCH endpoint —
/// the operator reconciles the change on its next loop.
async fn admin_update_app_deployment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateAppDeploymentRequest>,
) -> ApiResult<AdminAppDeploymentInfo> {
    auth.require_permission(AdminResource::AppDeployment, AdminAction::Update)?;
    let mut d = this.db.get_app_deployment(id).await?;

    // Rename: validate DNS-safe and enforce unique name per cluster.
    if let Some(new_name) = &req.name {
        let new_name = new_name.trim();
        lnvps_compose::validate_deployment_name(new_name)
            .map_err(|e| lnvps_api_common::ApiError::new(e.to_string()))?;
        if new_name != d.name {
            if let Some(existing) = this
                .db
                .find_app_deployment_by_cluster_name(d.cluster_id, new_name)
                .await?
                && existing.id != d.id
            {
                return Err(lnvps_api_common::ApiError::new(
                    "A deployment with this name already exists in this region",
                ));
            }
            d.name = new_name.to_string();
        }
    }

    // Config update: validate against the app's compose schema and store the
    // resolved map (encrypted — it may hold secret values).
    if let Some(submitted) = &req.config {
        let app = this.db.get_app(d.app_id).await?;
        let compose = lnvps_compose::Compose::parse(&app.compose)
            .map_err(|e| lnvps_api_common::ApiError::new(format!("app compose is invalid: {e}")))?;
        let config = lnvps_compose::resolve_config(&compose, submitted)
            .map_err(|e| lnvps_api_common::ApiError::new(e.to_string()))?;
        let config_json = serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string());
        d.config = Some(lnvps_db::EncryptedString::new(config_json));
    }

    // Custom domain: set (validated) or clear.
    if let Some(cd) = &req.custom_domain {
        d.custom_domain = match cd {
            Some(v) if !v.trim().is_empty() => Some(
                lnvps_compose::validate_custom_domain(v)
                    .map_err(|e| lnvps_api_common::ApiError::new(e.to_string()))?,
            ),
            _ => None,
        };
    }

    this.db.update_app_deployment(&d).await?;
    let mut info = AdminAppDeploymentInfo::from(d.clone());
    info.config = deployment_config_map(&d);
    ApiData::ok(info)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AdminDeleteAppDeploymentRequest {
    /// Permanently purge the deployment and all of its billing records
    /// (subscription, line items and payments) from the database, even if it
    /// has payment history. Requires the `super_admin` role. Never-paid
    /// deployments are purged regardless of this flag.
    purge: Option<bool>,
}

/// Delete an app deployment (`app_deployment::delete`).
///
/// The admin equivalent of the customer delete: billing is deactivated and the
/// row soft-deleted, and the operator tears the namespace and its volumes down
/// on its next reconcile. Teardown is driven by the deployment's absence from
/// the operator's active set, so a purged row is collected exactly like a
/// soft-deleted one — a purge does not orphan Kubernetes resources.
async fn admin_delete_app_deployment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    body: Option<Json<AdminDeleteAppDeploymentRequest>>,
) -> ApiResult<bool> {
    auth.require_permission(AdminResource::AppDeployment, AdminAction::Delete)?;

    // Purging a deployment with payment history is destructive and
    // irreversible, so it is restricted to super-admins. Authorize before
    // looking the deployment up, matching the VM purge.
    let purge = body.and_then(|b| b.purge).unwrap_or(false);
    if purge && !auth.is_super_admin(&this.db).await? {
        return Err(lnvps_api_common::ApiError::forbidden(
            "Only super admins can permanently purge an app deployment",
        ));
    }

    let deployment = this.db.get_app_deployment(id).await?;

    // An already-deleted deployment can still be purged (that is the point of a
    // purge). Only reject a plain delete of an already-deleted deployment.
    if deployment.deleted && !purge {
        return Err(lnvps_api_common::ApiError::conflict(
            "Deployment is already deleted",
        ));
    }

    // A deployment whose first payment was never confirmed carries no billing
    // history, so it is removed entirely — the same rule VMs use.
    let subscription = this
        .db
        .get_subscription_by_line_item_id(deployment.subscription_line_item_id)
        .await;
    let ever_paid = subscription.as_ref().map(|s| s.is_setup).unwrap_or(false);

    if purge || !ever_paid {
        this.db.hard_delete_app_deployment(id).await?;
    } else {
        // Stop billing, then soft-delete.
        if let Ok(mut sub) = subscription {
            sub.is_active = false;
            sub.auto_renewal_enabled = false;
            this.db.update_subscription(&sub).await?;
        }
        this.db.delete_app_deployment(id).await?;
    }
    ApiData::ok(true)
}

// ----- App clusters -----

/// Query parameters for the cluster listing. `app_cluster` has no soft-delete,
/// so `enabled` is the only visibility filter.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AppClusterQuery {
    #[serde(flatten)]
    page: PageQuery,
    /// Filter by accepting-new-deployments flag; omit for all.
    enabled: Option<bool>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    region_id: Option<u64>,
    /// Case-insensitive substring match against name and ingress_domain.
    search: Option<String>,
}

async fn admin_list_app_clusters(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<AppClusterQuery>,
) -> ApiPaginatedResult<AdminAppClusterInfo> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;

    let limit = params.page.limit.unwrap_or(50).min(100);
    let offset = params.page.offset.unwrap_or(0);

    let (clusters, total) = this
        .db
        .admin_list_app_clusters_filtered(
            limit,
            offset,
            params.enabled,
            params.region_id,
            params.search.as_deref(),
        )
        .await?;
    ApiPaginatedData::ok(
        clusters.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
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

    #[test]
    fn test_validate_category() {
        // Returns the trimmed value, so an untrimmed one cannot reach the
        // column: the stored string is rendered verbatim into `<title>`.
        assert_eq!(
            validate_category("  Nostr relay  ".to_string()).ok(),
            Some("Nostr relay".to_string())
        );
        assert_eq!(
            validate_category("Blossom media server".to_string()).ok(),
            Some("Blossom media server".to_string())
        );

        // Blank is rejected rather than stored: `category` is NOT NULL
        // precisely so a missing one cannot degrade silently into a generic
        // title, and "" would reintroduce exactly that.
        assert!(validate_category(String::new()).is_err());
        assert!(validate_category("   ".to_string()).is_err());
        assert!(validate_category("\t\n".to_string()).is_err());
    }
}
