//! Customer-facing **managed app** endpoints (read-only).
//!
//! Browse the app catalog and view your own deployments. Ordering, lifecycle
//! control and the operator reconcile land in later increments.

use crate::api::RouterState;
use axum::extract::{Path, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiIntervalType, ApiResult, AppCapacity, AppClusterCapacityService,
    Nip98Auth,
};
use lnvps_db::{
    App, AppDeployment, AppDeploymentDesiredState, AppDeploymentStatus, EncryptedString, LNVpsDb,
    Subscription, SubscriptionLineItem, SubscriptionType,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/apps", get(v1_list_apps))
        .route("/api/v1/apps/{id}", get(v1_get_app))
        .route("/api/v1/apps/{id}/regions", get(v1_list_app_regions))
        .route(
            "/api/v1/app-deployments",
            get(v1_list_app_deployments).post(v1_create_app_deployment),
        )
        .route(
            "/api/v1/app-deployments/{id}",
            get(v1_get_app_deployment).delete(v1_delete_app_deployment),
        )
        .route(
            "/api/v1/app-deployments/{id}/start",
            patch(v1_start_app_deployment),
        )
        .route(
            "/api/v1/app-deployments/{id}/stop",
            patch(v1_stop_app_deployment),
        )
}

/// A catalog app offered for deployment.
#[derive(Serialize)]
pub struct ApiApp {
    pub id: u64,
    /// URL/DNS-safe slug.
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    /// docker-compose-style YAML defining the app. Clients render the
    /// configuration form (ports/env) from this spec.
    pub compose: String,
    /// Recurring price in the smallest currency unit (cents / millisats).
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
    /// One-off setup fee in the smallest currency unit (0 = none).
    pub setup_amount: u64,
}

impl From<App> for ApiApp {
    fn from(a: App) -> Self {
        Self {
            id: a.id,
            name: a.name,
            display_name: a.display_name,
            description: a.description,
            icon: a.icon,
            compose: a.compose,
            amount: a.amount,
            currency: a.currency,
            interval_amount: a.interval_amount,
            interval_type: a.interval_type.into(),
            setup_amount: a.setup_amount,
        }
    }
}

/// A region an app can be deployed in.
#[derive(Serialize)]
pub struct ApiAppRegion {
    pub id: u64,
    pub name: String,
    /// Whether a cluster in this region currently has enough free capacity for
    /// this app. `false` regions can be shown-but-disabled in the picker.
    pub available: bool,
}

/// A customer's app deployment.
#[derive(Serialize)]
pub struct ApiAppDeployment {
    pub id: u64,
    /// Catalog app this deployment runs.
    pub app_id: u64,
    /// User-chosen instance name.
    pub name: String,
    /// Public endpoint hostname once assigned (`None` until reconciled or for
    /// apps with no ingress port).
    pub hostname: Option<String>,
    /// Desired run state: `running` or `stopped`.
    pub desired_state: String,
    /// Observed status: `pending`, `running`, `stopped`, `error`, `deleting`.
    pub status: String,
    /// Human-readable status/error detail from the operator, when present.
    pub status_message: Option<String>,
    /// Subscription this deployment is billed under (renew via the subscription
    /// endpoints). `None` if the subscription can't be resolved.
    pub subscription_id: Option<u64>,
    pub created: DateTime<Utc>,
}

async fn deployment_to_api(this: &RouterState, d: AppDeployment) -> ApiAppDeployment {
    // Resolve the owning subscription from the line item (best-effort).
    let subscription_id = this
        .db
        .get_subscription_by_line_item_id(d.subscription_line_item_id)
        .await
        .ok()
        .map(|s| s.id);
    ApiAppDeployment {
        id: d.id,
        app_id: d.app_id,
        name: d.name,
        hostname: d.hostname,
        desired_state: d.desired_state.to_string(),
        status: d.status.to_string(),
        status_message: d.status_message,
        subscription_id,
        created: d.created,
    }
}

/// List all enabled catalog apps.
///
/// Public (no auth) — the catalog is a shopping/marketing surface, mirroring
/// `GET /api/v1/vm/templates`.
async fn v1_list_apps(State(this): State<RouterState>) -> ApiResult<Vec<ApiApp>> {
    let apps = this.db.list_apps(true).await?;
    ApiData::ok(apps.into_iter().map(Into::into).collect())
}

/// Get a single enabled catalog app. Public (no auth), like the list.
async fn v1_get_app(State(this): State<RouterState>, Path(id): Path<u64>) -> ApiResult<ApiApp> {
    let app = this.db.get_app(id).await?;
    if !app.enabled {
        return Err(ApiError::not_found("App not found"));
    }
    ApiData::ok(app.into())
}

/// List the regions this app can be deployed in (regions with an enabled
/// cluster), each flagged with whether it currently has capacity for the app.
/// Public (no auth) so the deploy form can show availability pre-login.
async fn v1_list_app_regions(
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<ApiAppRegion>> {
    let app = this.db.get_app(id).await?;
    if !app.enabled {
        return Err(ApiError::not_found("App not found"));
    }
    let need = AppCapacity {
        cpu_milli: app.cpu_milli,
        memory_bytes: app.memory_bytes,
        storage_bytes: app.storage_bytes,
    };
    let capacity = AppClusterCapacityService::new(this.db.clone());
    let mut out = Vec::new();
    for (region_id, available) in capacity.regions_availability(need).await? {
        // Only surface enabled regions; skip any that can't be resolved.
        if let Ok(region) = this.db.get_host_region(region_id).await
            && region.enabled
        {
            out.push(ApiAppRegion {
                id: region.id,
                name: region.name,
                available,
            });
        }
    }
    ApiData::ok(out)
}

/// List the authenticated user's app deployments.
async fn v1_list_app_deployments(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiAppDeployment>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let deployments = this.db.list_user_app_deployments(uid).await?;
    let mut out = Vec::with_capacity(deployments.len());
    for d in deployments {
        out.push(deployment_to_api(&this, d).await);
    }
    ApiData::ok(out)
}

/// Get one of the authenticated user's app deployments.
async fn v1_get_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiAppDeployment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let deployment = this.db.get_app_deployment(id).await?;
    if deployment.user_id != uid || deployment.deleted {
        return Err(ApiError::not_found("Deployment not found"));
    }
    ApiData::ok(deployment_to_api(&this, deployment).await)
}

/// Order a new app deployment.
#[derive(Deserialize)]
pub struct CreateAppDeploymentRequest {
    /// Catalog app to deploy.
    pub app_id: u64,
    /// User-chosen DNS-safe instance name (becomes the subdomain).
    pub name: String,
    /// Region to deploy in; a cluster there with capacity is selected.
    pub region_id: u64,
    /// Values for the app's `config` fields.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

/// Validate `name` is a DNS-safe label usable as a subdomain.
fn validate_deployment_name(name: &str) -> Result<(), ApiError> {
    let n = name.trim();
    if n.is_empty() || n.len() > 40 {
        return Err(ApiError::new("name must be 1–40 characters"));
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || n.starts_with('-')
        || n.ends_with('-')
    {
        return Err(ApiError::new(
            "name must be a DNS-safe label (lowercase letters, digits, hyphens)",
        ));
    }
    Ok(())
}

/// Validate the submitted `config` against the app's compose `config` schema:
/// required fields must be present, unknown keys rejected; returns the resolved
/// map (submitted values ∪ declared defaults).
fn resolve_config(
    compose: &lnvps_compose::Compose,
    submitted: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ApiError> {
    let declared: std::collections::HashSet<&str> =
        compose.config.iter().map(|c| c.name.as_str()).collect();
    for key in submitted.keys() {
        if !declared.contains(key.as_str()) {
            return Err(ApiError::new(format!("unknown config field '{key}'")));
        }
    }
    let mut out = BTreeMap::new();
    for field in &compose.config {
        match submitted.get(&field.name).or(field.default.as_ref()) {
            Some(v) => {
                out.insert(field.name.clone(), v.clone());
            }
            None if field.required => {
                return Err(ApiError::new(format!(
                    "config field '{}' is required",
                    field.name
                )));
            }
            None => {}
        }
    }
    Ok(out)
}

async fn v1_create_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<CreateAppDeploymentRequest>,
) -> ApiResult<ApiAppDeployment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;

    let app = this.db.get_app(req.app_id).await?;
    if !app.enabled {
        return Err(ApiError::new("App is not available"));
    }
    validate_deployment_name(&req.name)?;

    // Validate config against the app's compose schema.
    let compose = lnvps_compose::Compose::parse(&app.compose)
        .map_err(|e| ApiError::new(format!("app compose is invalid: {e}")))?;
    let config = resolve_config(&compose, &req.config)?;

    // Capacity admission: pick an enabled cluster in the region with room for
    // the app's footprint.
    let need = AppCapacity {
        cpu_milli: app.cpu_milli,
        memory_bytes: app.memory_bytes,
        storage_bytes: app.storage_bytes,
    };
    let capacity = AppClusterCapacityService::new(this.db.clone());
    let Some(cluster) = capacity.select_in_region(req.region_id, need).await? else {
        return Err(ApiError::new(
            "No cluster with enough capacity is available in this region",
        ));
    };
    let region = this.db.get_host_region(cluster.region_id).await?;

    // Create the subscription + App line item (billed via the standard
    // subscription payment flow — pay the returned subscription to activate).
    let subscription = Subscription {
        id: 0,
        user_id: uid,
        company_id: region.company_id,
        name: format!("{} deployment", app.display_name),
        description: None,
        created: Utc::now(),
        expires: None,
        is_active: false,
        is_setup: false,
        currency: app.currency.clone(),
        interval_amount: app.interval_amount,
        interval_type: app.interval_type,
        setup_fee: app.setup_amount,
        auto_renewal_enabled: true,
        external_id: None,
    };
    let line_item = SubscriptionLineItem {
        id: 0,
        subscription_id: 0,
        subscription_type: SubscriptionType::App,
        name: app.display_name.clone(),
        description: None,
        amount: app.amount,
        setup_amount: app.setup_amount,
        configuration: None,
    };
    let (_sub_id, line_item_ids) = this
        .db
        .insert_subscription_with_line_items(&subscription, vec![line_item])
        .await?;
    let line_item_id = line_item_ids[0];

    // Config is stored encrypted (may hold secret values).
    let config_json = serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string());

    let mut deployment = AppDeployment {
        id: 0,
        user_id: uid,
        app_id: app.id,
        cluster_id: cluster.id,
        subscription_line_item_id: line_item_id,
        name: req.name.trim().to_string(),
        // Temporary unique namespace; finalized to `app-{id}` below.
        namespace: format!("app-pending-{line_item_id}"),
        hostname: None,
        config: Some(EncryptedString::new(config_json)),
        desired_state: AppDeploymentDesiredState::Running,
        status: AppDeploymentStatus::Pending,
        status_message: None,
        created: Utc::now(),
        deleted: false,
    };
    let id = this.db.insert_app_deployment(&deployment).await?;
    // Finalize the namespace to the operator's derived form.
    deployment.id = id;
    deployment.namespace = format!("app-{id}");
    this.db.update_app_deployment(&deployment).await?;

    ApiData::ok(deployment_to_api(&this, deployment).await)
}

/// Resolve and ownership-check a deployment for the authenticated user.
async fn owned_deployment(
    this: &RouterState,
    uid: u64,
    id: u64,
) -> Result<AppDeployment, ApiError> {
    let d = this.db.get_app_deployment(id).await?;
    if d.user_id != uid || d.deleted {
        return Err(ApiError::not_found("Deployment not found"));
    }
    Ok(d)
}

async fn v1_delete_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<bool> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let deployment = owned_deployment(&this, uid, id).await?;

    // Stop billing: deactivate the subscription, then soft-delete the
    // deployment (the operator tears down the namespace + volumes on its next
    // reconcile).
    if let Ok(mut sub) = this
        .db
        .get_subscription_by_line_item_id(deployment.subscription_line_item_id)
        .await
    {
        sub.is_active = false;
        sub.auto_renewal_enabled = false;
        let _ = this.db.update_subscription(&sub).await;
    }
    this.db.delete_app_deployment(id).await?;
    ApiData::ok(true)
}

async fn set_desired_state(
    this: &RouterState,
    uid: u64,
    id: u64,
    state: AppDeploymentDesiredState,
) -> ApiResult<ApiAppDeployment> {
    let mut deployment = owned_deployment(this, uid, id).await?;
    deployment.desired_state = state;
    this.db.update_app_deployment(&deployment).await?;
    ApiData::ok(deployment_to_api(this, deployment).await)
}

async fn v1_start_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiAppDeployment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    set_desired_state(&this, uid, id, AppDeploymentDesiredState::Running).await
}

async fn v1_stop_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiAppDeployment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    set_desired_state(&this, uid, id, AppDeploymentDesiredState::Stopped).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_deployment_name() {
        assert!(validate_deployment_name("my-relay").is_ok());
        assert!(validate_deployment_name("relay1").is_ok());
        assert!(validate_deployment_name("").is_err());
        assert!(validate_deployment_name("Relay").is_err());
        assert!(validate_deployment_name("re lay").is_err());
        assert!(validate_deployment_name("-relay").is_err());
        assert!(validate_deployment_name("relay-").is_err());
        assert!(validate_deployment_name(&"a".repeat(41)).is_err());
    }

    #[test]
    fn test_resolve_config() {
        let compose = lnvps_compose::Compose::parse(
            "services:\n  a:\n    image: x\nconfig:\n  - { name: relay_name, type: string, required: true }\n  - { name: max_mb, type: int, default: \"100\" }\n",
        )
        .unwrap();

        // Required present + default filled.
        let mut submitted = BTreeMap::new();
        submitted.insert("relay_name".to_string(), "Zap".to_string());
        let resolved = resolve_config(&compose, &submitted).ok().unwrap();
        assert_eq!(resolved.get("relay_name").unwrap(), "Zap");
        assert_eq!(resolved.get("max_mb").unwrap(), "100");

        // Missing required -> error.
        assert!(resolve_config(&compose, &BTreeMap::new()).is_err());

        // Unknown key -> error.
        let mut bad = submitted.clone();
        bad.insert("nope".to_string(), "x".to_string());
        assert!(resolve_config(&compose, &bad).is_err());

        // Submitted overrides default.
        let mut over = submitted.clone();
        over.insert("max_mb".to_string(), "500".to_string());
        let resolved = resolve_config(&compose, &over).ok().unwrap();
        assert_eq!(resolved.get("max_mb").unwrap(), "500");
    }
}
