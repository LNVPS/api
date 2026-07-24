//! Customer-facing **managed app** endpoints (read-only).
//!
//! Browse the app catalog and view your own deployments. Ordering, lifecycle
//! control and the operator reconcile land in later increments.

use crate::api::RouterState;
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiData, ApiError, ApiIntervalType, ApiResult, Nip98Auth};
use lnvps_db::{App, AppDeployment, LNVpsDb};
use serde::Serialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/apps", get(v1_list_apps))
        .route("/api/v1/apps/{id}", get(v1_get_app))
        .route("/api/v1/app-deployments", get(v1_list_app_deployments))
        .route("/api/v1/app-deployments/{id}", get(v1_get_app_deployment))
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
async fn v1_list_apps(_auth: Nip98Auth, State(this): State<RouterState>) -> ApiResult<Vec<ApiApp>> {
    let apps = this.db.list_apps(true).await?;
    ApiData::ok(apps.into_iter().map(Into::into).collect())
}

/// Get a single enabled catalog app.
async fn v1_get_app(
    _auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiApp> {
    let app = this.db.get_app(id).await?;
    if !app.enabled {
        return Err(ApiError::not_found("App not found"));
    }
    ApiData::ok(app.into())
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
