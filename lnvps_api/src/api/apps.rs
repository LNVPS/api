//! Customer-facing **managed app** endpoints (read-only).
//!
//! Browse the app catalog and view your own deployments. Ordering, lifecycle
//! control and the operator reconcile land in later increments.

use crate::api::model::{ApiPrice, ApiSubscriptionPayment};
use crate::api::{PaymentMethodQuery, RouterState};
use axum::extract::{Path, Query, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiIntervalType, ApiResult, AppCapacity, AppClusterCapacityService,
    Nip98Auth,
};
use lnvps_db::{
    App, AppDeployment, AppDeploymentDesiredState, AppDeploymentStatus, EncryptedString,
    PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionType,
};
use payments_rs::currency::CurrencyAmount;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;

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
            get(v1_get_app_deployment)
                .patch(v1_patch_app_deployment)
                .delete(v1_delete_app_deployment),
        )
        .route(
            "/api/v1/app-deployments/{id}/start",
            patch(v1_start_app_deployment),
        )
        .route(
            "/api/v1/app-deployments/{id}/stop",
            patch(v1_stop_app_deployment),
        )
        .route(
            "/api/v1/app-deployments/{id}/upgrade-quote",
            post(v1_app_deployment_upgrade_quote),
        )
        .route(
            "/api/v1/app-deployments/{id}/upgrade",
            post(v1_app_deployment_upgrade),
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
    /// Canonical source repository URL (e.g. the project's GitHub), for a
    /// "Source" link / README rendering on the app-detail page.
    pub repo_url: Option<String>,
    /// Short, human-readable class of software (e.g. `Nostr relay`, `Blossom
    /// media server`). Free text, always present, never empty.
    ///
    /// Sentence case with proper nouns capitalised, carrying no article, no
    /// "hosting", no "managed" and no trailing punctuation — the client's
    /// template supplies those, e.g. `{display_name} Hosting — Managed
    /// {category}`. Also suitable for `Product.category` in structured data.
    pub category: String,
    /// Per-app override for the page `<title>`. Null for almost every app —
    /// clients should template from `display_name` + `category` and only use
    /// this when it is set. Never translated (see `seo_description`).
    pub seo_title: Option<String>,
    /// Per-app override for the page meta description. Null for almost every
    /// app. These strings arrive over the wire and so are never picked up by
    /// the client's message extraction: they are English-only by construction,
    /// which is why `category` carries the general case.
    pub seo_description: Option<String>,
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
    /// Total requested CPU in millicores, computed from the compose (issue #231).
    pub cpu_milli: u64,
    /// Total requested memory in bytes, computed from the compose.
    pub memory_bytes: u64,
    /// Total persistent volume size in bytes, computed from the compose.
    pub storage_bytes: u64,
    /// Per-service resource breakdown (sorted by name), summing to the totals
    /// above. Lets the UI show what each container in a multi-service app uses.
    pub services: Vec<ApiAppServiceResources>,
}

/// One service's share of an app's resource footprint.
#[derive(Serialize)]
pub struct ApiAppServiceResources {
    pub name: String,
    pub cpu_milli: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
}

impl From<App> for ApiApp {
    fn from(a: App) -> Self {
        // Per-service breakdown from the (already-validated) compose; best-effort.
        let services = lnvps_compose::Compose::parse(&a.compose)
            .ok()
            .and_then(|c| c.service_footprints().ok())
            .unwrap_or_default()
            .into_iter()
            .map(|s| ApiAppServiceResources {
                name: s.name,
                cpu_milli: s.cpu_milli,
                memory_bytes: s.memory_bytes,
                storage_bytes: s.storage_bytes,
            })
            .collect();
        Self {
            id: a.id,
            name: a.name,
            display_name: a.display_name,
            description: a.description,
            icon: a.icon,
            repo_url: a.repo_url,
            category: a.category,
            seo_title: a.seo_title,
            seo_description: a.seo_description,
            compose: a.compose,
            amount: a.amount,
            currency: a.currency,
            interval_amount: a.interval_amount,
            interval_type: a.interval_type.into(),
            setup_amount: a.setup_amount,
            cpu_milli: a.cpu_milli,
            memory_bytes: a.memory_bytes,
            storage_bytes: a.storage_bytes,
            services,
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
    /// Ingress base domain of a cluster in this region. The deploy form can
    /// preview the final hostname as `{name}.{ingress_domain}`.
    pub ingress_domain: String,
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
    /// Customer-owned domain (CNAME'd to `hostname`). When set, the operator
    /// serves it too and cert-manager issues a TLS cert for it (HTTP-01 once
    /// DNS resolves). `None` when unset.
    pub custom_domain: Option<String>,
    /// Desired run state: `running` or `stopped`.
    pub desired_state: String,
    /// Observed status: `pending`, `running`, `stopped`, `error`, `deleting`.
    pub status: String,
    /// Human-readable status/error detail from the operator, when present.
    pub status_message: Option<String>,
    /// Subscription this deployment is billed under (renew via the subscription
    /// endpoints). `None` if the subscription can't be resolved.
    pub subscription_id: Option<u64>,
    /// Size of this deployment as a multiple of the catalog app's base
    /// footprint and price. `1` = the base app. Increase it via
    /// `POST /api/v1/app-deployments/{id}/upgrade`.
    pub resource_multiplier: u32,
    /// Effective resources after applying `resource_multiplier`, so the UI does
    /// not have to multiply the catalog app's figures itself.
    pub cpu_milli: u64,
    pub memory_bytes: u64,
    pub storage_bytes: u64,
    /// Current customer-supplied `config` field values (issue #232), for
    /// prefilling the edit form so a config `PATCH` preserves untouched fields.
    /// Only the `config:` map — generated `secrets:` are never exposed. `None`
    /// if no config was stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<BTreeMap<String, String>>,
    pub created: DateTime<Utc>,
}

async fn deployment_to_api(
    this: &RouterState,
    d: AppDeployment,
) -> Result<ApiAppDeployment, ApiError> {
    // Resolve the owning subscription from the line item (best-effort).
    let subscription_id = this
        .db
        .get_subscription_by_line_item_id(d.subscription_line_item_id)
        .await
        .ok()
        .map(|s| s.id);
    // Decrypt and parse the stored config (customer-supplied field values only).
    let config = d
        .config
        .as_ref()
        .and_then(|c| serde_json::from_str::<BTreeMap<String, String>>(c.as_str()).ok());
    // Effective footprint = the catalog app's footprint x the multiplier.
    // `app_id` is a required foreign key, so a missing app is a broken
    // deployment row; propagate rather than reporting a zero footprint, which
    // the client would render as "0 CPU".
    let multiplier = d.resource_multiplier.max(1);
    let app = this.db.get_app(d.app_id).await?;
    let m = multiplier as u64;
    Ok(ApiAppDeployment {
        id: d.id,
        app_id: d.app_id,
        name: d.name,
        hostname: d.hostname,
        custom_domain: d.custom_domain,
        desired_state: d.desired_state.to_string(),
        status: d.status.to_string(),
        status_message: d.status_message,
        subscription_id,
        resource_multiplier: multiplier,
        cpu_milli: app.cpu_milli * m,
        memory_bytes: app.memory_bytes * m,
        storage_bytes: app.storage_bytes * m,
        config,
        created: d.created,
    })
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
    for r in capacity.regions_availability(need).await? {
        // Only surface enabled regions; skip any that can't be resolved.
        if let Ok(region) = this.db.get_host_region(r.region_id).await
            && region.enabled
        {
            out.push(ApiAppRegion {
                id: region.id,
                name: region.name,
                available: r.available,
                ingress_domain: r.ingress_domain,
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
        out.push(deployment_to_api(&this, d).await?);
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
    ApiData::ok(deployment_to_api(&this, deployment).await?)
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
    lnvps_compose::validate_deployment_name(name).map_err(|e| ApiError::new(e.to_string()))
}

/// Validate the submitted `config` against the app's compose `config` schema:
/// required fields must be present, unknown keys rejected; returns the resolved
/// map (submitted values ∪ declared defaults).
fn resolve_config(
    compose: &lnvps_compose::Compose,
    submitted: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ApiError> {
    lnvps_compose::resolve_config(compose, submitted).map_err(|e| ApiError::new(e.to_string()))
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

    // Enforce unique deployment name per cluster: the name becomes the ingress
    // hostname subdomain (`{name}.{ingress_domain}`), so a duplicate on the same
    // cluster would collide on routing and TLS. Checked against non-deleted
    // deployments so a name freed by deletion can be reused.
    let name = req.name.trim();
    if this
        .db
        .find_app_deployment_by_cluster_name(cluster.id, name)
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            "A deployment with this name already exists in this region",
        ));
    }

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
        resource_multiplier: 1,
        subscription_line_item_id: line_item_id,
        name: name.to_string(),
        // Temporary unique namespace; finalized to `app-{id}` below.
        namespace: format!("app-pending-{line_item_id}"),
        hostname: None,
        custom_domain: None,
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

    ApiData::ok(deployment_to_api(&this, deployment).await?)
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

/// Update an app deployment. All fields are optional — only those present are
/// changed (partial update).
#[derive(Deserialize)]
pub struct PatchAppDeploymentRequest {
    /// New instance name (becomes the ingress subdomain). Validated DNS-safe and
    /// checked unique on the cluster. Changing it changes the public hostname.
    #[serde(default)]
    pub name: Option<String>,
    /// New values for the app's `config` fields. When present, validated against
    /// the app's compose schema and defaults are filled, exactly like ordering —
    /// send the full desired config; it replaces the stored config wholesale.
    #[serde(default)]
    pub config: Option<BTreeMap<String, String>>,
    /// Set or clear the customer-owned domain. `Some("blog.example.com")` sets
    /// it (validated DNS-safe); `Some("")` or `Some(null)` clears it. When set,
    /// the operator serves the domain and cert-manager issues a TLS cert once
    /// the customer points a CNAME at the deployment's `hostname`. Absent =
    /// leave unchanged.
    #[serde(default)]
    pub custom_domain: Option<Option<String>>,
}

/// Validate a customer-supplied custom domain: lowercase DNS hostname, one or
/// more labels, no scheme/port/path. Returns the normalized (trimmed, lowercase)
/// domain.
fn validate_custom_domain(d: &str) -> Result<String, ApiError> {
    lnvps_compose::validate_custom_domain(d).map_err(|e| ApiError::new(e.to_string()))
}

/// Update a deployment's name and/or config. The operator re-applies the change
/// (hostname/ingress, secrets/env/configmap) and rolls the workload on its next
/// reconcile.
async fn v1_patch_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<PatchAppDeploymentRequest>,
) -> ApiResult<ApiAppDeployment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let mut deployment = owned_deployment(&this, uid, id).await?;

    // Rename: validate DNS-safe and enforce unique name per cluster (the name is
    // the ingress hostname subdomain). Skip the check when the name is unchanged.
    if let Some(new_name) = &req.name {
        let new_name = new_name.trim();
        validate_deployment_name(new_name)?;
        if new_name != deployment.name {
            if let Some(existing) = this
                .db
                .find_app_deployment_by_cluster_name(deployment.cluster_id, new_name)
                .await?
                && existing.id != deployment.id
            {
                return Err(ApiError::new(
                    "A deployment with this name already exists in this region",
                ));
            }
            deployment.name = new_name.to_string();
        }
    }

    // Config update: validate against the app's compose schema and store the
    // resolved map (encrypted — it may hold secret values).
    if let Some(submitted) = &req.config {
        let app = this.db.get_app(deployment.app_id).await?;
        let compose = lnvps_compose::Compose::parse(&app.compose)
            .map_err(|e| ApiError::new(format!("app compose is invalid: {e}")))?;
        let config = resolve_config(&compose, submitted)?;
        let config_json = serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string());
        deployment.config = Some(EncryptedString::new(config_json));
    }

    // Custom domain: set (validated) or clear. The operator reconciles the
    // Ingress + cert on its next loop; TLS is issued once the customer's CNAME
    // resolves to the deployment hostname.
    if let Some(cd) = &req.custom_domain {
        deployment.custom_domain = match cd {
            Some(d) if !d.trim().is_empty() => Some(validate_custom_domain(d)?),
            _ => None,
        };
    }

    this.db.update_app_deployment(&deployment).await?;
    ApiData::ok(deployment_to_api(&this, deployment).await?)
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
    ApiData::ok(deployment_to_api(this, deployment).await?)
}

async fn v1_start_app_deployment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiAppDeployment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    set_desired_state(&this, uid, id, AppDeploymentDesiredState::Running).await
}

/// Request to resize a deployment to a larger multiple of the app's base size.
#[derive(Deserialize)]
pub struct ApiAppUpgradeRequest {
    /// Desired size as a multiple of the catalog app's base footprint. Must be
    /// greater than the deployment's current `resource_multiplier`.
    pub resource_multiplier: u32,
}

/// Quoted cost of an app resize.
#[derive(Serialize)]
pub struct ApiAppUpgradeQuote {
    /// Prorated amount payable now (net, before tax) to run at the new size for
    /// the remainder of the current period.
    pub cost_difference: ApiPrice,
    /// What a full period will cost at the new size from the next renewal.
    pub new_renewal_cost: ApiPrice,
    /// Credit for the time already paid for at the current size.
    pub discount: ApiPrice,
    pub tax: ApiPrice,
    pub processing_fee: ApiPrice,
}

/// Largest size a deployment may be upgraded to, as a multiple of the base app.
///
/// A guard rail against a typo (`resource_multiplier: 1000`) quoting an
/// enormous invoice or exhausting a cluster; raise it if real demand appears.
const MAX_RESOURCE_MULTIPLIER: u32 = 16;

/// Validate an upgrade request and return the capacity delta it needs.
///
/// Shared by the quote and the payment endpoints so both enforce the same
/// rules: increase-only (PVCs cannot shrink), bounded, and the *additional*
/// footprint must fit on the cluster the deployment already runs on — it cannot
/// be moved, because its volumes live there.
async fn validate_app_upgrade(
    this: &RouterState,
    deployment: &AppDeployment,
    new_multiplier: u32,
) -> Result<(), ApiError> {
    let current = deployment.resource_multiplier.max(1);
    if new_multiplier <= current {
        return Err(ApiError::new(format!(
            "Resource multiplier can only be increased (current {current}, requested {new_multiplier})"
        )));
    }
    if new_multiplier > MAX_RESOURCE_MULTIPLIER {
        return Err(ApiError::new(format!(
            "Resource multiplier may not exceed {MAX_RESOURCE_MULTIPLIER}"
        )));
    }

    // An upgrade is prorated against the time left on the current period, so a
    // deployment that was never paid for (no expiry) or has already expired
    // cannot be quoted. Checked here so these return 400 with an actionable
    // message; reaching the pricing engine would surface them as a 500.
    let line_item = this
        .db
        .get_subscription_line_item(deployment.subscription_line_item_id)
        .await?;
    let subscription = this.db.get_subscription(line_item.subscription_id).await?;
    match subscription.expires {
        None => {
            return Err(ApiError::new(
                "This deployment has not been paid for yet, so there is no period to upgrade. Pay for it first, then upgrade.",
            ));
        }
        Some(expires) if expires <= Utc::now() => {
            return Err(ApiError::new(
                "This deployment has expired. Renew it before upgrading.",
            ));
        }
        Some(_) => {}
    }

    let app = this.db.get_app(deployment.app_id).await?;
    let delta = (new_multiplier - current) as u64;
    let need = AppCapacity {
        cpu_milli: app.cpu_milli * delta,
        memory_bytes: app.memory_bytes * delta,
        storage_bytes: app.storage_bytes * delta,
    };
    let capacity = AppClusterCapacityService::new(this.db.clone());
    if !capacity.fits(deployment.cluster_id, need).await? {
        return Err(ApiError::new(
            "The cluster this deployment runs on does not have enough free capacity for this upgrade",
        ));
    }
    Ok(())
}

/// Quote the prorated cost of resizing a deployment. Does not charge anything.
async fn v1_app_deployment_upgrade_quote(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiAppUpgradeRequest>,
) -> ApiResult<ApiAppUpgradeQuote> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let deployment = owned_deployment(&this, uid, id).await?;
    validate_app_upgrade(&this, &deployment, req.resource_multiplier).await?;

    let method = q
        .method
        .as_deref()
        .and_then(|m| PaymentMethod::from_str(m).ok())
        .unwrap_or(PaymentMethod::Lightning);
    let quote = this
        .sub_handler
        .pricing_engine()
        .calculate_app_upgrade_cost(id, req.resource_multiplier, method)
        .await?;

    let currency = quote.upgrade.amount.currency();
    ApiData::ok(ApiAppUpgradeQuote {
        cost_difference: quote.upgrade.amount.into(),
        new_renewal_cost: quote.renewal.amount.into(),
        discount: quote.discount.amount.into(),
        tax: CurrencyAmount::from_u64(currency, quote.tax.amount).into(),
        processing_fee: CurrencyAmount::from_u64(currency, quote.processing_fee).into(),
    })
}

/// Start an app resize by creating the upgrade payment.
///
/// The deployment is resized only once this payment settles, so an abandoned
/// upgrade leaves it untouched.
async fn v1_app_deployment_upgrade(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiAppUpgradeRequest>,
) -> ApiResult<ApiSubscriptionPayment> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let deployment = owned_deployment(&this, uid, id).await?;
    validate_app_upgrade(&this, &deployment, req.resource_multiplier).await?;

    // Same payment resolution as renewals: interactive, saved NWC wallet, or
    // saved Revolut card.
    let (method, mode) = crate::api::resolve_payment_mode(&this, uid, &q).await?;
    let payment = this
        .sub_handler
        .create_app_upgrade_payment(id, req.resource_multiplier, method, mode)
        .await?;

    ApiData::ok(ApiSubscriptionPayment::from(payment))
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
    fn test_validate_custom_domain() {
        // Valid hostnames normalize (trim, lowercase, strip trailing dot).
        assert_eq!(
            validate_custom_domain("blog.example.com").ok().as_deref(),
            Some("blog.example.com")
        );
        assert_eq!(
            validate_custom_domain(" Blog.Example.COM. ")
                .ok()
                .as_deref(),
            Some("blog.example.com")
        );
        assert_eq!(
            validate_custom_domain("a-b.co.uk").ok().as_deref(),
            Some("a-b.co.uk")
        );

        // Invalid: no dot (bare label/TLD), bad chars, scheme/port/path, empties.
        assert!(validate_custom_domain("").is_err());
        assert!(validate_custom_domain("localhost").is_err());
        assert!(validate_custom_domain("example").is_err());
        assert!(validate_custom_domain("https://blog.example.com").is_err());
        assert!(validate_custom_domain("blog.example.com:8443").is_err());
        assert!(validate_custom_domain("blog.example.com/path").is_err());
        assert!(validate_custom_domain("-bad.example.com").is_err());
        assert!(validate_custom_domain("bad-.example.com").is_err());
        assert!(validate_custom_domain("bl og.example.com").is_err());
        assert!(validate_custom_domain("a..com").is_err());
        assert!(validate_custom_domain(&format!("{}.com", "a".repeat(64))).is_err());
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

    /// The unique-name lookup is scoped to (cluster, name) and ignores
    /// soft-deleted rows, so a freed name is reusable but a live one isn't.
    #[tokio::test]
    async fn find_app_deployment_by_cluster_name_scopes_correctly() {
        use lnvps_api_common::MockDb;
        use lnvps_db::{AppDeployment, LNVpsDbBase};

        let db = MockDb::default();
        let mk = |cluster_id: u64, name: &str| AppDeployment {
            id: 0,
            user_id: 1,
            app_id: 1,
            cluster_id,
            resource_multiplier: 1,
            subscription_line_item_id: 0,
            name: name.to_string(),
            namespace: format!("ns-{name}"),
            hostname: None,
            custom_domain: None,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Pending,
            status_message: None,
            created: Utc::now(),
            deleted: false,
        };
        db.insert_app_deployment(&mk(1, "live")).await.unwrap();
        let gone = db.insert_app_deployment(&mk(1, "gone")).await.unwrap();
        db.delete_app_deployment(gone).await.unwrap();

        // Live name on the cluster is found.
        assert!(
            db.find_app_deployment_by_cluster_name(1, "live")
                .await
                .unwrap()
                .is_some()
        );
        // Same name on a different cluster is not.
        assert!(
            db.find_app_deployment_by_cluster_name(2, "live")
                .await
                .unwrap()
                .is_none()
        );
        // A soft-deleted name is treated as free.
        assert!(
            db.find_app_deployment_by_cluster_name(1, "gone")
                .await
                .unwrap()
                .is_none()
        );
        // Unknown name.
        assert!(
            db.find_app_deployment_by_cluster_name(1, "missing")
                .await
                .unwrap()
                .is_none()
        );
    }
}
