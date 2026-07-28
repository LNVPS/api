use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminAppClusterInfo, AdminAppDeploymentInfo, AdminAppInfo, AdminAppTagInfo, AdminAppTagRef,
    AdminCreateAppClusterRequest, AdminCreateAppRequest, AdminCreateAppTagRequest,
    AdminDeleteAppTagResult, AdminUpdateAppClusterRequest, AdminUpdateAppDeploymentRequest,
    AdminUpdateAppRequest, AdminUpdateAppTagRequest,
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
            "/api/admin/v1/app-tags",
            get(admin_list_app_tags).post(admin_create_app_tag),
        )
        .route(
            "/api/admin/v1/app-tags/{id}",
            get(admin_get_app_tag)
                .patch(admin_update_app_tag)
                .delete(admin_delete_app_tag),
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

/// Resolve tag slugs to ids, rejecting the first unknown one by name.
///
/// The vocabulary is controlled: an unrecognised slug is a `400` naming it,
/// never an implicit create. Auto-creation is exactly the drift the tag table
/// exists to prevent — `Nostr relay`, `nostr-relay` and `nostr` becoming three
/// tags the first time two admins type them.
///
/// Slugs are trimmed and de-duplicated, so a request listing the same tag
/// twice is one assignment rather than a unique-key violation from the driver.
async fn resolve_tag_slugs(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    slugs: &[String],
) -> Result<Vec<u64>, lnvps_api_common::ApiError> {
    let mut ids = Vec::with_capacity(slugs.len());
    for slug in slugs {
        let slug = slug.trim();
        if slug.is_empty() {
            continue;
        }
        let tag = db
            .get_app_tag_by_slug(slug)
            .await
            .map_err(|_| lnvps_api_common::ApiError::new(format!("unknown tag slug: {slug}")))?;
        if !ids.contains(&tag.id) {
            ids.push(tag.id);
        }
    }
    Ok(ids)
}

/// Load one app's tags in the admin wire shape.
async fn app_tag_refs(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    app_id: u64,
) -> Result<Vec<AdminAppTagRef>, lnvps_api_common::ApiError> {
    Ok(db
        .list_app_tag_assignments(&[app_id])
        .await?
        .into_iter()
        .map(|(_, t)| t.into())
        .collect())
}

/// Validate and normalise a tag slug: URL-safe, since it is a path segment in
/// `/apps/tag/{slug}` and a query value. Same rule as an app's `name`.
fn validate_tag_slug(slug: &str) -> Result<String, lnvps_api_common::ApiError> {
    let slug = slug.trim();
    if slug.is_empty() {
        return Err(lnvps_api_common::ApiError::new("slug is required"));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || slug.starts_with('-')
        || slug.ends_with('-')
    {
        return Err(lnvps_api_common::ApiError::new(
            "slug must be URL-safe (lowercase letters, digits, hyphens)",
        ));
    }
    Ok(slug.to_string())
}

/// Trim and require a non-empty tag `display_name`.
///
/// Required rather than derived from the slug: title-casing in JS mangles
/// `NIP-96`, `HTTP` and `Git`, which is why the column exists at all.
fn validate_tag_display_name(name: String) -> Result<String, lnvps_api_common::ApiError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(lnvps_api_common::ApiError::new("display_name is required"));
    }
    Ok(name.to_string())
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

    // One assignment query for the whole page, not one per row.
    let ids: Vec<u64> = apps.iter().map(|a| a.id).collect();
    let mut tags: std::collections::BTreeMap<u64, Vec<AdminAppTagRef>> = Default::default();
    for (app_id, tag) in this.db.list_app_tag_assignments(&ids).await? {
        tags.entry(app_id).or_default().push(tag.into());
    }

    ApiPaginatedData::ok(
        apps.into_iter()
            .map(|a| {
                let app_tags = tags.remove(&a.id).unwrap_or_default();
                AdminAppInfo::from_app(a, app_tags)
            })
            .collect(),
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
    let tags = app_tag_refs(&this.db, id).await?;
    ApiData::ok(AdminAppInfo::from_app(app, tags))
}

async fn admin_create_app(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<AdminCreateAppRequest>,
) -> ApiResult<AdminAppInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Create)?;
    validate_app_fields(&req.name, &req.display_name, &req.compose, &req.currency)?;
    let category = validate_category(req.category)?;
    // Resolve before the insert: an unknown slug should fail the whole request
    // rather than leave a created-but-untagged app behind.
    let tag_ids = match &req.tags {
        Some(slugs) => Some(resolve_tag_slugs(&this.db, slugs).await?),
        None => None,
    };
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
    if let Some(tag_ids) = tag_ids {
        this.db.set_app_tags(id, &tag_ids).await?;
    }
    let tags = app_tag_refs(&this.db, id).await?;
    ApiData::ok(AdminAppInfo::from_app(this.db.get_app(id).await?, tags))
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
        let category =
            category.ok_or_else(|| lnvps_api_common::ApiError::new("category cannot be null"))?;
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
    // Resolve before any write, so an unknown slug leaves the app untouched
    // rather than half-applying the rest of the patch.
    let tag_ids = match &req.tags {
        Some(slugs) => Some(resolve_tag_slugs(&this.db, slugs).await?),
        None => None,
    };
    // Recompute the footprint from the (possibly updated) compose.
    let footprint = compose_footprint(&app.compose)?;
    app.cpu_milli = footprint.cpu_milli;
    app.memory_bytes = footprint.memory_bytes;
    app.storage_bytes = footprint.storage_bytes;
    this.db.update_app(&app).await?;
    // Replace-set: an empty list clears, omitted leaves the set alone.
    if let Some(tag_ids) = tag_ids {
        this.db.set_app_tags(id, &tag_ids).await?;
    }
    let tags = app_tag_refs(&this.db, id).await?;
    ApiData::ok(AdminAppInfo::from_app(this.db.get_app(id).await?, tags))
}

/// The parent of a deployment — the two resources whose delete the FK guards.
#[derive(Clone, Copy)]
enum DeploymentParent {
    App(u64),
    Cluster(u64),
}

impl DeploymentParent {
    fn filter(&self, include_deleted: bool) -> AppDeploymentFilter {
        let mut filter = AppDeploymentFilter {
            include_deleted,
            ..Default::default()
        };
        match self {
            DeploymentParent::App(id) => filter.app_id = Some(*id),
            DeploymentParent::Cluster(id) => filter.cluster_id = Some(*id),
        }
        filter
    }

    fn noun(&self) -> &'static str {
        match self {
            DeploymentParent::App(_) => "app",
            DeploymentParent::Cluster(_) => "cluster",
        }
    }
}

/// Refuse to delete an app or cluster while any `app_deployment` row still
/// references it (#238).
///
/// The guard has to count the rows the foreign key counts.
/// `fk_app_deployment_app` and `fk_app_deployment_cluster` do not look at
/// `deleted`, and deployment deletion is a soft delete, so a soft-deleted row
/// blocks the parent delete exactly as a live one does. Counting only live
/// deployments let the delete through to MySQL, which rejected it — turning the
/// 400 this guard exists to produce into a 500.
///
/// Soft-deleted deployments are hidden from the admin deployment list by
/// default, so an admin refused on their account has nothing to look at. The
/// message names the count and the purge that clears them.
async fn ensure_no_deployments(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    parent: DeploymentParent,
) -> Result<(), lnvps_api_common::ApiError> {
    // Only the totals are used, so ask for the narrowest page.
    let (_, total) = db
        .admin_list_app_deployments_filtered(1, 0, &parent.filter(true))
        .await?;
    if total == 0 {
        return Ok(());
    }
    let (_, live) = db
        .admin_list_app_deployments_filtered(1, 0, &parent.filter(false))
        .await?;
    let soft_deleted = total.saturating_sub(live);
    let noun = parent.noun();

    Err(lnvps_api_common::ApiError::new(if live > 0 {
        format!(
            "cannot delete this {noun} with existing deployments \
             ({live} active, {soft_deleted} soft-deleted); disable it instead"
        )
    } else {
        format!(
            "cannot delete this {noun}: {soft_deleted} soft-deleted deployment(s) still \
             reference it. A super admin can purge them (DELETE \
             /api/admin/v1/app-deployments/{{id}} with `purge: true`), then retry"
        )
    }))
}

async fn admin_delete_app(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<bool> {
    auth.require_permission(AdminResource::App, AdminAction::Delete)?;
    this.db.get_app(id).await?;

    ensure_no_deployments(&this.db, DeploymentParent::App(id)).await?;

    this.db.delete_app(id).await?;
    ApiData::ok(true)
}

// ----- App tags (the vocabulary itself) -----
//
// All of these reuse `AdminResource::App`. Tags are catalog metadata, and a
// separate resource would mean a new enum value, a new RBAC migration, and a
// permission every existing app-admin role would have to be granted before the
// feature worked at all.

async fn admin_list_app_tags(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<AdminAppTagInfo>> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;
    let tags = this.db.list_app_tags_with_counts().await?;
    ApiData::ok(
        tags.into_iter()
            .map(|(t, app_count)| AdminAppTagInfo {
                id: t.id,
                slug: t.slug,
                display_name: t.display_name,
                description: t.description,
                app_count,
                created: t.created,
            })
            .collect(),
    )
}

async fn admin_get_app_tag(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAppTagInfo> {
    auth.require_permission(AdminResource::App, AdminAction::View)?;
    let tag = this.db.get_app_tag(id).await?;
    // Count from the same source as the listing so the two cannot disagree.
    let app_count = this
        .db
        .list_app_tags_with_counts()
        .await?
        .into_iter()
        .find(|(t, _)| t.id == id)
        .map(|(_, c)| c)
        .unwrap_or(0);
    ApiData::ok(AdminAppTagInfo {
        id: tag.id,
        slug: tag.slug,
        display_name: tag.display_name,
        description: tag.description,
        app_count,
        created: tag.created,
    })
}

async fn admin_create_app_tag(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<AdminCreateAppTagRequest>,
) -> ApiResult<AdminAppTagInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Create)?;
    let slug = validate_tag_slug(&req.slug)?;
    let display_name = validate_tag_display_name(req.display_name)?;

    let tag = lnvps_db::AppTag {
        id: 0,
        slug,
        display_name,
        description: req.description.filter(|s| !s.trim().is_empty()),
        created: chrono::Utc::now(),
    };
    let id = this.db.insert_app_tag(&tag).await?;
    let tag = this.db.get_app_tag(id).await?;
    ApiData::ok(AdminAppTagInfo {
        id: tag.id,
        slug: tag.slug,
        display_name: tag.display_name,
        description: tag.description,
        // Freshly created, so nothing can carry it yet.
        app_count: 0,
        created: tag.created,
    })
}

async fn admin_update_app_tag(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateAppTagRequest>,
) -> ApiResult<AdminAppTagInfo> {
    auth.require_permission(AdminResource::App, AdminAction::Update)?;
    let mut tag = this.db.get_app_tag(id).await?;

    if let Some(slug) = req.slug {
        // Renaming a slug breaks any /apps/tag/{slug} link already indexed —
        // allowed, because the alternative is an unfixable typo, but it is a
        // deliberate act and not something to do casually.
        tag.slug = validate_tag_slug(&slug)?;
    }
    if let Some(display_name) = req.display_name {
        tag.display_name = validate_tag_display_name(display_name)?;
    }
    if let Some(description) = req.description {
        tag.description = description.filter(|s| !s.trim().is_empty());
    }

    this.db.update_app_tag(&tag).await?;
    let tag = this.db.get_app_tag(id).await?;
    let app_count = this
        .db
        .list_app_tags_with_counts()
        .await?
        .into_iter()
        .find(|(t, _)| t.id == id)
        .map(|(_, c)| c)
        .unwrap_or(0);
    ApiData::ok(AdminAppTagInfo {
        id: tag.id,
        slug: tag.slug,
        display_name: tag.display_name,
        description: tag.description,
        app_count,
        created: tag.created,
    })
}

/// Delete a tag from the vocabulary, cascading its assignments.
///
/// Unlike deleting an app, this is **not** refused when the tag is in use:
/// untagging is the point of retiring a tag, and the assignment rows are not
/// billable. The response reports how many apps it untagged, because the
/// cascade is otherwise invisible.
async fn admin_delete_app_tag(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminDeleteAppTagResult> {
    auth.require_permission(AdminResource::App, AdminAction::Delete)?;
    // Confirm it exists first, so deleting a non-existent tag is a 404 rather
    // than a 200 claiming it removed zero assignments.
    this.db.get_app_tag(id).await?;
    let assignments_removed = this.db.delete_app_tag(id).await?;
    ApiData::ok(AdminDeleteAppTagResult {
        assignments_removed,
    })
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

    ensure_no_deployments(&this.db, DeploymentParent::Cluster(id)).await?;

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
    fn test_validate_tag_slug() {
        // Returns trimmed: the slug is a path segment in /apps/tag/{slug} and
        // a query value, so a stray space is a broken URL, not a cosmetic slip.
        assert_eq!(
            validate_tag_slug("  nostr  ").ok(),
            Some("nostr".to_string())
        );
        assert_eq!(
            validate_tag_slug("media-server").ok(),
            Some("media-server".to_string())
        );
        assert_eq!(validate_tag_slug("nip-96").ok(), Some("nip-96".to_string()));

        assert!(validate_tag_slug("").is_err());
        assert!(validate_tag_slug("   ").is_err());
        // Uppercase and spaces would have to be escaped in a URL, and two
        // admins typing `Nostr` and `nostr` is the vocabulary drift the
        // controlled table exists to prevent.
        assert!(validate_tag_slug("Nostr").is_err());
        assert!(validate_tag_slug("media server").is_err());
        assert!(validate_tag_slug("nostr_relay").is_err());
        assert!(validate_tag_slug("-nostr").is_err());
        assert!(validate_tag_slug("nostr-").is_err());
    }

    #[test]
    fn test_validate_tag_display_name() {
        // Required rather than derived from the slug: title-casing `nip-96` in
        // JS yields `Nip-96`, which is why the column exists.
        assert_eq!(
            validate_tag_display_name("  NIP-96  ".to_string()).ok(),
            Some("NIP-96".to_string())
        );
        assert!(validate_tag_display_name(String::new()).is_err());
        assert!(validate_tag_display_name("   ".to_string()).is_err());
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

    // ----- Delete guard (#238) -----

    fn mk_deployment(app_id: u64, cluster_id: u64, name: &str) -> lnvps_db::AppDeployment {
        lnvps_db::AppDeployment {
            id: 0,
            user_id: 1,
            app_id,
            cluster_id,
            resource_multiplier: 1,
            subscription_line_item_id: 0,
            name: name.to_string(),
            namespace: format!("app-{name}"),
            hostname: None,
            custom_domain: None,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Pending,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: chrono::Utc::now(),
            deleted: false,
        }
    }

    /// The guard has to count soft-deleted deployments, because the foreign key
    /// does. A soft delete leaves the row (and its `app_id`/`cluster_id`) in
    /// place, so letting the parent delete through produced a MySQL FK error as
    /// a 500 instead of this 400.
    #[tokio::test]
    async fn test_delete_guard_counts_soft_deleted_deployments() {
        let db: std::sync::Arc<dyn lnvps_db::LNVpsDb> =
            std::sync::Arc::new(lnvps_api_common::MockDb::default());

        // Nothing deployed: both deletes are allowed.
        assert!(
            ensure_no_deployments(&db, DeploymentParent::App(7))
                .await
                .is_ok()
        );
        assert!(
            ensure_no_deployments(&db, DeploymentParent::Cluster(3))
                .await
                .is_ok()
        );

        let dep_id = db
            .insert_app_deployment(&mk_deployment(7, 3, "alpha"))
            .await
            .unwrap();

        // Live deployment: refused, and told to disable instead.
        let err = ensure_no_deployments(&db, DeploymentParent::App(7))
            .await
            .expect_err("live deployment blocks the app delete");
        assert_eq!(err.code, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.error.contains("1 active"), "{}", err.error);
        assert!(err.error.contains("disable it instead"), "{}", err.error);
        assert!(
            ensure_no_deployments(&db, DeploymentParent::Cluster(3))
                .await
                .is_err()
        );

        // Another app/cluster is unaffected by it.
        assert!(
            ensure_no_deployments(&db, DeploymentParent::App(8))
                .await
                .is_ok()
        );
        assert!(
            ensure_no_deployments(&db, DeploymentParent::Cluster(4))
                .await
                .is_ok()
        );

        // Soft delete: the row still holds the FK, so the delete stays refused —
        // this is the case the old `list_all_app_deployments` guard let through.
        db.delete_app_deployment(dep_id).await.unwrap();
        let err = ensure_no_deployments(&db, DeploymentParent::App(7))
            .await
            .expect_err("soft-deleted deployment still blocks the app delete");
        assert!(err.error.contains("1 soft-deleted"), "{}", err.error);
        assert!(err.error.contains("purge"), "{}", err.error);
        let err = ensure_no_deployments(&db, DeploymentParent::Cluster(3))
            .await
            .expect_err("soft-deleted deployment still blocks the cluster delete");
        assert!(err.error.contains("cluster"), "{}", err.error);
        assert!(err.error.contains("purge"), "{}", err.error);

        // Purge: the row is gone, so both deletes are allowed again.
        db.hard_delete_app_deployment(dep_id).await.unwrap();
        assert!(
            ensure_no_deployments(&db, DeploymentParent::App(7))
                .await
                .is_ok()
        );
        assert!(
            ensure_no_deployments(&db, DeploymentParent::Cluster(3))
                .await
                .is_ok()
        );
    }

    /// A mix of live and soft-deleted deployments reports both counts, so an
    /// admin can tell whether purging alone would unblock the delete.
    #[tokio::test]
    async fn test_delete_guard_reports_both_counts() {
        let db: std::sync::Arc<dyn lnvps_db::LNVpsDb> =
            std::sync::Arc::new(lnvps_api_common::MockDb::default());
        let dead = db
            .insert_app_deployment(&mk_deployment(7, 3, "dead"))
            .await
            .unwrap();
        db.insert_app_deployment(&mk_deployment(7, 3, "live"))
            .await
            .unwrap();
        db.delete_app_deployment(dead).await.unwrap();

        let err = ensure_no_deployments(&db, DeploymentParent::App(7))
            .await
            .expect_err("one live deployment still blocks the delete");
        assert!(err.error.contains("1 active"), "{}", err.error);
        assert!(err.error.contains("1 soft-deleted"), "{}", err.error);
    }
}
