use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminVmOsImageInfo, CreateVmOsImageRequest, UpdateVmOsImageRequest};
use crate::admin::{PageQuery, RouterState};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vm_os_images",
            get(admin_list_vm_os_images).post(admin_create_vm_os_image),
        )
        .route(
            "/api/admin/v1/vm_os_images/{id}",
            get(admin_get_vm_os_image)
                .patch(admin_update_vm_os_image)
                .delete(admin_delete_vm_os_image),
        )
}

/// List VM OS images with pagination
async fn admin_list_vm_os_images(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let (images, total) = this.db.admin_list_vm_os_images(limit, offset).await?;
    let mut admin_images = Vec::new();
    for image in images {
        admin_images.push(AdminVmOsImageInfo::from_db_with_vm_count(&this.db, image).await?);
    }

    ApiPaginatedData::ok(admin_images, total, limit, offset)
}

/// Get VM OS image details
async fn admin_get_vm_os_image(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(image_id): Path<u64>,
) -> ApiResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::View)?;

    let image = this.db.admin_get_vm_os_image(image_id).await?;
    let admin_image = AdminVmOsImageInfo::from_db_with_vm_count(&this.db, image).await?;
    ApiData::ok(admin_image)
}

/// Create a new VM OS image
async fn admin_create_vm_os_image(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<CreateVmOsImageRequest>,
) -> ApiResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Create)?;

    // Convert request to VmOsImage
    let mut vm_os_image = request.to_vm_os_image()?;

    // Create the image in the database
    let image_id = this.db.admin_create_vm_os_image(&vm_os_image).await?;
    vm_os_image.id = image_id;

    ApiData::ok(vm_os_image.into())
}

/// Update VM OS image
async fn admin_update_vm_os_image(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(image_id): Path<u64>,
    Json(request): Json<UpdateVmOsImageRequest>,
) -> ApiResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Update)?;

    // Get existing image
    let mut image = this.db.admin_get_vm_os_image(image_id).await?;

    // Update fields if provided
    if let Some(distribution) = &request.distribution {
        image.distribution = (*distribution).into();
    }

    if let Some(flavour) = &request.flavour {
        image.flavour = flavour.clone();
    }

    if let Some(version) = &request.version {
        image.version = version.clone();
    }

    if let Some(enabled) = request.enabled {
        image.enabled = enabled;
    }

    if let Some(release_date) = request.release_date {
        image.release_date = release_date;
    }

    if let Some(url) = &request.url {
        image.url = url.clone();
    }

    if let Some(default_username) = &request.default_username {
        image.default_username = Some(default_username.clone());
    }

    // Update in database
    this.db.admin_update_vm_os_image(&image).await?;

    ApiData::ok(image.into())
}

/// Delete VM OS image
async fn admin_delete_vm_os_image(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(image_id): Path<u64>,
) -> ApiResult<String> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Delete)?;

    this.db.admin_delete_vm_os_image(image_id).await?;
    ApiData::ok("VM OS image deleted successfully".to_string())
}
