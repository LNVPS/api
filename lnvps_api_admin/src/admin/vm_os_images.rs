use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminVmOsImageInfo, CreateVmOsImageRequest, UpdateVmOsImageRequest};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

/// List VM OS images with pagination
#[get("/api/admin/v1/vm_os_images?<limit>&<offset>")]
pub async fn admin_list_vm_os_images(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let (images, total) = db.admin_list_vm_os_images(limit, offset).await?;
    let mut admin_images = Vec::new();
    for image in images {
        admin_images.push(AdminVmOsImageInfo::from_db_with_vm_count(db, image).await?);
    }

    ApiPaginatedData::ok(admin_images, total, limit, offset)
}

/// Get VM OS image details
#[get("/api/admin/v1/vm_os_images/<image_id>")]
pub async fn admin_get_vm_os_image(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    image_id: u64,
) -> ApiResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::View)?;

    let image = db.admin_get_vm_os_image(image_id).await?;
    let admin_image = AdminVmOsImageInfo::from_db_with_vm_count(db, image).await?;
    ApiData::ok(admin_image)
}

/// Create a new VM OS image
#[post("/api/admin/v1/vm_os_images", data = "<request>")]
pub async fn admin_create_vm_os_image(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<CreateVmOsImageRequest>,
) -> ApiResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Create)?;

    // Convert request to VmOsImage
    let mut vm_os_image = request.to_vm_os_image()?;

    // Create the image in the database
    let image_id = db.admin_create_vm_os_image(&vm_os_image).await?;
    vm_os_image.id = image_id;

    ApiData::ok(vm_os_image.into())
}

/// Update VM OS image
#[patch("/api/admin/v1/vm_os_images/<image_id>", data = "<request>")]
pub async fn admin_update_vm_os_image(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    image_id: u64,
    request: Json<UpdateVmOsImageRequest>,
) -> ApiResult<AdminVmOsImageInfo> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Update)?;

    // Get existing image
    let mut image = db.admin_get_vm_os_image(image_id).await?;

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
    db.admin_update_vm_os_image(&image).await?;

    ApiData::ok(image.into())
}

/// Delete VM OS image
#[delete("/api/admin/v1/vm_os_images/<image_id>")]
pub async fn admin_delete_vm_os_image(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    image_id: u64,
) -> ApiResult<String> {
    // Check permission
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Delete)?;

    db.admin_delete_vm_os_image(image_id).await?;
    ApiData::ok("VM OS image deleted successfully".to_string())
}
