use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminVmOsImageInfo, CreateVmOsImageRequest, UpdateVmOsImageRequest};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::shasum::{fetch_checksum_for_file, probe_checksum_from_image_url};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery, WorkJob};
use lnvps_db::{AdminAction, AdminResource, VmOsImage};
use log::warn;

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
        .route(
            "/api/admin/v1/vm_os_images/{id}/download",
            axum::routing::post(admin_download_vm_os_image),
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

/// Resolve the current checksum for an image and populate `sha2` (and
/// `sha2_url` if it was auto-discovered).  No-op if `sha2` is already set.
///
/// Resolution order:
/// 1. If `sha2_url` is set, fetch from that URL directly.
/// 2. Otherwise, probe well-known SHASUMS filenames in the image's URL directory.
///
/// Failures are logged as warnings and do not prevent the image from being saved.
async fn resolve_sha2(image: &mut VmOsImage) {
    if image.sha2.is_some() {
        return;
    }
    // Use the original URL filename (e.g. "debian-12-generic-amd64.qcow2") since
    // that is what appears in SHASUMS files, not the host-stored ".img" variant.
    let filename = match image.url_filename() {
        Ok(f) => f,
        Err(e) => {
            warn!("Could not determine filename for sha2 resolution: {}", e);
            return;
        }
    };
    if let Some(sha2_url) = image.sha2_url.clone() {
        match fetch_checksum_for_file(&sha2_url, &filename).await {
            Ok(entry) => image.sha2 = Some(entry.checksum),
            Err(e) => warn!("Failed to fetch sha2 from {}: {}", sha2_url, e),
        }
    } else {
        match probe_checksum_from_image_url(&image.url, &filename).await {
            Some((entry, sums_url)) => {
                image.sha2 = Some(entry.checksum);
                image.sha2_url = Some(sums_url);
            }
            None => warn!("Could not find a SHASUMS file for {}", image.url),
        }
    }
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

    // Fetch the current checksum from sha2_url if sha2 was not explicitly provided
    resolve_sha2(&mut vm_os_image).await;

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

    if let Some(sha2) = &request.sha2 {
        image.sha2 = sha2.clone();
    }

    let sha2_url_changed = request.sha2_url.is_some();
    if let Some(sha2_url) = &request.sha2_url {
        image.sha2_url = sha2_url.clone();
    }

    // If sha2_url was updated (or url changed) and sha2 was not explicitly set,
    // fetch the current checksum from the new sha2_url
    let url_changed = request.url.is_some();
    if (sha2_url_changed || url_changed) && request.sha2.is_none() {
        image.sha2 = None; // clear stale checksum before re-resolving
        resolve_sha2(&mut image).await;
    }

    // Update in database
    this.db.admin_update_vm_os_image(&image).await?;

    ApiData::ok(image.into())
}

/// Trigger an immediate download/re-check of a VM OS image on all hosts
async fn admin_download_vm_os_image(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(image_id): Path<u64>,
) -> ApiResult<String> {
    auth.require_permission(AdminResource::VmOsImage, AdminAction::Update)?;

    // Verify the image exists before enqueuing
    this.db.admin_get_vm_os_image(image_id).await?;

    this.work_commander
        .send(WorkJob::DownloadOsImages {
            image_id: Some(image_id),
        })
        .await?;

    ApiData::ok("Download job enqueued".to_string())
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
