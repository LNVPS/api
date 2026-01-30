use crate::admin::PageQuery;
use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminUserInfo, AdminUserRole, AdminUserUpdateRequest};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use isocountry::CountryCode;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource};
use serde::Deserialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/admin/v1/users", get(admin_list_users))
        .route(
            "/api/admin/v1/users/{id}",
            get(admin_get_user).patch(admin_update_user),
        )
}

/// Get a specific user's information
async fn admin_get_user(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminUserInfo> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    // Get the user directly from the database
    let user = this.db.get_user(id).await?;

    // Create a basic AdminUserInfo with the user data
    let mut result = AdminUserInfo::from(user);

    // Check if user has admin role
    result.is_admin = this.db.is_admin_user(result.id).await.unwrap_or(false);

    // Get the user's VM count - a simple approach by querying for their VMs
    let vms = this.db.list_user_vms(result.id).await.unwrap_or_default();
    result.vm_count = vms.len() as u64;

    ApiData::ok(result)
}

#[derive(Deserialize)]
struct ListUsersQuery {
    #[serde(flatten)]
    pub page: PageQuery,
    pub search: Option<String>,
}

/// List all users with pagination and filtering
async fn admin_list_users(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(query): Query<ListUsersQuery>,
) -> ApiPaginatedResult<AdminUserInfo> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    let limit = query.page.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = query.page.offset.unwrap_or(0);

    // Get users with admin data in a single efficient query
    let search_pubkey = query.search.as_deref();
    let (db_admin_users, total) = this
        .db
        .admin_list_users(limit, offset, search_pubkey)
        .await?;

    ApiPaginatedData::ok(
        db_admin_users.into_iter().map(|u| u.into()).collect(),
        total,
        limit,
        offset,
    )
}

/// Update user account information
async fn admin_update_user(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUserUpdateRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::Update)?;

    let mut user = this.db.get_user(id).await?;

    // Update user fields if provided
    if let Some(email) = &req.email {
        user.email = Some(email.into());
    }
    if let Some(contact_nip17) = req.contact_nip17 {
        user.contact_nip17 = contact_nip17;
    }
    if let Some(contact_email) = req.contact_email {
        user.contact_email = contact_email;
    }
    if let Some(country_code) = &req.country_code {
        user.country_code = CountryCode::for_alpha3(country_code)
            .ok()
            .map(|c| c.alpha3().to_string());
    }
    if let Some(billing_name) = &req.billing_name {
        user.billing_name = Some(billing_name.clone());
    }
    if let Some(billing_address_1) = &req.billing_address_1 {
        user.billing_address_1 = Some(billing_address_1.clone());
    }
    if let Some(billing_address_2) = &req.billing_address_2 {
        user.billing_address_2 = Some(billing_address_2.clone());
    }
    if let Some(billing_city) = &req.billing_city {
        user.billing_city = Some(billing_city.clone());
    }
    if let Some(billing_state) = &req.billing_state {
        user.billing_state = Some(billing_state.clone());
    }
    if let Some(billing_postcode) = &req.billing_postcode {
        user.billing_postcode = Some(billing_postcode.clone());
    }
    if let Some(billing_tax_id) = &req.billing_tax_id {
        user.billing_tax_id = Some(billing_tax_id.clone());
    }

    // Update user in database
    this.db.update_user(&user).await?;

    // Handle admin role changes if requested
    if let Some(admin_role) = &req.admin_role {
        match admin_role {
            AdminUserRole::SuperAdmin | AdminUserRole::Admin | AdminUserRole::ReadOnly => {
                let role_name = match admin_role {
                    AdminUserRole::SuperAdmin => "super_admin",
                    AdminUserRole::Admin => "admin",
                    AdminUserRole::ReadOnly => "read_only",
                };

                // Get the role by name
                if let Ok(role) = this.db.get_role_by_name(role_name).await {
                    // First revoke any existing roles for this user
                    let current_roles = this.db.get_user_roles(user.id).await.unwrap_or_default();
                    for role_id in current_roles {
                        let _ = this.db.revoke_user_role(user.id, role_id).await;
                    }
                    // Assign the new role
                    this.db
                        .assign_user_role(user.id, role.id, auth.user_id)
                        .await?;
                } else {
                    return ApiData::err("Invalid admin role specified");
                }
            }
        }
    }

    // TODO: Log admin action for audit trail
    // audit_log.log_user_update(auth.user_id, id, old_values, new_values).await?;

    ApiData::ok(())
}
