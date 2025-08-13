use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminUserInfo, AdminUserRole, AdminUserUpdateRequest};
use isocountry::CountryCode;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{get, patch, State};
use std::sync::Arc;

/// List all users with pagination and filtering
#[get("/api/admin/v1/users?<limit>&<offset>&<search>")]
pub async fn admin_list_users(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
    search: Option<String>, // Search by pubkey (hex)
) -> ApiPaginatedResult<AdminUserInfo> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    // Get users with admin data in a single efficient query
    let search_pubkey = search.as_deref();
    let (db_admin_users, total) = db.admin_list_users(limit, offset, search_pubkey).await?;

    // Convert database AdminUserInfo to API AdminUserInfo
    let admin_users: Vec<AdminUserInfo> = db_admin_users
        .into_iter()
        .map(|db_user| AdminUserInfo {
            id: db_user.id,
            pubkey: hex::encode(&db_user.pubkey),
            created: db_user.created,
            email: db_user.email.map(|e| e.into()),
            contact_nip17: db_user.contact_nip17,
            contact_email: db_user.contact_email,
            country_code: db_user.country_code,
            billing_name: db_user.billing_name,
            billing_address_1: db_user.billing_address_1,
            billing_address_2: db_user.billing_address_2,
            billing_city: db_user.billing_city,
            billing_state: db_user.billing_state,
            billing_postcode: db_user.billing_postcode,
            billing_tax_id: db_user.billing_tax_id,
            vm_count: db_user.vm_count as u64,
            last_login: None, // TODO: Add last_login tracking
            is_admin: db_user.is_admin,
        })
        .collect();

    ApiPaginatedData::ok(admin_users, total, limit, offset)
}

/// Update user account information
#[patch("/api/admin/v1/users/<id>", data = "<req>")]
pub async fn admin_update_user(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: Json<AdminUserUpdateRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::Update)?;

    let mut user = db.get_user(id).await?;

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
    db.update_user(&user).await?;

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
                if let Ok(role) = db.get_role_by_name(role_name).await {
                    // First revoke any existing roles for this user
                    let current_roles = db.get_user_roles(user.id).await.unwrap_or_default();
                    for role_id in current_roles {
                        let _ = db.revoke_user_role(user.id, role_id).await;
                    }
                    // Assign the new role
                    db.assign_user_role(user.id, role.id, auth.user_id).await?;
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
