use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminRoleInfo, AssignRoleRequest, CreateRoleRequest, Permission, UpdateRoleRequest,
    UserRoleInfo,
};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

/// List all roles
#[get("/api/admin/v1/roles?<limit>&<offset>")]
pub async fn admin_list_roles(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminRoleInfo> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let roles = db.list_roles().await?;
    let total = roles.len() as u64;

    let mut role_infos = Vec::new();
    for role in roles.into_iter().skip(offset as usize).take(limit as usize) {
        let mut role_info: AdminRoleInfo = role.clone().into();

        // Get role permissions
        let permission_tuples = db.get_role_permissions(role.id).await?;
        role_info.permissions = permission_tuples
            .into_iter()
            .filter_map(|(resource, action)| {
                // Convert enum values back to AdminResource and AdminAction
                let admin_resource = match AdminResource::try_from(resource) {
                    Ok(r) => r,
                    Err(_) => return None,
                };
                let admin_action = match AdminAction::try_from(action) {
                    Ok(a) => a,
                    Err(_) => return None,
                };
                let permission = Permission {
                    resource: admin_resource,
                    action: admin_action,
                };
                Some(permission.to_string())
            })
            .collect();

        // Get user count for this role
        role_info.user_count = db.count_role_users(role.id).await.unwrap_or(0);

        role_infos.push(role_info);
    }

    ApiPaginatedData::ok(role_infos, total, limit, offset)
}

/// Get role details
#[get("/api/admin/v1/roles/<id>")]
pub async fn admin_get_role(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminRoleInfo> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::View)?;

    let role = db.get_role(id).await?;
    let mut role_info: AdminRoleInfo = role.clone().into();

    // Get role permissions
    let permission_tuples = db.get_role_permissions(role.id).await?;
    role_info.permissions = permission_tuples
        .into_iter()
        .filter_map(|(resource, action)| {
            // Convert enum values back to AdminResource and AdminAction
            let admin_resource = match AdminResource::try_from(resource) {
                Ok(r) => r,
                Err(_) => return None,
            };
            let admin_action = match AdminAction::try_from(action) {
                Ok(a) => a,
                Err(_) => return None,
            };
            let permission = Permission {
                resource: admin_resource,
                action: admin_action,
            };
            Some(permission.to_string())
        })
        .collect();

    // Get user count for this role
    role_info.user_count = db.count_role_users(role.id).await.unwrap_or(0);

    ApiData::ok(role_info)
}

/// Create a new role
#[post("/api/admin/v1/roles", data = "<req>")]
pub async fn admin_create_role(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<CreateRoleRequest>,
) -> ApiResult<AdminRoleInfo> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::Create)?;

    // Create the role
    let role_id = db
        .create_role(&req.name, req.description.as_deref())
        .await?;

    // Add permissions to the role
    for perm_str in &req.permissions {
        if let Ok(permission) = perm_str.parse::<Permission>() {
            let resource_val = permission.resource as u16;
            let action_val = permission.action as u16;
            db.add_role_permission(role_id, resource_val, action_val)
                .await?;
        } else {
            return ApiData::err(&format!("Invalid permission format: {}", perm_str));
        }
    }

    // Return the created role
    let role = db.get_role(role_id).await?;
    let mut role_info: AdminRoleInfo = role.into();
    role_info.permissions = req.permissions.clone();
    role_info.user_count = 0;

    ApiData::ok(role_info)
}

/// Update role information
#[patch("/api/admin/v1/roles/<id>", data = "<req>")]
pub async fn admin_update_role(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: Json<UpdateRoleRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::Update)?;

    let mut role = db.get_role(id).await?;

    // Prevent updating system roles
    if role.is_system_role {
        return ApiData::err("Cannot modify system roles");
    }

    // Update role fields
    if let Some(name) = &req.name {
        role.name = name.clone();
    }
    if let Some(description) = &req.description {
        role.description = Some(description.clone());
    }

    db.update_role(&role).await?;

    // Update permissions if provided
    if let Some(permissions) = &req.permissions {
        // Get current permissions
        let current_permissions = db.get_role_permissions(id).await?;

        // Remove all current permissions
        for (resource, action) in current_permissions {
            db.remove_role_permission(id, resource, action).await?;
        }

        // Add new permissions
        for perm_str in permissions {
            if let Ok(permission) = perm_str.parse::<Permission>() {
                let resource_val = permission.resource as u16;
                let action_val = permission.action as u16;
                db.add_role_permission(id, resource_val, action_val).await?;
            } else {
                return ApiData::err(&format!("Invalid permission format: {}", perm_str));
            }
        }
    }

    ApiData::ok(())
}

/// Delete a role
#[delete("/api/admin/v1/roles/<id>")]
pub async fn admin_delete_role(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::Delete)?;

    let role = db.get_role(id).await?;

    // Prevent deleting system roles
    if role.is_system_role {
        return ApiData::err("Cannot delete system roles");
    }

    // Check if any users are assigned to this role
    let user_count = db.count_role_users(id).await?;
    if user_count > 0 {
        return ApiData::err(&format!(
            "Cannot delete role with {} assigned users. Remove all user assignments first.",
            user_count
        ));
    }

    db.delete_role(id).await?;
    ApiData::ok(())
}

/// Get user's roles
#[get("/api/admin/v1/users/<user_id>/roles")]
pub async fn admin_get_user_roles(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    user_id: u64,
) -> ApiResult<Vec<UserRoleInfo>> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    // Check that user exists
    let _user = db.get_user(user_id).await?;

    let role_assignments = db.get_user_role_assignments(user_id).await?;
    let mut user_roles = Vec::new();

    for assignment in role_assignments {
        let role = db.get_role(assignment.role_id).await?;

        // Get role permissions
        let permissions = db.get_role_permissions(assignment.role_id).await?;
        let permission_strings: Vec<String> = permissions
            .into_iter()
            .filter_map(|(resource, action)| {
                // Convert enum values back to AdminResource and AdminAction
                let admin_resource = match AdminResource::try_from(resource) {
                    Ok(r) => r,
                    Err(_) => return None,
                };
                let admin_action = match AdminAction::try_from(action) {
                    Ok(a) => a,
                    Err(_) => return None,
                };
                let permission = Permission {
                    resource: admin_resource,
                    action: admin_action,
                };
                Some(permission.to_string())
            })
            .collect();

        // Get user count for this role
        let user_count = db.count_role_users(assignment.role_id).await?;

        let role_info = AdminRoleInfo {
            id: role.id,
            name: role.name,
            description: role.description,
            is_system_role: role.is_system_role,
            permissions: permission_strings,
            user_count,
            created_at: role.created_at,
            updated_at: role.updated_at,
        };

        user_roles.push(UserRoleInfo {
            role: role_info,
            assigned_by: assignment.assigned_by,
            assigned_at: assignment.assigned_at,
            expires_at: assignment.expires_at,
        });
    }

    ApiData::ok(user_roles)
}

/// Assign role to user
#[post("/api/admin/v1/users/<user_id>/roles", data = "<req>")]
pub async fn admin_assign_user_role(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    user_id: u64,
    req: Json<AssignRoleRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::Update)?;

    // Check that user exists
    let _user = db.get_user(user_id).await?;

    // Check that role exists
    let _role = db.get_role(req.role_id).await?;

    // Assign the role
    db.assign_user_role(user_id, req.role_id, auth.user_id)
        .await?;

    ApiData::ok(())
}

/// Revoke role from user
#[delete("/api/admin/v1/users/<user_id>/roles/<role_id>")]
pub async fn admin_revoke_user_role(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    user_id: u64,
    role_id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::Update)?;

    // Check that user exists
    let _user = db.get_user(user_id).await?;

    // Check that role exists
    let role = db.get_role(role_id).await?;

    // Only prevent super_admin users from revoking their own super_admin role
    // (to avoid locking themselves out of the system)
    if auth.user_id == user_id && role.name == "super_admin" {
        // Check if the current user has super_admin role
        let user_roles = db.get_user_roles(auth.user_id).await?;
        for user_role_id in user_roles {
            let user_role = db.get_role(user_role_id).await?;
            if user_role.name == "super_admin" {
                return ApiData::err("Super admins cannot revoke their own super_admin role");
            }
        }
    }

    // Revoke the role
    db.revoke_user_role(user_id, role_id).await?;

    ApiData::ok(())
}

/// Get current user's admin roles
#[get("/api/admin/v1/me/roles")]
pub async fn admin_get_my_roles(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<Vec<UserRoleInfo>> {
    let user_id = auth.user_id;

    // Get user's role assignments
    let mut role_assignments = db.get_user_role_assignments(user_id).await?;

    #[cfg(feature = "demo")]
    {
        // assign admin role when no roles are found
        if role_assignments.len() == 0 {
            let roles = db.list_roles().await?;
            if let Some(admin_role) = roles.iter().find(|r| r.name == "admin") {
                db.assign_user_role(user_id, admin_role.id, user_id).await?;
                role_assignments = db.get_user_role_assignments(user_id).await?;
            }
        }
    }

    let mut user_roles = Vec::new();
    for assignment in role_assignments {
        // Get role details
        let role = db.get_role(assignment.role_id).await?;

        // Get role permissions - reuse logic from admin_get_role
        let permissions = db.get_role_permissions(assignment.role_id).await?;
        let permission_strings: Vec<String> = permissions
            .into_iter()
            .filter_map(|(resource, action)| {
                // Convert enum values back to AdminResource and AdminAction
                let admin_resource = match AdminResource::try_from(resource) {
                    Ok(r) => r,
                    Err(_) => return None,
                };
                let admin_action = match AdminAction::try_from(action) {
                    Ok(a) => a,
                    Err(_) => return None,
                };
                let permission = Permission {
                    resource: admin_resource,
                    action: admin_action,
                };
                Some(permission.to_string())
            })
            .collect();

        // Get user count for this role
        let user_count = db.count_role_users(assignment.role_id).await?;

        let role_info = AdminRoleInfo {
            id: role.id,
            name: role.name,
            description: role.description,
            is_system_role: role.is_system_role,
            permissions: permission_strings,
            user_count,
            created_at: role.created_at,
            updated_at: role.updated_at,
        };

        let user_role = UserRoleInfo {
            role: role_info,
            assigned_by: assignment.assigned_by,
            assigned_at: assignment.assigned_at,
            expires_at: assignment.expires_at,
        };

        user_roles.push(user_role);
    }

    ApiData::ok(user_roles)
}
