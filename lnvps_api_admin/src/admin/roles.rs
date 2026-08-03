use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminRoleInfo, AssignRoleRequest, CreateRoleRequest, Permission, UpdateRoleRequest,
    UserRoleInfo,
};
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery,
};
use lnvps_db::{AdminAction, AdminResource};
use std::collections::HashSet;

/// Name of the built-in role that grants every permission in the system.
const SUPER_ADMIN_ROLE: &str = "super_admin";

/// Authorization rules for granting a role to a user.
///
/// Role assignment is an escalation primitive: without these checks any admin
/// holding the assignment permission could grant themselves `super_admin`,
/// which collapses the whole RBAC model into a single permission.
fn check_role_assignment(
    caller_user_id: u64,
    target_user_id: u64,
    caller_is_super_admin: bool,
    role_name: &str,
    caller_permissions: &HashSet<Permission>,
    role_permissions: &HashSet<Permission>,
) -> Result<(), ApiError> {
    // An admin must never be able to widen their own grants.
    if caller_user_id == target_user_id {
        return Err(ApiError::forbidden(
            "Admins cannot assign roles to themselves",
        ));
    }

    if role_name == SUPER_ADMIN_ROLE && !caller_is_super_admin {
        return Err(ApiError::forbidden(format!(
            "Only a {} can grant the {} role",
            SUPER_ADMIN_ROLE, SUPER_ADMIN_ROLE
        )));
    }

    // No granting permissions you don't hold yourself.
    if !caller_is_super_admin {
        let mut missing: Vec<String> = role_permissions
            .difference(caller_permissions)
            .map(|p| format!("{}::{}", p.resource, p.action))
            .collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(ApiError::forbidden(format!(
                "Cannot grant a role holding permissions you do not have: {}",
                missing.join(", ")
            )));
        }
    }

    Ok(())
}

/// Authorization rules for defining a role's permission set.
///
/// Assignment is guarded by [`check_role_assignment`], but *defining* a role was
/// not: anyone holding `roles::create` / `roles::update` could mint or edit a
/// role carrying permissions they do not themselves have. Because an admin can
/// edit a role they already hold, that was a direct self-escalation to every
/// permission in the system — the assignment guard never runs, since no new
/// assignment happens.
///
/// A super admin implicitly holds everything and is unrestricted.
fn check_role_definition(
    caller_is_super_admin: bool,
    caller_permissions: &HashSet<Permission>,
    role_permissions: &HashSet<Permission>,
) -> Result<(), ApiError> {
    if caller_is_super_admin {
        return Ok(());
    }

    let mut missing: Vec<String> = role_permissions
        .difference(caller_permissions)
        .map(|p| format!("{}::{}", p.resource, p.action))
        .collect();
    if !missing.is_empty() {
        missing.sort();
        return Err(ApiError::forbidden(format!(
            "Cannot define a role holding permissions you do not have: {}",
            missing.join(", ")
        )));
    }

    Ok(())
}

/// Parse the wire representation of a permission set, rejecting unknown values.
fn parse_permissions(raw: &[String]) -> Result<HashSet<Permission>, ApiError> {
    raw.iter()
        .map(|p| {
            p.parse::<Permission>()
                .map_err(|_| ApiError::new(format!("Invalid permission format: {}", p)))
        })
        .collect()
}

/// Authorization rules for revoking a role from a user.
///
/// Self-revocation of `super_admin` is only blocked when the caller is the last
/// super admin, otherwise an unwanted grant could never be handed back.
fn check_role_revocation(
    caller_user_id: u64,
    target_user_id: u64,
    caller_is_super_admin: bool,
    role_name: &str,
    role_user_count: u64,
) -> Result<(), ApiError> {
    if role_name == SUPER_ADMIN_ROLE {
        if !caller_is_super_admin {
            return Err(ApiError::forbidden(format!(
                "Only a {} can revoke the {} role",
                SUPER_ADMIN_ROLE, SUPER_ADMIN_ROLE
            )));
        }
        if caller_user_id == target_user_id && role_user_count <= 1 {
            return Err(ApiError::forbidden(format!(
                "Cannot revoke your own {} role, you are the last {}",
                SUPER_ADMIN_ROLE, SUPER_ADMIN_ROLE
            )));
        }
    }

    Ok(())
}

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/roles",
            get(admin_list_roles).post(admin_create_role),
        )
        .route(
            "/api/admin/v1/roles/{id}",
            get(admin_get_role)
                .patch(admin_update_role)
                .delete(admin_delete_role),
        )
        // User role assignments
        .route(
            "/api/admin/v1/users/{id}/roles",
            get(admin_get_user_roles).post(admin_assign_user_role),
        )
        .route(
            "/api/admin/v1/users/{id}/roles/{role_id}",
            delete(admin_revoke_user_role),
        )
        .route("/api/admin/v1/me/roles", get(admin_get_my_roles))
}

/// List all roles
async fn admin_list_roles(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(page): Query<PageQuery>,
) -> ApiPaginatedResult<AdminRoleInfo> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::View)?;

    let limit = page.limit.unwrap_or(50).min(100);
    let offset = page.offset.unwrap_or(0);

    let (roles, total) = this.db.list_roles_paginated(limit, offset).await?;

    let mut role_infos = Vec::new();
    for role in roles {
        let mut role_info: AdminRoleInfo = role.clone().into();

        // Get role permissions
        let permission_tuples = this.db.get_role_permissions(role.id).await?;
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
        role_info.user_count = this.db.count_role_users(role.id).await.unwrap_or(0);

        role_infos.push(role_info);
    }

    ApiPaginatedData::ok(role_infos, total, limit, offset)
}

/// Get role details
async fn admin_get_role(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminRoleInfo> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::View)?;

    let role = this.db.get_role(id).await?;
    let mut role_info: AdminRoleInfo = role.clone().into();

    // Get role permissions
    let permission_tuples = this.db.get_role_permissions(role.id).await?;
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
    role_info.user_count = this.db.count_role_users(role.id).await.unwrap_or(0);

    ApiData::ok(role_info)
}

/// Create a new role
async fn admin_create_role(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateRoleRequest>,
) -> ApiResult<AdminRoleInfo> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::Create)?;

    // Validate the whole permission set *before* creating anything, so an
    // invalid or escalating request cannot leave a half-populated role behind.
    let permissions = parse_permissions(&req.permissions)?;
    check_role_definition(
        auth.is_super_admin(&this.db).await?,
        &auth.permissions,
        &permissions,
    )?;

    // Create the role
    let role_id = this
        .db
        .create_role(&req.name, req.description.as_deref())
        .await?;

    // Add permissions to the role
    for permission in &permissions {
        this.db
            .add_role_permission(
                role_id,
                permission.resource as u16,
                permission.action as u16,
            )
            .await?;
    }

    // Return the created role
    let role = this.db.get_role(role_id).await?;
    let mut role_info: AdminRoleInfo = role.into();
    role_info.permissions = req.permissions.clone();
    role_info.user_count = 0;

    ApiData::ok(role_info)
}

/// Update role information
async fn admin_update_role(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateRoleRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::Update)?;

    let mut role = this.db.get_role(id).await?;

    // Prevent updating system roles
    if role.is_system_role {
        return Err(ApiError::forbidden("Cannot modify system roles"));
    }

    // An admin may hold the role they are editing, so widening its permissions
    // is a self-escalation path that never touches the assignment guard.
    // Validate up front, before any mutation.
    let new_permissions = req
        .permissions
        .as_deref()
        .map(parse_permissions)
        .transpose()?;
    if let Some(new_permissions) = &new_permissions {
        check_role_definition(
            auth.is_super_admin(&this.db).await?,
            &auth.permissions,
            new_permissions,
        )?;
    }

    // Update role fields
    if let Some(name) = &req.name {
        role.name = name.clone();
    }
    if let Some(description) = &req.description {
        role.description = Some(description.clone());
    }

    this.db.update_role(&role).await?;

    // Update permissions if provided
    if let Some(permissions) = new_permissions {
        // Get current permissions
        let current_permissions = this.db.get_role_permissions(id).await?;

        // Remove all current permissions
        for (resource, action) in current_permissions {
            this.db.remove_role_permission(id, resource, action).await?;
        }

        // Add new permissions
        for permission in &permissions {
            this.db
                .add_role_permission(id, permission.resource as u16, permission.action as u16)
                .await?;
        }
    }

    ApiData::ok(())
}

/// Delete a role
async fn admin_delete_role(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Roles, AdminAction::Delete)?;

    let role = this.db.get_role(id).await?;

    // Prevent deleting system roles
    if role.is_system_role {
        return Err(ApiError::forbidden("Cannot delete system roles"));
    }

    // Check if any users are assigned to this role
    let user_count = this.db.count_role_users(id).await?;
    if user_count > 0 {
        return ApiData::err(&format!(
            "Cannot delete role with {} assigned users. Remove all user assignments first.",
            user_count
        ));
    }

    this.db.delete_role(id).await?;
    ApiData::ok(())
}

/// Get user's roles
async fn admin_get_user_roles(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(user_id): Path<u64>,
) -> ApiResult<Vec<UserRoleInfo>> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    // Check that user exists
    let _user = this.db.get_user(user_id).await?;

    let role_assignments = this.db.get_user_role_assignments(user_id).await?;
    let mut user_roles = Vec::new();

    for assignment in role_assignments {
        let role = this.db.get_role(assignment.role_id).await?;

        // Get role permissions
        let permissions = this.db.get_role_permissions(assignment.role_id).await?;
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
        let user_count = this.db.count_role_users(assignment.role_id).await?;

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
async fn admin_assign_user_role(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(user_id): Path<u64>,
    Json(req): Json<AssignRoleRequest>,
) -> ApiResult<()> {
    // Role assignment is role management, not user management
    auth.require_permission(AdminResource::Roles, AdminAction::Update)?;

    // Check that user exists
    let _user = this.db.get_user(user_id).await?;

    // Check that role exists
    let role = this.db.get_role(req.role_id).await?;

    let role_permissions: HashSet<Permission> = this
        .db
        .get_role_permissions(role.id)
        .await?
        .into_iter()
        .filter_map(|(resource, action)| {
            Some(Permission {
                resource: AdminResource::try_from(resource).ok()?,
                action: AdminAction::try_from(action).ok()?,
            })
        })
        .collect();

    check_role_assignment(
        auth.user_id,
        user_id,
        auth.is_super_admin(&this.db).await?,
        &role.name,
        &auth.permissions,
        &role_permissions,
    )?;

    // Assign the role
    this.db
        .assign_user_role(user_id, req.role_id, auth.user_id)
        .await?;

    ApiData::ok(())
}

/// Revoke role from user
async fn admin_revoke_user_role(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((user_id, role_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    // Role assignment is role management, not user management
    auth.require_permission(AdminResource::Roles, AdminAction::Update)?;

    // Check that user exists
    let _user = this.db.get_user(user_id).await?;

    // Check that role exists
    let role = this.db.get_role(role_id).await?;

    check_role_revocation(
        auth.user_id,
        user_id,
        auth.is_super_admin(&this.db).await?,
        &role.name,
        this.db.count_role_users(role.id).await?,
    )?;

    // Revoke the role
    this.db.revoke_user_role(user_id, role_id).await?;

    ApiData::ok(())
}

/// Get current user's admin roles
async fn admin_get_my_roles(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<UserRoleInfo>> {
    let user_id = auth.user_id;

    #[allow(unused_mut)]
    // Get user's role assignments
    let mut role_assignments = this.db.get_user_role_assignments(user_id).await?;

    #[cfg(feature = "demo")]
    {
        // assign admin role when no roles are found
        if role_assignments.len() == 0 {
            let roles = this.db.list_roles().await?;
            if let Some(admin_role) = roles.iter().find(|r| r.name == "admin") {
                this.db
                    .assign_user_role(user_id, admin_role.id, user_id)
                    .await?;
                role_assignments = this.db.get_user_role_assignments(user_id).await?;
            }
        }
    }

    let mut user_roles = Vec::new();
    for assignment in role_assignments {
        // Get role details
        let role = this.db.get_role(assignment.role_id).await?;

        // Get role permissions - reuse logic from admin_get_role
        let permissions = this.db.get_role_permissions(assignment.role_id).await?;
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
        let user_count = this.db.count_role_users(assignment.role_id).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn perm(resource: AdminResource, action: AdminAction) -> Permission {
        Permission { resource, action }
    }

    fn perms(items: &[(AdminResource, AdminAction)]) -> HashSet<Permission> {
        items.iter().map(|(r, a)| perm(*r, *a)).collect()
    }

    /// Regression: a `user_manager` (users::update, no role permissions) could
    /// POST /users/{self}/roles with role_id=super_admin and take over.
    #[test]
    fn test_cannot_self_assign_super_admin() {
        let caller = perms(&[
            (AdminResource::Users, AdminAction::Update),
            (AdminResource::Roles, AdminAction::Update),
        ]);
        let super_admin = perms(&[(AdminResource::Roles, AdminAction::Update)]);

        // Self-assignment is refused outright, even for a super admin.
        assert!(
            check_role_assignment(7, 7, false, SUPER_ADMIN_ROLE, &caller, &super_admin).is_err()
        );
        assert!(
            check_role_assignment(7, 7, true, SUPER_ADMIN_ROLE, &caller, &super_admin).is_err()
        );
        assert!(check_role_assignment(7, 7, false, "read_only", &caller, &HashSet::new()).is_err());
    }

    #[test]
    fn test_only_super_admin_can_grant_super_admin() {
        let caller = perms(&[(AdminResource::Roles, AdminAction::Update)]);

        assert!(
            check_role_assignment(1, 2, false, SUPER_ADMIN_ROLE, &caller, &caller).is_err(),
            "non super admin must not hand out super_admin"
        );
        assert!(check_role_assignment(1, 2, true, SUPER_ADMIN_ROLE, &caller, &caller).is_ok());
    }

    #[test]
    fn test_cannot_grant_permissions_caller_does_not_hold() {
        let caller = perms(&[
            (AdminResource::Roles, AdminAction::Update),
            (AdminResource::Users, AdminAction::View),
        ]);

        // Role holds vm::delete which the caller does not have.
        let escalating = perms(&[
            (AdminResource::Users, AdminAction::View),
            (AdminResource::VirtualMachines, AdminAction::Delete),
        ]);
        let err = check_role_assignment(1, 2, false, "vm_manager", &caller, &escalating)
            .expect_err("escalating grant must be refused");
        assert!(
            err.error.contains("virtual_machines::delete"),
            "{}",
            err.error
        );

        // Subset of the caller's own permissions is fine.
        let subset = perms(&[(AdminResource::Users, AdminAction::View)]);
        assert!(check_role_assignment(1, 2, false, "read_only", &caller, &subset).is_ok());

        // A super admin holds everything implicitly.
        assert!(
            check_role_assignment(1, 2, true, "vm_manager", &HashSet::new(), &escalating).is_ok()
        );
    }

    /// Regression (F-05): `check_role_assignment` stopped an admin *granting*
    /// a role stronger than their own, but nothing stopped them *editing* a
    /// role they already hold. An admin with only `roles::update` could add
    /// every permission in the system to their own role and never trip the
    /// assignment guard, because no new assignment happens.
    #[test]
    fn test_cannot_define_role_with_permissions_caller_lacks() {
        let caller = perms(&[
            (AdminResource::Roles, AdminAction::Update),
            (AdminResource::Users, AdminAction::View),
        ]);

        // The escalation: hand my own role vm::delete and users::update.
        let escalating = perms(&[
            (AdminResource::Roles, AdminAction::Update),
            (AdminResource::VirtualMachines, AdminAction::Delete),
            (AdminResource::Users, AdminAction::Update),
        ]);

        let err = check_role_definition(false, &caller, &escalating)
            .expect_err("defining an escalating role must be refused");
        assert!(
            err.error.contains("virtual_machines::delete"),
            "{}",
            err.error
        );
        assert!(err.error.contains("users::update"), "{}", err.error);
    }

    /// Defining a role within your own permissions stays allowed — that is the
    /// ordinary delegation case.
    #[test]
    fn test_can_define_role_within_own_permissions() {
        let caller = perms(&[
            (AdminResource::Roles, AdminAction::Create),
            (AdminResource::Users, AdminAction::View),
            (AdminResource::VirtualMachines, AdminAction::View),
        ]);

        let delegated = perms(&[
            (AdminResource::Users, AdminAction::View),
            (AdminResource::VirtualMachines, AdminAction::View),
        ]);

        assert!(check_role_definition(false, &caller, &delegated).is_ok());
        // An empty role is trivially fine.
        assert!(check_role_definition(false, &caller, &HashSet::new()).is_ok());
    }

    /// A super admin implicitly holds everything, so may define any role.
    #[test]
    fn test_super_admin_can_define_any_role() {
        let everything = perms(&[
            (AdminResource::VirtualMachines, AdminAction::Delete),
            (AdminResource::Roles, AdminAction::Update),
            (AdminResource::Users, AdminAction::Update),
        ]);

        assert!(check_role_definition(true, &HashSet::new(), &everything).is_ok());
    }

    /// An unparseable permission string must be a clean 400, and must be caught
    /// before any mutation happens (the handler validates the whole set first,
    /// so a bad entry cannot leave a half-populated role behind).
    #[test]
    fn test_parse_permissions_rejects_unknown_values() {
        assert!(parse_permissions(&["users::view".to_string()]).is_ok());

        let err = parse_permissions(&["users::view".to_string(), "not_a_permission".to_string()])
            .expect_err("unknown permission must be rejected");
        assert!(err.error.contains("not_a_permission"), "{}", err.error);
    }

    /// Regression: the old guard made an accidental grant permanent, since the
    /// account that escalated itself could never hand the role back.
    #[test]
    fn test_super_admin_can_self_revoke_unless_last() {
        // Two super admins: self-revoke is allowed.
        assert!(check_role_revocation(1, 1, true, SUPER_ADMIN_ROLE, 2).is_ok());
        // Last super admin: blocked to avoid locking everyone out.
        assert!(check_role_revocation(1, 1, true, SUPER_ADMIN_ROLE, 1).is_err());
        // Revoking someone else's super_admin is fine even at count 1.
        assert!(check_role_revocation(1, 2, true, SUPER_ADMIN_ROLE, 1).is_ok());
        // Non super admins cannot strip super_admin at all.
        assert!(check_role_revocation(1, 2, false, SUPER_ADMIN_ROLE, 5).is_err());
        // Ordinary roles are unaffected.
        assert!(check_role_revocation(1, 1, false, "read_only", 1).is_ok());
    }
}
