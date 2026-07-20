use crate::admin::RouterState;
use crate::admin::model::Permission;
use anyhow::Result;
use axum::extract::FromRef;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use lnvps_api_common::{ApiError, Nip98Auth};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use std::collections::HashSet;
use std::sync::Arc;

pub struct AdminAuth {
    pub user_id: u64,
    pub pubkey: Vec<u8>,
    pub permissions: HashSet<Permission>,
    pub nip98_auth: Nip98Auth,
}

impl AdminAuth {
    pub async fn from_nip98_auth(nip98_auth: Nip98Auth, db: &Arc<dyn LNVpsDb>) -> Result<Self> {
        let pubkey = nip98_auth.pubkey();
        let user_id = db.upsert_user(&pubkey).await?;

        // Check if user has admin privileges and get their permissions
        let permission_tuples = db.get_user_permissions(user_id).await?;

        // Convert database tuples to Permission structs
        let permissions: HashSet<Permission> = permission_tuples
            .into_iter()
            .filter_map(|(resource_val, action_val)| {
                let resource = AdminResource::try_from(resource_val).ok()?;
                let action = AdminAction::try_from(action_val).ok()?;
                Some(Permission { resource, action })
            })
            .collect();

        Ok(AdminAuth {
            user_id,
            pubkey: pubkey.to_vec(),
            permissions,
            nip98_auth,
        })
    }

    /// Check whether the authenticated admin holds the `super_admin` role.
    ///
    /// Permissions alone can't express "super admin only" actions (a custom role
    /// could be granted the same permission tuples), so destructive operations
    /// like permanently purging a paid VM are gated on the role by name.
    pub async fn is_super_admin(&self, db: &Arc<dyn LNVpsDb>) -> Result<bool> {
        let role_ids = db.get_user_roles(self.user_id).await?;
        for role_id in role_ids {
            if db.get_role(role_id).await?.name == "super_admin" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check if the authenticated admin has a specific permission
    pub fn has_permission(&self, resource: AdminResource, action: AdminAction) -> bool {
        self.permissions.contains(&Permission { resource, action })
    }

    /// Require a specific permission, returning a 403 error if not present
    pub fn require_permission(
        &self,
        resource: AdminResource,
        action: AdminAction,
    ) -> std::result::Result<(), ApiError> {
        if self.has_permission(resource, action) {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!(
                "Insufficient permissions for {}::{}",
                resource, action
            )))
        }
    }

    /// Check if user has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[Permission]) -> bool {
        permissions
            .iter()
            .any(|perm| self.permissions.contains(perm))
    }

    /// Require any of the specified permissions, returning a 403 error if none present
    pub fn require_any_permission(
        &self,
        permissions: &[Permission],
    ) -> std::result::Result<(), ApiError> {
        if self.has_any_permission(permissions) {
            Ok(())
        } else {
            let perm_strings: Vec<String> = permissions
                .iter()
                .map(|p| format!("{}::{}", p.resource, p.action))
                .collect();
            Err(ApiError::forbidden(format!(
                "Insufficient permissions, need one of: {}",
                perm_strings.join(", ")
            )))
        }
    }
}

// Define state type for Admin API
pub struct AdminState {
    pub db: Arc<dyn LNVpsDb>,
}

impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
    RouterState: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        Box::pin(async {
            // First get the regular NIP-98 auth
            let nip98_auth = Nip98Auth::from_request_parts(parts, state).await?;

            let state = RouterState::from_ref(state);
            // Check admin privileges
            AdminAuth::from_nip98_auth(nip98_auth, &state.db)
                .await
                .map_err(|e| (StatusCode::FORBIDDEN, e.to_string()))
        })
    }
}

/// Verify admin authentication from a query parameter auth token
pub async fn verify_admin_auth_from_token(
    auth_token: &str,
    db: &Arc<dyn LNVpsDb>,
) -> Result<AdminAuth> {
    let nip98_auth = Nip98Auth::from_base64(auth_token)?;
    AdminAuth::from_nip98_auth(nip98_auth, db).await
}
