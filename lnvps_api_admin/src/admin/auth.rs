use crate::admin::RouterState;
use crate::admin::model::Permission;
use anyhow::{Result, bail};
use axum::extract::FromRef;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use lnvps_api_common::Nip98Auth;
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
        let pubkey = nip98_auth.event.pubkey.to_bytes();
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

    /// Check if the authenticated admin has a specific permission
    pub fn has_permission(&self, resource: AdminResource, action: AdminAction) -> bool {
        self.permissions.contains(&Permission { resource, action })
    }

    /// Require a specific permission, returning an error if not present
    pub fn require_permission(&self, resource: AdminResource, action: AdminAction) -> Result<()> {
        if self.has_permission(resource, action) {
            Ok(())
        } else {
            bail!("Insufficient permissions for {}::{}", resource, action)
        }
    }

    /// Check if user has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[Permission]) -> bool {
        permissions
            .iter()
            .any(|perm| self.permissions.contains(perm))
    }

    /// Require any of the specified permissions
    pub fn require_any_permission(&self, permissions: &[Permission]) -> anyhow::Result<()> {
        if self.has_any_permission(permissions) {
            Ok(())
        } else {
            let perm_strings: Vec<String> = permissions
                .iter()
                .map(|p| format!("{}::{}", p.resource, p.action))
                .collect();
            bail!(
                "Insufficient permissions, need one of: {}",
                perm_strings.join(", ")
            )
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
            let nip98_auth = Nip98Auth::from_request_parts(parts, state)
                .await
                .map_err(|(status, msg)| (status, msg))?;

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
