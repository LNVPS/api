use crate::admin::model::Permission;
use anyhow::{bail, Result};
use lnvps_api_common::Nip98Auth;
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::{async_trait, Request, State};
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

#[async_trait]
impl<'r> FromRequest<'r> for AdminAuth {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // First get the regular NIP-98 auth
        let nip98_auth = match Nip98Auth::from_request(request).await {
            Outcome::Success(auth) => auth,
            Outcome::Error((status, msg)) => return Outcome::Error((status, msg)),
            Outcome::Forward(forward) => return Outcome::Forward(forward),
        };

        // Get database connection
        let db = match request.guard::<&State<Arc<dyn LNVpsDb>>>().await {
            Outcome::Success(db) => db,
            Outcome::Error(_) => {
                return Outcome::Error((
                    Status::InternalServerError,
                    "Database connection unavailable".to_string(),
                ));
            }
            Outcome::Forward(_) => {
                return Outcome::Error((
                    Status::InternalServerError,
                    "Database connection unavailable".to_string(),
                ));
            }
        };

        // Check admin privileges
        match AdminAuth::from_nip98_auth(nip98_auth, db.inner()).await {
            Ok(admin_auth) => Outcome::Success(admin_auth),
            Err(e) => Outcome::Error((Status::Forbidden, e.to_string())),
        }
    }
}

/// Verify admin authentication from a query parameter auth token
pub async fn verify_admin_auth_from_token(auth_token: &str, db: &Arc<dyn LNVpsDb>) -> Result<AdminAuth> {
    let nip98_auth = Nip98Auth::from_base64(auth_token)?;
    AdminAuth::from_nip98_auth(nip98_auth, db).await
}
