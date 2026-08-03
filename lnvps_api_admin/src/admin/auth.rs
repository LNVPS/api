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
    /// The NIP-98 event this request authenticated with, when it came in via the
    /// `Authorization` header. `None` for the query-parameter/ticket path, which
    /// resolves an identity without retaining an event.
    pub nip98_auth: Option<Nip98Auth>,
}

impl AdminAuth {
    pub async fn from_nip98_auth(nip98_auth: Nip98Auth, db: &Arc<dyn LNVpsDb>) -> Result<Self> {
        let pubkey = nip98_auth.pubkey();
        let user_id = db.upsert_user(&pubkey).await?;
        let permissions = Self::load_permissions(user_id, db).await?;

        Ok(AdminAuth {
            user_id,
            pubkey: pubkey.to_vec(),
            permissions,
            nip98_auth: Some(nip98_auth),
        })
    }

    /// Build from an already-resolved identity (the query-parameter/ticket path,
    /// which has no NIP-98 event to retain).
    async fn from_user_id(user_id: u64, pubkey: [u8; 32], db: &Arc<dyn LNVpsDb>) -> Result<Self> {
        Ok(AdminAuth {
            user_id,
            pubkey: pubkey.to_vec(),
            permissions: Self::load_permissions(user_id, db).await?,
            nip98_auth: None,
        })
    }

    /// Load and decode the user's granted permissions.
    async fn load_permissions(user_id: u64, db: &Arc<dyn LNVpsDb>) -> Result<HashSet<Permission>> {
        Ok(db
            .get_user_permissions(user_id)
            .await?
            .into_iter()
            .filter_map(|(resource_val, action_val)| {
                let resource = AdminResource::try_from(resource_val).ok()?;
                let action = AdminAction::try_from(action_val).ok()?;
                Some(Permission { resource, action })
            })
            .collect())
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
    Arc<dyn LNVpsDb>: axum::extract::FromRef<S>,
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

/// Credential carried in the query string by endpoints a browser cannot send an
/// `Authorization` header to (WebSocket handshakes).
///
/// Prefer `ticket` — a single-use, path-scoped, 30-second credential from
/// `POST /api/admin/v1/auth/ticket`. `auth` (a raw base64 NIP-98 event) is the
/// legacy form, retained during the client migration.
#[derive(serde::Deserialize)]
pub struct AdminAuthQuery {
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub ticket: Option<String>,
}

impl AdminAuthQuery {
    /// Resolve and authorize the caller for `path`.
    pub async fn resolve(&self, path: &str, db: &Arc<dyn LNVpsDb>) -> Result<AdminAuth> {
        let pubkey = match (&self.ticket, &self.auth) {
            (Some(ticket), _) => lnvps_api_common::consume_ticket(ticket, path)?,
            (None, Some(auth)) => {
                let nip98 = Nip98Auth::from_base64(auth)?;
                nip98.check(path, "GET")?;
                nip98.pubkey()
            }
            (None, None) => anyhow::bail!("Missing auth or ticket param"),
        };

        let user_id = db.upsert_user(&pubkey).await?;
        AdminAuth::from_user_id(user_id, pubkey, db).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::{DEFAULT_TICKET_TTL_SECS, MockDb, init_session_secret, issue_ticket};

    const FEEDBACK_PATH: &str = "/api/admin/v1/jobs/feedback";

    fn db() -> Arc<dyn LNVpsDb> {
        Arc::new(MockDb::default())
    }

    /// A ticket resolves to the identity it was minted for, on the path it was
    /// minted for.
    #[tokio::test]
    async fn resolves_a_ticket_for_the_right_path() {
        init_session_secret(b"unit-test-secret".to_vec());
        let db = db();
        let pubkey = [21u8; 32];

        let q = AdminAuthQuery {
            auth: None,
            ticket: Some(issue_ticket(&pubkey, FEEDBACK_PATH, DEFAULT_TICKET_TTL_SECS).unwrap()),
        };

        let auth = q.resolve(FEEDBACK_PATH, &db).await.unwrap();
        assert_eq!(auth.pubkey, pubkey.to_vec());
        // MockDb grants nothing, so the permission gate downstream still bites.
        assert!(auth.permissions.is_empty());
    }

    /// A ticket minted for another path must not open this endpoint.
    #[tokio::test]
    async fn rejects_a_ticket_for_another_path() {
        init_session_secret(b"unit-test-secret".to_vec());
        let db = db();

        let q = AdminAuthQuery {
            auth: None,
            ticket: Some(
                issue_ticket(&[22u8; 32], "/api/v1/vm/1/console", DEFAULT_TICKET_TTL_SECS).unwrap(),
            ),
        };

        assert!(q.resolve(FEEDBACK_PATH, &db).await.is_err());
    }

    /// Regression (F-03): this path used to call `Nip98Auth::from_base64` and
    /// trust the result. `from_base64` only *parses* — it verifies neither the
    /// signature nor the event id — so any well-formed JSON authenticated as
    /// whatever `pubkey` it claimed. A bogus credential must now be refused.
    /// (The forged-but-well-formed-event case is covered in
    /// `lnvps_api_common::nip98`, which owns the verification.)
    #[tokio::test]
    async fn rejects_unverifiable_legacy_auth() {
        let db = db();

        let q = AdminAuthQuery {
            auth: Some("this-is-not-a-nostr-event".to_string()),
            ticket: None,
        };
        assert!(q.resolve(FEEDBACK_PATH, &db).await.is_err());

        // Valid base64 of JSON that is not an event.
        let q = AdminAuthQuery {
            auth: Some("eyJhIjoxfQ==".to_string()),
            ticket: None,
        };
        assert!(q.resolve(FEEDBACK_PATH, &db).await.is_err());
    }

    /// Supplying no credential at all must be refused, not treated as anonymous.
    #[tokio::test]
    async fn rejects_missing_credential() {
        let db = db();
        let q = AdminAuthQuery {
            auth: None,
            ticket: None,
        };
        assert!(q.resolve(FEEDBACK_PATH, &db).await.is_err());
    }

    /// A used ticket is dead, so a copy captured from a log is inert.
    #[tokio::test]
    async fn ticket_is_single_use() {
        init_session_secret(b"unit-test-secret".to_vec());
        let db = db();
        let ticket = issue_ticket(&[23u8; 32], FEEDBACK_PATH, DEFAULT_TICKET_TTL_SECS).unwrap();

        let first = AdminAuthQuery {
            auth: None,
            ticket: Some(ticket.clone()),
        };
        assert!(first.resolve(FEEDBACK_PATH, &db).await.is_ok());

        let replay = AdminAuthQuery {
            auth: None,
            ticket: Some(ticket),
        };
        assert!(replay.resolve(FEEDBACK_PATH, &db).await.is_err());
    }
}
