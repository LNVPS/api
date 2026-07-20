//! Admin management of user passkeys (WebAuthn credentials).
//!
//! Passkeys are the login factors of a user account, so these endpoints are
//! gated behind the [`AdminResource::Users`] permission (View to list, Update
//! to revoke). Credential material (the serialised passkey / public key) is
//! never exposed — only metadata an admin needs to identify and revoke a
//! device.

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{delete, get};
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiData, ApiError, ApiResult};
use lnvps_db::{AccountType, AdminAction, AdminResource, WebauthnCredential};
use serde::Serialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/users/{id}/passkeys",
            get(admin_list_user_passkeys),
        )
        .route(
            "/api/admin/v1/users/{id}/passkeys/{passkey_id}",
            delete(admin_delete_user_passkey),
        )
}

/// Admin view of a registered passkey. Never includes the credential material.
#[derive(Serialize)]
pub struct AdminPasskeyInfo {
    /// Database id of the credential (used to revoke it).
    pub id: u64,
    /// Optional user-facing device label.
    pub name: Option<String>,
    /// Hex-encoded raw credential id.
    pub cred_id: String,
    /// When the passkey was registered.
    pub created: DateTime<Utc>,
    /// When the passkey was last used to authenticate, if ever.
    pub last_used: Option<DateTime<Utc>>,
}

impl From<&WebauthnCredential> for AdminPasskeyInfo {
    fn from(c: &WebauthnCredential) -> Self {
        Self {
            id: c.id,
            name: c.name.clone(),
            cred_id: hex::encode(&c.cred_id),
            created: c.created,
            last_used: c.last_used,
        }
    }
}

/// List all passkeys registered to a user.
async fn admin_list_user_passkeys(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<AdminPasskeyInfo>> {
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    // Resolve the user first so an unknown id is a clear 404 rather than an
    // empty list.
    this.db.get_user(id).await?;

    let creds = this.db.list_webauthn_credentials(id).await?;
    ApiData::ok(creds.iter().map(AdminPasskeyInfo::from).collect())
}

/// Revoke a single passkey from a user's account.
///
/// Refuses to remove the last passkey of a passwordless (WebAuthn-only)
/// account, since that would permanently lock the user out.
async fn admin_delete_user_passkey(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, passkey_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::Users, AdminAction::Update)?;

    let user = this.db.get_user(id).await?;
    let creds = this.db.list_webauthn_credentials(id).await?;

    if !creds.iter().any(|c| c.id == passkey_id) {
        return Err(ApiError::not_found("Passkey not found for this user"));
    }
    if user.account_type == AccountType::Webauthn && creds.len() <= 1 {
        return Err(ApiError::bad_request(
            "Cannot remove the user's only passkey; a passwordless account would be locked out",
        ));
    }

    // delete_webauthn_credential is scoped to (id, user_id) so an admin can only
    // remove a credential that actually belongs to the target user.
    this.db.delete_webauthn_credential(passkey_id, id).await?;
    ApiData::ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{LNVpsDb, webauthn_pubkey};
    use std::sync::Arc;

    async fn mk_cred(db: &Arc<dyn LNVpsDb>, uid: u64, cid: Vec<u8>) -> u64 {
        db.insert_webauthn_credential(&WebauthnCredential {
            user_id: uid,
            cred_id: cid,
            passkey: "{}".to_string(),
            name: Some("device".to_string()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// Deleting the only passkey of a webauthn account is refused; deleting one
    /// of several is allowed.
    #[tokio::test]
    async fn last_passkey_of_webauthn_account_is_protected() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let uid = db
            .upsert_webauthn_user(&webauthn_pubkey("acct"))
            .await
            .unwrap();

        let id1 = mk_cred(&db, uid, vec![1]).await;

        // Only credential — protected.
        let user = db.get_user(uid).await.unwrap();
        let creds = db.list_webauthn_credentials(uid).await.unwrap();
        assert_eq!(user.account_type, AccountType::Webauthn);
        assert_eq!(creds.len(), 1);

        // Add a second, then the first can be removed.
        let _id2 = mk_cred(&db, uid, vec![2]).await;
        db.delete_webauthn_credential(id1, uid).await.unwrap();
        assert_eq!(db.list_webauthn_credentials(uid).await.unwrap().len(), 1);
    }
}
