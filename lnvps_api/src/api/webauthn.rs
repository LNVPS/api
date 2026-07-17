//! Passwordless WebAuthn / passkey login.
//!
//! Mirrors the OAuth flow (`api/oauth.rs`): a passkey *is* the account. A fresh
//! account is minted on registration with a synthetic identity
//! (`sha256("webauthn:{user_handle}")`, see [`lnvps_db::webauthn_pubkey`]) and,
//! on success, the user is issued the same stateless session JWT that OAuth
//! users get — accepted by the shared `Nip98Auth` extractor as
//! `Authorization: Bearer <jwt>`.
//!
//! Login is **usernameless/discoverable**: the browser presents whichever
//! passkey the user picks, the authenticator returns the account's user handle,
//! and the server resolves the account from the stored credential.
//!
//! Both ceremonies are two round-trips. The intermediate server-owned state
//! (`PasskeyRegistration` / `DiscoverableAuthentication`) is carried back to the
//! client inside a signed, short-lived *challenge token* (HS256, see
//! [`lnvps_api_common::issue_challenge_token`]) so the API stays stateless while
//! remaining tamper-proof against the client.

use axum::Router;
use axum::extract::{Json, State};
use axum::routing::post;
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, ApiResult, DEFAULT_CHALLENGE_TTL_SECS, issue_challenge_token,
    issue_session_token, verify_challenge_token,
};
use lnvps_db::{WebauthnCredential, webauthn_pubkey};

use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::api::RouterState;
use crate::settings::WebauthnConfig;

const PURPOSE_REG: &str = "webauthn-reg";
const PURPOSE_AUTH: &str = "webauthn-auth";

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/webauthn/register/start", post(register_start))
        .route("/api/v1/webauthn/register/finish", post(register_finish))
        .route("/api/v1/webauthn/login/start", post(login_start))
        .route("/api/v1/webauthn/login/finish", post(login_finish))
}

/// Session token handed back after a successful passkey register/login. Same
/// shape as the OAuth token response.
#[derive(Serialize)]
pub struct WebauthnTokenResponse {
    /// Session JWT to be sent as `Authorization: Bearer <token>`.
    pub token: String,
    /// Token type, always `Bearer`.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
}

#[derive(Deserialize)]
struct RegisterStartRequest {
    /// Optional friendly label shown in the authenticator UI (not an identity).
    name: Option<String>,
}

#[derive(Serialize)]
struct RegisterStartResponse {
    /// Pass straight to `navigator.credentials.create({ publicKey })`.
    challenge: CreationChallengeResponse,
    /// Opaque signed state to echo back on the finish step.
    state: String,
}

/// Registration ceremony state we carry through the client (signed).
#[derive(Serialize, Deserialize)]
struct RegState {
    /// Per-account user handle minted at start; basis of the synthetic pubkey.
    handle: String,
    reg: PasskeyRegistration,
}

#[derive(Deserialize)]
struct RegisterFinishRequest {
    /// The signed state returned by `register/start`.
    state: String,
    /// The credential produced by `navigator.credentials.create`.
    credential: RegisterPublicKeyCredential,
    /// Optional friendly label to store with the credential.
    name: Option<String>,
}

#[derive(Serialize)]
struct LoginStartResponse {
    /// Pass straight to `navigator.credentials.get({ publicKey })`.
    challenge: RequestChallengeResponse,
    /// Opaque signed state to echo back on the finish step.
    state: String,
}

#[derive(Deserialize)]
struct LoginFinishRequest {
    /// The signed state returned by `login/start`.
    state: String,
    /// The assertion produced by `navigator.credentials.get`.
    credential: PublicKeyCredential,
}

/// Build a `Webauthn` instance from the configured relying-party identity.
fn build_webauthn(cfg: &WebauthnConfig) -> Result<Webauthn, ApiError> {
    let origin = Url::parse(&cfg.rp_origin)
        .map_err(|e| ApiError::internal(format!("Invalid webauthn rp_origin: {}", e)))?;
    let builder = WebauthnBuilder::new(&cfg.rp_id, &origin)
        .map_err(|e| ApiError::internal(format!("Invalid webauthn config: {}", e)))?;
    builder
        .rp_name(&cfg.rp_name)
        .build()
        .map_err(|e| ApiError::internal(format!("Failed to build webauthn: {}", e)))
}

/// Resolve the WebAuthn config or 4xx if passkeys are disabled.
fn webauthn_cfg(this: &RouterState) -> Result<WebauthnConfig, ApiError> {
    this.settings
        .webauthn
        .clone()
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("WebAuthn not configured")))
}

/// Begin registration of a brand-new passwordless account.
async fn register_start(
    State(this): State<RouterState>,
    body: Option<Json<RegisterStartRequest>>,
) -> ApiResult<RegisterStartResponse> {
    let cfg = webauthn_cfg(&this)?;
    let webauthn = build_webauthn(&cfg)?;

    let name = body
        .and_then(|b| b.0.name)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "LNVPS user".to_string());

    // Fresh, stable account handle. Stored inside the credential and returned by
    // the authenticator during discoverable login.
    let handle = Uuid::new_v4();

    let (ccr, reg) = webauthn
        .start_passkey_registration(handle, &name, &name, None)
        .map_err(|e| ApiError::internal(format!("Failed to start registration: {}", e)))?;

    let state = RegState {
        handle: handle.to_string(),
        reg,
    };
    let token = issue_challenge_token(
        PURPOSE_REG,
        &serde_json::to_string(&state).map_err(ApiError::internal)?,
        DEFAULT_CHALLENGE_TTL_SECS,
    )
    .map_err(|e| ApiError::internal(format!("Failed to create challenge: {}", e)))?;

    ApiData::ok(RegisterStartResponse {
        challenge: ccr,
        state: token,
    })
}

/// Complete registration: verify the attestation, create the account, store the
/// credential and issue a session token.
async fn register_finish(
    State(this): State<RouterState>,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<WebauthnTokenResponse> {
    let cfg = webauthn_cfg(&this)?;
    let webauthn = build_webauthn(&cfg)?;

    let state_json = verify_challenge_token(PURPOSE_REG, &req.state)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Invalid registration state: {}", e)))?;
    let state: RegState = serde_json::from_str(&state_json).map_err(ApiError::internal)?;

    let passkey = webauthn
        .finish_passkey_registration(&req.credential, &state.reg)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Registration failed: {}", e)))?;

    let cred_id = passkey.cred_id().as_ref().to_vec();

    // A credential id must never be registered to two accounts.
    if this.db.get_webauthn_credential(&cred_id).await.is_ok() {
        return Err(ApiError::from(anyhow::anyhow!(
            "Credential already registered"
        )));
    }

    // Mint the account from the handle-derived synthetic identity.
    let pubkey = webauthn_pubkey(&state.handle);
    let uid = this.db.upsert_webauthn_user(&pubkey).await?;

    let passkey_json = serde_json::to_string(&passkey).map_err(ApiError::internal)?;
    this.db
        .insert_webauthn_credential(&WebauthnCredential {
            user_id: uid,
            cred_id,
            passkey: passkey_json,
            name: req.name.filter(|s| !s.trim().is_empty()),
            ..Default::default()
        })
        .await?;

    issue_token(&pubkey, uid, cfg.session_ttl)
}

/// Begin a usernameless (discoverable) login.
async fn login_start(State(this): State<RouterState>) -> ApiResult<LoginStartResponse> {
    let cfg = webauthn_cfg(&this)?;
    let webauthn = build_webauthn(&cfg)?;

    let (rcr, auth) = webauthn
        .start_discoverable_authentication()
        .map_err(|e| ApiError::internal(format!("Failed to start authentication: {}", e)))?;

    let token = issue_challenge_token(
        PURPOSE_AUTH,
        &serde_json::to_string(&auth).map_err(ApiError::internal)?,
        DEFAULT_CHALLENGE_TTL_SECS,
    )
    .map_err(|e| ApiError::internal(format!("Failed to create challenge: {}", e)))?;

    ApiData::ok(LoginStartResponse {
        challenge: rcr,
        state: token,
    })
}

/// Complete a discoverable login: identify the account from the assertion,
/// verify it against the stored passkeys, bump the counter and issue a token.
async fn login_finish(
    State(this): State<RouterState>,
    Json(req): Json<LoginFinishRequest>,
) -> ApiResult<WebauthnTokenResponse> {
    let cfg = webauthn_cfg(&this)?;
    let webauthn = build_webauthn(&cfg)?;

    let state_json = verify_challenge_token(PURPOSE_AUTH, &req.state)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Invalid authentication state: {}", e)))?;
    let auth: DiscoverableAuthentication =
        serde_json::from_str(&state_json).map_err(ApiError::internal)?;

    // Extract the credential id the user asserted with, and locate the account.
    let (_uuid, cred_id) = webauthn
        .identify_discoverable_authentication(&req.credential)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Unknown credential: {}", e)))?;

    let used = this
        .db
        .get_webauthn_credential(cred_id.as_ref())
        .await
        .map_err(|_| ApiError::from(anyhow::anyhow!("Unknown credential")))?;

    // Load all of the account's passkeys as discoverable keys for verification.
    let stored = this.db.list_webauthn_credentials(used.user_id).await?;
    let passkeys: Vec<Passkey> = stored
        .iter()
        .filter_map(|c| serde_json::from_str::<Passkey>(&c.passkey).ok())
        .collect();
    let discoverable: Vec<DiscoverableKey> = passkeys.iter().map(DiscoverableKey::from).collect();

    let result = webauthn
        .finish_discoverable_authentication(&req.credential, auth, &discoverable)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Authentication failed: {}", e)))?;

    // Persist any counter/backup-state change on the credential that was used.
    if let Some(mut pk) = passkeys
        .iter()
        .find(|p| p.cred_id() == result.cred_id())
        .cloned()
        && pk.update_credential(&result).is_some()
        && let Ok(json) = serde_json::to_string(&pk)
    {
        // Best-effort — a failed counter write must not block a valid login.
        let _ = this.db.update_webauthn_credential(used.id, &json).await;
    }

    let user = this.db.get_user(used.user_id).await?;
    let pubkey: [u8; 32] = user
        .pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal("Invalid stored pubkey"))?;

    issue_token(&pubkey, used.user_id, cfg.session_ttl)
}

/// Issue the session JWT response.
fn issue_token(pubkey: &[u8; 32], uid: u64, ttl: u64) -> ApiResult<WebauthnTokenResponse> {
    let token = issue_session_token(pubkey, uid, ttl)
        .map_err(|e| ApiError::internal(format!("Failed to issue session: {}", e)))?;
    ApiData::ok(WebauthnTokenResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDb;
    use std::sync::Arc;

    fn test_cfg() -> WebauthnConfig {
        WebauthnConfig {
            rp_id: "example.com".to_string(),
            rp_origin: "https://example.com".to_string(),
            rp_name: "Example".to_string(),
            session_secret: "unit-test-secret".to_string(),
            session_ttl: 3600,
        }
    }

    /// A valid relying-party config builds; a bad origin is rejected.
    #[test]
    fn build_webauthn_validates_origin() {
        assert!(build_webauthn(&test_cfg()).is_ok());

        let mut bad = test_cfg();
        bad.rp_origin = "not a url".to_string();
        assert!(build_webauthn(&bad).is_err());
    }

    /// The credential store round-trips: a passkey account can be minted, its
    /// credential inserted, looked up by credential id, listed and updated.
    #[tokio::test]
    async fn credential_store_roundtrip() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());

        let pubkey = webauthn_pubkey("handle-abc");
        let uid = db.upsert_webauthn_user(&pubkey).await.unwrap();
        // Account is marked as a webauthn account.
        assert_eq!(
            db.get_user(uid).await.unwrap().account_type,
            lnvps_db::AccountType::Webauthn
        );
        // Same handle resolves to the same account (idempotent upsert).
        assert_eq!(db.upsert_webauthn_user(&pubkey).await.unwrap(), uid);

        let cred_id = vec![1u8, 2, 3, 4];
        let id = db
            .insert_webauthn_credential(&WebauthnCredential {
                user_id: uid,
                cred_id: cred_id.clone(),
                passkey: "{\"v\":1}".to_string(),
                name: Some("YubiKey".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();

        let got = db.get_webauthn_credential(&cred_id).await.unwrap();
        assert_eq!(got.user_id, uid);
        assert_eq!(got.name.as_deref(), Some("YubiKey"));

        let list = db.list_webauthn_credentials(uid).await.unwrap();
        assert_eq!(list.len(), 1);

        db.update_webauthn_credential(id, "{\"v\":2}")
            .await
            .unwrap();
        assert_eq!(
            db.get_webauthn_credential(&cred_id).await.unwrap().passkey,
            "{\"v\":2}"
        );
    }
}
