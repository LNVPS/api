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
use axum::extract::{Json, Path, State};
use axum::routing::{delete, get, post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, ApiResult, DEFAULT_CHALLENGE_TTL_SECS, Nip98Auth, issue_challenge_token,
    issue_session_token, verify_challenge_token,
};
use lnvps_db::{WebauthnCredential, webauthn_pubkey};

use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
    Webauthn, WebauthnBuilder,
};
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, COSEAlgorithm, CredProtect, CredentialProtectionPolicy,
    RegistrationState, RequestRegistrationExtensions, UserVerificationPolicy,
};

use crate::api::RouterState;
use crate::settings::WebauthnConfig;

const PURPOSE_REG: &str = "webauthn-reg";
const PURPOSE_AUTH: &str = "webauthn-auth";
/// Registration ceremony for adding a passkey to an already-authenticated account.
const PURPOSE_CRED_REG: &str = "webauthn-cred-reg";

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/webauthn/register/start", post(register_start))
        .route("/api/v1/webauthn/register/finish", post(register_finish))
        .route("/api/v1/webauthn/login/start", post(login_start))
        .route("/api/v1/webauthn/login/finish", post(login_finish))
        // Manage passkeys on the authenticated account.
        .route("/api/v1/webauthn/credentials", get(list_credentials))
        .route(
            "/api/v1/webauthn/credentials/start",
            post(add_credential_start),
        )
        .route(
            "/api/v1/webauthn/credentials/finish",
            post(add_credential_finish),
        )
        .route(
            "/api/v1/webauthn/credentials/{id}",
            delete(delete_credential),
        )
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
    reg: RegistrationState,
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

/// Public view of a registered passkey on the authenticated account.
#[derive(Serialize)]
pub struct WebauthnCredentialInfo {
    pub id: u64,
    pub name: Option<String>,
    pub created: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

impl From<&WebauthnCredential> for WebauthnCredentialInfo {
    fn from(c: &WebauthnCredential) -> Self {
        WebauthnCredentialInfo {
            id: c.id,
            name: c.name.clone(),
            created: c.created,
            last_used: c.last_used,
        }
    }
}

/// Stable per-account WebAuthn user handle so every passkey a user adds to their
/// account shares one identity in the authenticator. Derived from the account's
/// pubkey; login still resolves the account by credential id, so this value is
/// not security-critical.
fn account_handle(pubkey: &[u8; 32]) -> Uuid {
    let mut b = [0u8; 16];
    b.copy_from_slice(&pubkey[..16]);
    Uuid::from_bytes(b)
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

/// Build the lower-level [`WebauthnCore`] used to generate discoverable
/// (resident-key) registration challenges.
///
/// webauthn-rs' high-level `start_passkey_registration` hardcodes
/// `require_resident_key(false)` (`residentKey: "discouraged"`), so non-synced
/// authenticators (security keys, Windows Hello) create a *non-discoverable*
/// credential that usernameless `start_discoverable_authentication` can't find.
/// We drop to core to force `residentKey: "required"`.
fn build_webauthn_core(cfg: &WebauthnConfig) -> Result<WebauthnCore, ApiError> {
    let origin = Url::parse(&cfg.rp_origin)
        .map_err(|e| ApiError::internal(format!("Invalid webauthn rp_origin: {}", e)))?;
    Ok(WebauthnCore::new_unsafe_experts_only(
        &cfg.rp_name,
        &cfg.rp_id,
        vec![origin],
        // Matches webauthn-rs' default authenticator timeout.
        std::time::Duration::from_millis(60_000),
        None,
        None,
    ))
}

/// Registration extensions matching webauthn-rs' `start_passkey_registration`
/// (cred_protect UV-required, uvm, cred_props) so behaviour is otherwise
/// unchanged versus the high-level flow.
fn passkey_reg_extensions() -> RequestRegistrationExtensions {
    RequestRegistrationExtensions {
        cred_protect: Some(CredProtect {
            credential_protection_policy: CredentialProtectionPolicy::UserVerificationRequired,
            // Requesting strict enforcement makes many devices fail outright; we
            // request the policy but don't force it (same as webauthn-rs).
            enforce_credential_protection_policy: Some(false),
        }),
        uvm: Some(true),
        cred_props: Some(true),
        min_pin_length: None,
        hmac_create_secret: None,
    }
}

/// Begin a passkey registration that yields a **discoverable** credential.
///
/// Mirrors webauthn-rs' `start_passkey_registration` but with
/// `require_resident_key` driven by config (default `true`) and
/// `userVerification: required`, so usernameless login works across all
/// authenticator classes.
fn start_discoverable_registration(
    core: &WebauthnCore,
    handle: Uuid,
    name: &str,
    exclude: Option<Vec<CredentialID>>,
    require_resident_key: bool,
) -> Result<(CreationChallengeResponse, RegistrationState), ApiError> {
    let builder = core
        .new_challenge_register_builder(handle.as_bytes(), name, name)
        .map_err(|e| ApiError::internal(format!("Failed to start registration: {}", e)))?
        .attestation(AttestationConveyancePreference::None)
        .credential_algorithms(COSEAlgorithm::secure_algs())
        .require_resident_key(require_resident_key)
        .authenticator_attachment(None)
        .user_verification_policy(UserVerificationPolicy::Required)
        .reject_synchronised_authenticators(false)
        .exclude_credentials(exclude)
        .hints(None)
        .extensions(Some(passkey_reg_extensions()));
    core.generate_challenge_register(builder)
        .map_err(|e| ApiError::internal(format!("Failed to start registration: {}", e)))
}

/// Finish a discoverable passkey registration into a high-level [`Passkey`].
///
/// The result serialises/deserialises identically to a `Passkey` produced by
/// the high-level flow, so the login path (`DiscoverableKey::from(&Passkey)`,
/// `finish_discoverable_authentication`) keeps working unchanged.
fn finish_discoverable_registration(
    core: &WebauthnCore,
    reg: &RegisterPublicKeyCredential,
    state: &RegistrationState,
) -> Result<Passkey, ApiError> {
    let cred = core
        .register_credential(reg, state, None)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Registration failed: {}", e)))?;
    Ok(Passkey::from(cred))
}

/// Session token lifetime from the shared `[session]` config (default 30 days).
fn session_ttl(this: &RouterState) -> u64 {
    this.settings
        .session
        .as_ref()
        .map(|s| s.ttl)
        .unwrap_or(lnvps_api_common::DEFAULT_SESSION_TTL_SECS)
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
    let core = build_webauthn_core(&cfg)?;

    let name = body
        .and_then(|b| b.0.name)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "LNVPS user".to_string());

    // Fresh, stable account handle. Stored inside the credential and returned by
    // the authenticator during discoverable login.
    let handle = Uuid::new_v4();

    // Force a discoverable (resident-key) credential so usernameless login can
    // find it on every authenticator type.
    let (ccr, reg) =
        start_discoverable_registration(&core, handle, &name, None, cfg.require_resident_key)?;

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
    let core = build_webauthn_core(&cfg)?;

    let state_json = verify_challenge_token(PURPOSE_REG, &req.state)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Invalid registration state: {}", e)))?;
    let state: RegState = serde_json::from_str(&state_json).map_err(ApiError::internal)?;

    let passkey = finish_discoverable_registration(&core, &req.credential, &state.reg)?;

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

    issue_token(&pubkey, uid, session_ttl(&this))
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

    issue_token(&pubkey, used.user_id, session_ttl(&this))
}

/// List the passkeys registered to the authenticated account.
async fn list_credentials(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<WebauthnCredentialInfo>> {
    // Passkeys require WebAuthn to be configured at all.
    webauthn_cfg(&this)?;
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let creds = this.db.list_webauthn_credentials(uid).await?;
    ApiData::ok(creds.iter().map(WebauthnCredentialInfo::from).collect())
}

/// Begin adding a passkey to the authenticated account (any account type).
async fn add_credential_start(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    body: Option<Json<RegisterStartRequest>>,
) -> ApiResult<RegisterStartResponse> {
    let cfg = webauthn_cfg(&this)?;
    let core = build_webauthn_core(&cfg)?;
    let uid = this.db.upsert_user(&auth.pubkey()).await?;

    let name = body
        .and_then(|b| b.0.name)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "LNVPS user".to_string());

    // Exclude already-registered credentials so the same authenticator cannot be
    // enrolled twice on this account.
    let existing = this.db.list_webauthn_credentials(uid).await?;
    let exclude: Vec<CredentialID> = existing
        .iter()
        .map(|c| CredentialID::from(c.cred_id.clone()))
        .collect();

    let handle = account_handle(&auth.pubkey());
    // Discoverable so an added passkey also works for usernameless login.
    let (ccr, reg) = start_discoverable_registration(
        &core,
        handle,
        &name,
        Some(exclude),
        cfg.require_resident_key,
    )?;

    let token = issue_challenge_token(
        PURPOSE_CRED_REG,
        &serde_json::to_string(&reg).map_err(ApiError::internal)?,
        DEFAULT_CHALLENGE_TTL_SECS,
    )
    .map_err(|e| ApiError::internal(format!("Failed to create challenge: {}", e)))?;

    ApiData::ok(RegisterStartResponse {
        challenge: ccr,
        state: token,
    })
}

/// Complete adding a passkey to the authenticated account and store it.
async fn add_credential_finish(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<WebauthnCredentialInfo> {
    let cfg = webauthn_cfg(&this)?;
    let core = build_webauthn_core(&cfg)?;

    let state_json = verify_challenge_token(PURPOSE_CRED_REG, &req.state)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Invalid registration state: {}", e)))?;
    let reg: RegistrationState = serde_json::from_str(&state_json).map_err(ApiError::internal)?;

    let passkey = finish_discoverable_registration(&core, &req.credential, &reg)?;

    let cred_id = passkey.cred_id().as_ref().to_vec();
    if this.db.get_webauthn_credential(&cred_id).await.is_ok() {
        return Err(ApiError::from(anyhow::anyhow!(
            "Credential already registered"
        )));
    }

    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let passkey_json = serde_json::to_string(&passkey).map_err(ApiError::internal)?;
    let id = this
        .db
        .insert_webauthn_credential(&WebauthnCredential {
            user_id: uid,
            cred_id,
            passkey: passkey_json,
            name: req.name.filter(|s| !s.trim().is_empty()),
            ..Default::default()
        })
        .await?;

    let created = this
        .db
        .list_webauthn_credentials(uid)
        .await?
        .iter()
        .find(|c| c.id == id)
        .map(WebauthnCredentialInfo::from)
        .ok_or_else(|| ApiError::internal("Stored credential not found"))?;
    ApiData::ok(created)
}

/// Remove a passkey from the authenticated account. A pure passkey account may
/// not delete its only credential (that would lock the user out permanently).
async fn delete_credential(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    webauthn_cfg(&this)?;
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let user = this.db.get_user(uid).await?;
    let creds = this.db.list_webauthn_credentials(uid).await?;

    if !creds.iter().any(|c| c.id == id) {
        return ApiData::err("Credential not found");
    }
    if user.account_type == lnvps_db::AccountType::Webauthn && creds.len() <= 1 {
        return ApiData::err("Cannot remove your only passkey");
    }

    this.db.delete_webauthn_credential(id, uid).await?;
    ApiData::ok(())
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
            require_resident_key: true,
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

    /// Registration options must request a discoverable (resident-key)
    /// credential with user verification required, so usernameless login works
    /// across all authenticator types (issue: non-synced authenticators).
    #[test]
    fn registration_requests_resident_key() {
        let core = build_webauthn_core(&test_cfg()).unwrap_or_else(|_| panic!("core builds"));
        let (ccr, _state) =
            start_discoverable_registration(&core, Uuid::new_v4(), "alice", None, true)
                .unwrap_or_else(|_| panic!("registration starts"));

        let sel = ccr
            .public_key
            .authenticator_selection
            .expect("authenticator_selection present");
        assert_eq!(
            sel.resident_key,
            Some(webauthn_rs_core::proto::ResidentKeyRequirement::Required),
            "residentKey must be required"
        );
        assert!(
            sel.require_resident_key,
            "require_resident_key must be true"
        );
        assert_eq!(
            sel.user_verification,
            UserVerificationPolicy::Required,
            "userVerification must be required"
        );

        // With the flag disabled, resident key is no longer required.
        let (ccr2, _s2) =
            start_discoverable_registration(&core, Uuid::new_v4(), "alice", None, false)
                .unwrap_or_else(|_| panic!("registration starts"));
        let sel2 = ccr2
            .public_key
            .authenticator_selection
            .expect("authenticator_selection present");
        assert_ne!(
            sel2.resident_key,
            Some(webauthn_rs_core::proto::ResidentKeyRequirement::Required)
        );
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

    /// A per-account handle is stable for the same pubkey and differs across
    /// accounts.
    #[test]
    fn account_handle_is_stable_per_account() {
        let a = webauthn_pubkey("handle-a");
        let b = webauthn_pubkey("handle-b");
        assert_eq!(account_handle(&a), account_handle(&a));
        assert_ne!(account_handle(&a), account_handle(&b));
    }

    /// Deleting a credential is scoped to its owner and removes only that row.
    #[tokio::test]
    async fn delete_credential_is_owner_scoped() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let uid = db
            .upsert_webauthn_user(&webauthn_pubkey("owner"))
            .await
            .unwrap();
        let other = db
            .upsert_webauthn_user(&webauthn_pubkey("intruder"))
            .await
            .unwrap();

        let mk = |user_id: u64, cid: Vec<u8>| WebauthnCredential {
            user_id,
            cred_id: cid,
            passkey: "{}".to_string(),
            ..Default::default()
        };
        let id1 = db
            .insert_webauthn_credential(&mk(uid, vec![1]))
            .await
            .unwrap();
        let id2 = db
            .insert_webauthn_credential(&mk(uid, vec![2]))
            .await
            .unwrap();

        // Another account cannot delete our credential.
        db.delete_webauthn_credential(id1, other).await.unwrap();
        assert_eq!(db.list_webauthn_credentials(uid).await.unwrap().len(), 2);

        // Owner can delete their own; only that row is removed.
        db.delete_webauthn_credential(id1, uid).await.unwrap();
        let left = db.list_webauthn_credentials(uid).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, id2);
    }
}
