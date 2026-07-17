//! Generic OAuth2 / OIDC login with built-in support for Google, GitHub,
//! Facebook and Sign in with Apple (plus a fully generic `oidc` flavor).
//!
//! On success the user is looked up/created via their synthetic identity
//! (`sha256("{provider}:{subject}")`, see [`lnvps_db::oauth_pubkey`]) and issued
//! a stateless session JWT. That JWT is accepted by the same `Nip98Auth`
//! extractor (as `Authorization: Bearer <jwt>`) that guards the rest of the API,
//! so OAuth users reach the exact same endpoints as Nostr users.
//!
//! Provider-specific quirks handled here:
//! - **GitHub** requires a `User-Agent` header and its subject is the numeric
//!   `id` (not `sub`); its token endpoint returns JSON when asked via `Accept`.
//! - **Facebook** identifies users via the Graph `me` endpoint (`id`).
//! - **Apple** has no userinfo endpoint (the subject comes from the `id_token`),
//!   requires a dynamically-signed **ES256** JWT as the `client_secret`, and
//!   uses `response_mode=form_post` (a POST callback) when name/email is asked.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use log::warn;
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, DEFAULT_STATE_TTL_SECS, issue_session_token, issue_state_token,
    verify_state_token,
};
use lnvps_db::{EncryptedString, LNVpsDb, oauth_pubkey};

use crate::api::RouterState;
use crate::settings::{OAuthProviderConfig, SubjectSource};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/oauth/{provider}/login", get(v1_oauth_login))
        .route(
            "/api/v1/oauth/{provider}/callback",
            // GET for standard redirects; POST for Apple `response_mode=form_post`.
            get(v1_oauth_callback_get).post(v1_oauth_callback_post),
        )
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct LoginParams {
    /// Optional per-request post-login redirect URL. Validated against the
    /// OAuth `allowed_redirects` allowlist before being round-tripped through
    /// the signed state.
    redirect: Option<String>,
}

#[derive(Serialize)]
pub struct OAuthTokenResponse {
    /// Session JWT to be sent as `Authorization: Bearer <token>`.
    pub token: String,
    /// Token type, always `Bearer`.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
}

/// Build the redirect URI this service exposes for a provider callback.
fn callback_uri(public_url: &str, provider: &str) -> String {
    format!(
        "{}/api/v1/oauth/{}/callback",
        public_url.trim_end_matches('/'),
        provider
    )
}

/// Start a login: redirect the browser to the provider's authorization endpoint.
async fn v1_oauth_login(
    Path(provider): Path<String>,
    Query(q): Query<LoginParams>,
    State(this): State<RouterState>,
) -> Result<Redirect, ApiError> {
    let (cfg, provider_cfg) = resolve_provider(&this, &provider)?;

    // Validate an optional per-request post-login redirect against the allowlist.
    // Rejecting unlisted targets prevents an open-redirect / token-theft hole
    // (e.g. `?redirect=evil.com` would otherwise leak the JWT).
    let redirect = match q.redirect.as_deref() {
        Some(r) => {
            if is_allowed_redirect(&cfg, r) {
                Some(r)
            } else {
                return Err(ApiError::from(anyhow::anyhow!("Redirect not allowed")));
            }
        }
        None => None,
    };

    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let state = issue_state_token(&provider, &nonce, redirect, DEFAULT_STATE_TTL_SECS)
        .map_err(|e| ApiError::internal(format!("Failed to create state: {}", e)))?;

    let redirect_uri = callback_uri(&this.settings.public_url, &provider);
    let scopes = provider_cfg.scopes().join(" ");
    let mut auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        provider_cfg.auth_url(),
        urlencoding::encode(provider_cfg.client_id()),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&state),
    );
    if let Some(mode) = provider_cfg.response_mode() {
        auth_url.push_str(&format!("&response_mode={}", mode));
    }
    Ok(Redirect::to(&auth_url))
}

/// Standard GET redirect callback.
async fn v1_oauth_callback_get(
    Path(provider): Path<String>,
    Query(q): Query<CallbackParams>,
    State(this): State<RouterState>,
) -> Result<axum::response::Response, ApiError> {
    handle_callback(&this, &provider, q).await
}

/// `form_post` callback (Apple) — the parameters arrive as a POST form body.
async fn v1_oauth_callback_post(
    Path(provider): Path<String>,
    State(this): State<RouterState>,
    Form(q): Form<CallbackParams>,
) -> Result<axum::response::Response, ApiError> {
    handle_callback(&this, &provider, q).await
}

/// Shared callback logic: verify state, exchange the code, resolve the user and
/// issue a session token.
async fn handle_callback(
    this: &RouterState,
    provider: &str,
    q: CallbackParams,
) -> Result<axum::response::Response, ApiError> {
    if let Some(err) = q.error {
        return Err(ApiError::from(anyhow::anyhow!(
            "OAuth provider returned error: {}",
            err
        )));
    }
    let code = q
        .code
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("Missing authorization code")))?;
    let state = q
        .state
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("Missing state")))?;

    // Verify CSRF state and that it was issued for this provider.
    let (state_provider, state_redirect) = verify_state_token(&state)
        .map_err(|e| ApiError::from(anyhow::anyhow!("Invalid state: {}", e)))?;
    if state_provider != provider {
        return Err(ApiError::from(anyhow::anyhow!("State provider mismatch")));
    }

    let (cfg, provider_cfg) = resolve_provider(this, provider)?;
    let redirect_uri = callback_uri(&this.settings.public_url, provider);
    let profile = exchange_and_identify(&provider_cfg, &code, &redirect_uri)
        .await
        .map_err(|e| ApiError::internal(format!("OAuth exchange failed: {}", e)))?;

    // Resolve/create the user by their synthetic identity.
    let pubkey = oauth_pubkey(provider, &profile.subject);
    let uid = this.db.upsert_oauth_user(&pubkey).await?;

    // Best-effort: back-fill the account's email from the provider on first
    // login. A sync failure (e.g. the email is already taken by another
    // account) must not block login, so errors are logged and swallowed.
    if let Err(e) = sync_user_email(&this.db, uid, &profile).await {
        warn!("Failed to sync OAuth email for user {}: {}", uid, e);
    }

    let token = issue_session_token(&pubkey, uid, session_ttl(this))
        .map_err(|e| ApiError::internal(format!("Failed to issue session: {}", e)))?;

    // Redirect to the frontend with the token in the fragment, or return JSON.
    // Prefer the per-request redirect carried (and pre-validated) in the signed
    // state, falling back to the configured default success redirect.
    let target_redirect = state_redirect
        .as_deref()
        .or_else(|| cfg_success_redirect(&cfg));
    if let Some(redirect) = target_redirect {
        let sep = if redirect.contains('#') { '&' } else { '#' };
        let url = format!("{}{}token={}", redirect, sep, urlencoding::encode(&token));
        Ok(Redirect::to(&url).into_response())
    } else {
        let resp = ApiData::ok(OAuthTokenResponse {
            token,
            token_type: "Bearer".to_string(),
            expires_in: session_ttl(this),
        })?;
        Ok(resp.into_response())
    }
}

/// Look up the OAuth config and the specific provider, cloning the provider so
/// the borrow on settings is not held across awaits.
fn resolve_provider(
    this: &RouterState,
    provider: &str,
) -> Result<(crate::settings::OAuthConfig, OAuthProviderConfig), ApiError> {
    let cfg = this
        .settings
        .oauth
        .clone()
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("OAuth not configured")))?;
    let provider_cfg = cfg
        .providers
        .get(provider)
        .cloned()
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("Unknown OAuth provider")))?;
    Ok((cfg, provider_cfg))
}

/// Session token lifetime from the shared `[session]` config (default 30 days).
fn session_ttl(this: &RouterState) -> u64 {
    this.settings
        .session
        .as_ref()
        .map(|s| s.ttl)
        .unwrap_or(lnvps_api_common::DEFAULT_SESSION_TTL_SECS)
}

fn cfg_success_redirect(cfg: &crate::settings::OAuthConfig) -> Option<&str> {
    cfg.success_redirect.as_deref()
}

/// Extract the host (without port or userinfo) from an absolute URL, if present.
///
/// Lightweight, dependency-free: `scheme://[user@]host[:port][/path...]`.
fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    // Authority ends at the first path/query/fragment delimiter.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop any userinfo (`user:pass@`).
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // Drop the port. (localhost is never a bracketed IPv6 literal.)
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() { None } else { Some(host) }
}

/// Whether `requested` is a permitted post-login redirect target.
///
/// Any `localhost` URL is always permitted (for local frontend development).
/// Otherwise accepted when it exactly equals, or extends at a path boundary,
/// either the configured `success_redirect` (always implicitly allowed) or any
/// entry in `allowed_redirects`. The boundary check (next char must be `/`, `?`,
/// `#`, or end-of-string) stops `http://localhost:3000` from also matching
/// `http://localhost:30000.evil` — which would be an open-redirect / token-theft
/// hole.
fn is_allowed_redirect(cfg: &crate::settings::OAuthConfig, requested: &str) -> bool {
    // Always allow the localhost hostname for local dev.
    if url_host(requested).is_some_and(|h| h.eq_ignore_ascii_case("localhost")) {
        return true;
    }

    let allowed = |prefix: &str| -> bool {
        if !requested.starts_with(prefix) {
            return false;
        }
        match requested[prefix.len()..].chars().next() {
            None => true,
            Some('/') | Some('?') | Some('#') => true,
            _ => false,
        }
    };

    cfg.success_redirect.as_deref().is_some_and(&allowed)
        || cfg.allowed_redirects.iter().any(|p| allowed(p))
}

/// Identifying details resolved from a provider after the token exchange.
struct OAuthProfile {
    /// Stable provider subject id.
    subject: String,
    /// Email address, if the provider returned one.
    email: Option<String>,
    /// Whether the provider asserts the email is verified.
    email_verified: bool,
}

/// Populate the account's email from the provider on first login only (when the
/// account has no email yet). Non-destructive: a user who later edits their
/// email is not overwritten on subsequent logins. OAuth users have no NIP-17
/// channel, so email contact is enabled by default when set.
async fn sync_user_email(
    db: &std::sync::Arc<dyn LNVpsDb>,
    uid: u64,
    profile: &OAuthProfile,
) -> anyhow::Result<()> {
    let Some(email) = profile.email.as_deref() else {
        return Ok(());
    };
    let mut user = db.get_user(uid).await?;
    if !user.email.is_empty() {
        return Ok(()); // already set — don't clobber user changes
    }
    user.email = EncryptedString::new(email.to_string());
    user.email_verified = profile.email_verified;
    user.contact_email = true;
    db.update_user(&user).await?;
    Ok(())
}

/// Exchange an authorization code for a token and resolve the user's profile.
async fn exchange_and_identify(
    cfg: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
) -> anyhow::Result<OAuthProfile> {
    let client = reqwest::Client::new();
    let client_secret = client_secret(cfg)?;

    // 1. Authorization-code -> token (application/x-www-form-urlencoded body).
    let body = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", cfg.client_id()),
        ("client_secret", client_secret.as_str()),
    ]
    .iter()
    .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
    .collect::<Vec<_>>()
    .join("&");

    let mut token_req = client
        .post(cfg.token_url())
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");
    if cfg.needs_user_agent() {
        token_req = token_req.header("User-Agent", "lnvps");
    }
    let token_resp = token_req.body(body).send().await?.error_for_status()?;

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        id_token: Option<String>,
    }
    let token: TokenResponse = token_resp.json().await?;

    // 2. Resolve the profile (subject id + email).
    match cfg.subject_source() {
        SubjectSource::IdToken => {
            // Apple: subject and email live in the id_token claims.
            let id_token = token
                .id_token
                .ok_or_else(|| anyhow::anyhow!("token response missing id_token"))?;
            let claims = decode_id_token(&id_token)?;
            if claims.sub.is_empty() {
                anyhow::bail!("id_token missing sub");
            }
            Ok(OAuthProfile {
                subject: claims.sub,
                email: claims.email.filter(|s| !s.is_empty()),
                email_verified: claims.email_verified.map(parse_bool_ish).unwrap_or(false),
            })
        }
        SubjectSource::Userinfo { url, field } => {
            let access_token = token
                .access_token
                .ok_or_else(|| anyhow::anyhow!("token response missing access_token"))?;
            let userinfo = fetch_json(&client, &url, &access_token, cfg.needs_user_agent()).await?;
            let subject = userinfo
                .get(&field)
                .map(value_to_string)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("userinfo missing subject field '{}'", field))?;

            let (email, email_verified) =
                resolve_email(&client, cfg, &userinfo, &access_token).await;

            Ok(OAuthProfile {
                subject,
                email,
                email_verified,
            })
        }
    }
}

/// GET a JSON document with the provider access token (and optional User-Agent).
async fn fetch_json(
    client: &reqwest::Client,
    url: &str,
    access_token: &str,
    user_agent: bool,
) -> anyhow::Result<serde_json::Value> {
    let mut req = client
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json");
    if user_agent {
        req = req.header("User-Agent", "lnvps");
    }
    Ok(req.send().await?.error_for_status()?.json().await?)
}

/// Resolve an `(email, verified)` pair for a userinfo-based provider.
///
/// - Google / generic OIDC: `email` + `email_verified` from userinfo.
/// - Facebook: `email` from the Graph response (Facebook only exposes verified
///   emails, so it is treated as verified).
/// - GitHub: `/user` often omits a private email, so the primary verified
///   address is fetched from `/user/emails`.
async fn resolve_email(
    client: &reqwest::Client,
    cfg: &OAuthProviderConfig,
    userinfo: &serde_json::Value,
    access_token: &str,
) -> (Option<String>, bool) {
    let direct_email = userinfo
        .get("email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    match cfg {
        OAuthProviderConfig::Github(_) => {
            // Prefer the authoritative primary verified address from /user/emails.
            match github_primary_email(client, access_token).await {
                Some((email, verified)) => (Some(email), verified),
                None => (direct_email, false),
            }
        }
        OAuthProviderConfig::Facebook(_) => {
            let verified = direct_email.is_some();
            (direct_email, verified)
        }
        _ => {
            let verified = userinfo
                .get("email_verified")
                .map(|v| parse_bool_ish(v.clone()))
                .unwrap_or(false);
            (direct_email, verified)
        }
    }
}

/// Fetch the GitHub user's primary verified email from `/user/emails`.
async fn github_primary_email(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<(String, bool)> {
    let emails: Vec<GithubEmail> = client
        .get("https://api.github.com/user/emails")
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "lnvps")
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .ok()?
        .json()
        .await
        .ok()?;
    emails
        .iter()
        .find(|e| e.primary && e.verified)
        .or_else(|| emails.iter().find(|e| e.verified))
        .map(|e| (e.email.clone(), e.verified))
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// Parse a boolean that some providers send as a JSON string (`"true"`) rather
/// than a JSON bool (Apple sends `email_verified` as a string).
fn parse_bool_ish(v: serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => b,
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Resolve the `client_secret` to send in the token request. For most providers
/// this is the static configured secret; for Apple it is a freshly-signed ES256
/// JWT.
fn client_secret(cfg: &OAuthProviderConfig) -> anyhow::Result<String> {
    match cfg {
        OAuthProviderConfig::Apple(a) => {
            apple_client_secret(&a.team_id, &a.client_id, &a.key_id, &a.private_key)
        }
        OAuthProviderConfig::Google(c)
        | OAuthProviderConfig::Github(c)
        | OAuthProviderConfig::Facebook(c)
        | OAuthProviderConfig::Oidc(c) => Ok(c.client_secret.clone()),
    }
}

/// Claims we read from an OIDC `id_token`.
#[derive(Deserialize)]
struct IdTokenClaims {
    #[serde(default)]
    sub: String,
    email: Option<String>,
    email_verified: Option<serde_json::Value>,
}

/// Decode (without re-verifying) the claims from an OIDC `id_token`.
///
/// The token is trusted because it was just received over TLS directly from the
/// provider's token endpoint (back-channel), so its signature is not re-verified
/// here.
fn decode_id_token(id_token: &str) -> anyhow::Result<IdTokenClaims> {
    let payload_b64 = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Malformed id_token"))?;
    let payload = BASE64_URL_SAFE_NO_PAD.decode(payload_b64.as_bytes())?;
    Ok(serde_json::from_slice(&payload)?)
}

/// Generate a Sign in with Apple `client_secret`: an ES256 JWT signed with the
/// `.p8` private key.
fn apple_client_secret(
    team_id: &str,
    client_id: &str,
    key_id: &str,
    private_key_pem: &str,
) -> anyhow::Result<String> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::pkcs8::DecodePrivateKey;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let header = serde_json::json!({ "alg": "ES256", "kid": key_id, "typ": "JWT" });
    let claims = serde_json::json!({
        "iss": team_id,
        "iat": now,
        "exp": now + 3600,
        "aud": "https://appleid.apple.com",
        "sub": client_id,
    });

    let signing_input = format!(
        "{}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?),
    );

    let key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| anyhow::anyhow!("Invalid Apple private key: {}", e))?;
    // ES256 = ECDSA/P-256/SHA-256; `to_bytes()` yields fixed-size r||s (64 bytes).
    let sig: Signature = key.sign(signing_input.as_bytes());
    let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Stringify a JSON scalar (numeric provider ids arrive as JSON numbers).
fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_localhost_always_allowed() {
        // No configured redirects at all.
        let cfg = crate::settings::OAuthConfig {
            success_redirect: None,
            allowed_redirects: vec![],
            providers: std::collections::HashMap::new(),
        };
        assert!(is_allowed_redirect(
            &cfg,
            "http://localhost:3000/oauth/complete"
        ));
        assert!(is_allowed_redirect(&cfg, "http://localhost"));
        assert!(is_allowed_redirect(&cfg, "https://localhost:8080/x"));
        assert!(is_allowed_redirect(&cfg, "http://user@localhost:3000/x"));
        // A non-localhost host that merely contains "localhost" is not localhost.
        assert!(!is_allowed_redirect(&cfg, "http://localhost.evil.com/x"));
        assert!(!is_allowed_redirect(&cfg, "http://notlocalhost/x"));
    }

    #[test]
    fn redirect_allowlist_matches_at_boundaries_only() {
        let cfg = crate::settings::OAuthConfig {
            success_redirect: Some("https://app.lnvps.com/oauth".to_string()),
            allowed_redirects: vec!["https://staging.lnvps.com".to_string()],
            providers: std::collections::HashMap::new(),
        };

        // Exact match against an allowlist entry.
        assert!(is_allowed_redirect(&cfg, "https://staging.lnvps.com"));
        // Path-boundary extensions are allowed.
        assert!(is_allowed_redirect(
            &cfg,
            "https://staging.lnvps.com/oauth/complete"
        ));
        assert!(is_allowed_redirect(&cfg, "https://staging.lnvps.com?x=1"));
        assert!(is_allowed_redirect(&cfg, "https://staging.lnvps.com#frag"));
        // success_redirect is always implicitly allowed.
        assert!(is_allowed_redirect(
            &cfg,
            "https://app.lnvps.com/oauth/complete"
        ));

        // Non-boundary extension must be rejected (open-redirect guard).
        assert!(!is_allowed_redirect(
            &cfg,
            "https://staging.lnvps.com.evil.com"
        ));
        assert!(!is_allowed_redirect(&cfg, "https://staging.lnvps.evil"));
        // Unrelated origin rejected.
        assert!(!is_allowed_redirect(&cfg, "https://evil.com"));
        // Prefix that isn't a real prefix rejected.
        assert!(!is_allowed_redirect(&cfg, "https://staging.lnvps.co"));
    }

    /// The Apple client-secret is a well-formed ES256 JWT with the expected
    /// header/claims, signed by the provided P-256 key.
    #[test]
    fn apple_client_secret_is_valid_es256_jwt() {
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};
        use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};

        // Fixed, valid P-256 scalar so the test needs no RNG (avoids rand_core
        // version coupling).
        let key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();

        let jwt = apple_client_secret("TEAMID1234", "com.example.svc", "KEYID5678", pem.as_str())
            .unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Header carries alg/kid.
        let header: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID5678");

        // Claims carry iss/sub/aud.
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAMID1234");
        assert_eq!(claims["sub"], "com.example.svc");
        assert_eq!(claims["aud"], "https://appleid.apple.com");

        // Signature verifies against the public key over "<header>.<payload>".
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        let vk = VerifyingKey::from(SigningKey::from_pkcs8_pem(pem.as_str()).unwrap());
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    /// Subject and email are read from an `id_token` payload, including Apple's
    /// string-encoded `email_verified`.
    #[test]
    fn id_token_claims_extraction() {
        let payload = BASE64_URL_SAFE_NO_PAD
            .encode(br#"{"sub":"001234.abcd","email":"a@b.c","email_verified":"true"}"#);
        let token = format!("header.{}.sig", payload);
        let claims = decode_id_token(&token).unwrap();
        assert_eq!(claims.sub, "001234.abcd");
        assert_eq!(claims.email.as_deref(), Some("a@b.c"));
        assert!(parse_bool_ish(claims.email_verified.unwrap()));
    }

    /// `email_verified` is accepted as JSON bool or string; anything else false.
    #[test]
    fn parse_bool_ish_variants() {
        assert!(parse_bool_ish(serde_json::json!(true)));
        assert!(parse_bool_ish(serde_json::json!("true")));
        assert!(parse_bool_ish(serde_json::json!("TRUE")));
        assert!(!parse_bool_ish(serde_json::json!(false)));
        assert!(!parse_bool_ish(serde_json::json!("false")));
        assert!(!parse_bool_ish(serde_json::json!(1)));
    }

    /// Numeric subject ids (GitHub/Facebook) stringify correctly.
    #[test]
    fn numeric_subject_stringifies() {
        assert_eq!(value_to_string(&serde_json::json!(12345)), "12345");
        assert_eq!(value_to_string(&serde_json::json!("abc")), "abc");
        assert_eq!(value_to_string(&serde_json::json!(null)), "");
    }

    /// Email is populated from the provider on first login, marks the account
    /// verified + email-contactable, and is not clobbered on later logins.
    #[tokio::test]
    async fn sync_user_email_first_login_only() {
        use lnvps_api_common::MockDb;
        use lnvps_db::oauth_pubkey;
        use std::sync::Arc;

        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let uid = db
            .upsert_oauth_user(&oauth_pubkey("google", "sub-1"))
            .await
            .unwrap();

        sync_user_email(
            &db,
            uid,
            &OAuthProfile {
                subject: "sub-1".to_string(),
                email: Some("user@example.com".to_string()),
                email_verified: true,
            },
        )
        .await
        .unwrap();

        let user = db.get_user(uid).await.unwrap();
        assert_eq!(user.email.as_str(), "user@example.com");
        assert!(user.email_verified);
        assert!(user.contact_email);

        // A later login with a different email must not overwrite it.
        sync_user_email(
            &db,
            uid,
            &OAuthProfile {
                subject: "sub-1".to_string(),
                email: Some("changed@example.com".to_string()),
                email_verified: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.get_user(uid).await.unwrap().email.as_str(),
            "user@example.com"
        );
    }
}
