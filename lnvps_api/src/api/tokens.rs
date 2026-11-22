use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Duration, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiResult, ClientInfo, DEFAULT_API_TOKEN_TTL_DAYS, MAX_API_TOKEN_TTL_DAYS,
    Nip98Auth, TokenScope, audit_user_action, new_api_token,
};
use serde::{Deserialize, Serialize};

use crate::api::RouterState;

const MAX_TOKENS_PER_ACCOUNT: usize = 20;

#[derive(Deserialize)]
pub struct CreateApiToken {
    pub name: String,
    pub scope: String,
    pub expires_in_days: Option<u64>,
}

#[derive(Serialize)]
pub struct ApiTokenInfo {
    pub id: u64,
    pub name: String,
    pub scope: String,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub last_ip: Option<String>,
}

impl From<lnvps_db::ApiToken> for ApiTokenInfo {
    fn from(t: lnvps_db::ApiToken) -> Self {
        Self {
            id: t.id,
            name: t.name,
            scope: t.scope,
            created: t.created,
            expires: t.expires,
            last_used: t.last_used,
            last_ip: t.last_ip,
        }
    }
}

#[derive(Serialize)]
pub struct CreatedApiToken {
    pub token: String,
    #[serde(flatten)]
    pub info: ApiTokenInfo,
}

pub async fn v1_create_api_token(
    auth: Nip98Auth,
    client: ClientInfo,
    State(this): State<RouterState>,
    Json(req): Json<CreateApiToken>,
) -> ApiResult<CreatedApiToken> {
    let scope = TokenScope::parse(&req.scope)
        .ok_or_else(|| ApiError::bad_request("scope must be 'read' or 'vm'"))?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("name must be 1 to 100 characters"));
    }
    let days = req.expires_in_days.unwrap_or(DEFAULT_API_TOKEN_TTL_DAYS);
    if days == 0 || days > MAX_API_TOKEN_TTL_DAYS {
        return Err(ApiError::bad_request(format!(
            "expires_in_days must be between 1 and {MAX_API_TOKEN_TTL_DAYS}"
        )));
    }
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    if this.db.list_api_tokens(uid).await?.len() >= MAX_TOKENS_PER_ACCOUNT {
        return Err(ApiError::bad_request("too many API tokens, delete one first"));
    }
    audit_user_action(
        this.db.as_ref(),
        &client,
        uid,
        auth.auth_method(),
        "auth.token.create",
        ("user", uid),
        Some(format!("{} {} {}d", name, scope.as_str(), days)),
    )
    .await?;
    let raw = new_api_token();
    let mut row = lnvps_db::ApiToken {
        user_id: uid,
        name: name.to_string(),
        token_hash: lnvps_db::hash_verify_token(&raw),
        scope: scope.as_str().to_string(),
        expires: Utc::now() + Duration::days(days as i64),
        ..Default::default()
    };
    row.id = this.db.insert_api_token(&row).await?;
    row.created = Utc::now();
    ApiData::ok(CreatedApiToken {
        token: raw,
        info: row.into(),
    })
}

pub async fn v1_list_api_tokens(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiTokenInfo>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    ApiData::ok(
        this.db
            .list_api_tokens(uid)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    )
}

pub async fn v1_delete_api_token(
    auth: Nip98Auth,
    client: ClientInfo,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    audit_user_action(
        this.db.as_ref(),
        &client,
        uid,
        auth.auth_method(),
        "auth.token.revoke",
        ("api_token", id),
        None,
    )
    .await?;
    this.db.delete_api_token(id, uid).await?;
    ApiData::ok(())
}
