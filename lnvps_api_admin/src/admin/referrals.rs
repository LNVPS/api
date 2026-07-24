use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCreateReferralPayoutRequest, AdminReferralDetail, AdminReferralEarning, AdminReferralInfo,
    AdminReferralPayoutInfo, AdminUpdateReferralPayoutRequest, AdminUpdateReferralRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult,
    deserialize_from_str_optional,
};
use lnvps_db::{AdminAction, AdminResource, Referral, ReferralPayout};
use std::collections::HashMap;
use std::str::FromStr;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/admin/v1/referrals", get(admin_list_referrals))
        .route(
            "/api/admin/v1/referrals/{id}",
            get(admin_get_referral).patch(admin_update_referral),
        )
        .route(
            "/api/admin/v1/referrals/{id}/payouts",
            get(admin_list_referral_payouts).post(admin_create_referral_payout),
        )
        .route(
            "/api/admin/v1/referrals/{id}/payouts/{payout_id}",
            axum::routing::patch(admin_update_referral_payout),
        )
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ListReferralsQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    /// Substring match on referral code, or a 64-char hex user pubkey.
    search: Option<String>,
}

/// Build the admin view of a referral, resolving the owner's pubkey.
async fn build_info(this: &RouterState, r: Referral) -> Result<AdminReferralInfo, ApiError> {
    let user = this.db.get_user(r.user_id).await?;
    Ok(AdminReferralInfo {
        id: r.id,
        user_id: r.user_id,
        user_pubkey: hex::encode(user.pubkey),
        code: r.code,
        address: r.address,
        mode: r.mode.to_string(),
        referral_rate: r.referral_rate,
        created: r.created,
    })
}

/// List referral enrollments (paginated, optional search).
async fn admin_list_referrals(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListReferralsQuery>,
) -> ApiPaginatedResult<AdminReferralInfo> {
    auth.require_permission(AdminResource::Referral, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let search = params.search.as_deref().filter(|s| !s.trim().is_empty());

    let (rows, total) = this.db.admin_list_referrals(limit, offset, search).await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(build_info(&this, r).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

/// Get a referral with its earnings and payout history.
async fn admin_get_referral(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminReferralDetail> {
    auth.require_permission(AdminResource::Referral, AdminAction::View)?;

    let referral = this.db.admin_get_referral(id).await?;
    let code = referral.code.clone();

    let (usage, payouts, referrals_failed) = tokio::try_join!(
        this.db.list_referral_usage(&code),
        this.db.list_referral_payouts(id),
        this.db.count_failed_referrals(&code),
    )?;

    // Aggregate commission earned per currency.
    let mut by_currency: HashMap<String, u64> = HashMap::new();
    for u in &usage {
        *by_currency.entry(u.currency.clone()).or_insert(0) += u.commission();
    }
    let mut earned: Vec<AdminReferralEarning> = by_currency
        .into_iter()
        .map(|(currency, amount)| AdminReferralEarning { currency, amount })
        .collect();
    earned.sort_by(|a, b| a.currency.cmp(&b.currency));

    let referrals_success = usage.len() as u64;
    let info = build_info(&this, referral).await?;

    ApiData::ok(AdminReferralDetail {
        referral: info,
        earned,
        payouts: payouts.into_iter().map(Into::into).collect(),
        referrals_success,
        referrals_failed,
    })
}

/// Set or clear a referral's per-referrer commission override.
async fn admin_update_referral(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateReferralRequest>,
) -> ApiResult<AdminReferralInfo> {
    auth.require_permission(AdminResource::Referral, AdminAction::Update)?;

    let mut referral = this.db.admin_get_referral(id).await?;

    if let Some(code) = &req.code {
        let code = code.trim();
        if code.is_empty() {
            return ApiData::err("code cannot be empty");
        }
        // Reject a code already taken by a different referral enrollment.
        if code != referral.code {
            if let Ok(existing) = this.db.get_referral_by_code(code).await {
                if existing.id != referral.id {
                    return ApiData::err("code is already in use by another referral");
                }
            }
        }
        referral.code = code.to_string();
    }

    if let Some(rate) = req.referral_rate {
        if let Some(r) = rate {
            if r < 0.0 {
                return ApiData::err("referral_rate cannot be negative");
            }
        }
        referral.referral_rate = rate;
    }

    this.db.update_referral(&referral).await?;
    let updated = this.db.admin_get_referral(id).await?;
    ApiData::ok(build_info(&this, updated).await?)
}

/// List a referral's payout records.
async fn admin_list_referral_payouts(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<AdminReferralPayoutInfo>> {
    auth.require_permission(AdminResource::Referral, AdminAction::View)?;

    // Ensure the referral exists for a clean 404.
    let _ = this.db.admin_get_referral(id).await?;
    let payouts = this.db.list_referral_payouts(id).await?;
    ApiData::ok(payouts.into_iter().map(Into::into).collect())
}

/// Create a manual payout record for a referral (e.g. an out-of-band payment).
async fn admin_create_referral_payout(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminCreateReferralPayoutRequest>,
) -> ApiResult<AdminReferralPayoutInfo> {
    auth.require_permission(AdminResource::Referral, AdminAction::Create)?;

    let _ = this.db.admin_get_referral(id).await?;

    if req.amount == 0 {
        return ApiData::err("amount must be greater than 0");
    }
    let currency = req.currency.trim().to_uppercase();
    if currency.is_empty() {
        return ApiData::err("currency is required");
    }

    let payout = ReferralPayout {
        id: 0,
        referral_id: id,
        amount: req.amount,
        currency,
        created: chrono::Utc::now(),
        fee: 0,
        is_paid: false,
        mode: match req.mode.as_deref() {
            Some(m) => lnvps_db::ReferralPayoutMode::from_str(m)
                .map_err(|_| ApiError::new("Invalid payout mode"))?,
            None => lnvps_db::ReferralPayoutMode::default(),
        },
        output: req.output.filter(|s| !s.trim().is_empty()),
        pre_image: None,
    };
    let payout_id = this.db.insert_referral_payout(&payout).await?;

    // Apply the initial paid flag if requested (insert defaults to unpaid).
    if req.is_paid {
        let mut created = ReferralPayout {
            id: payout_id,
            ..payout.clone()
        };
        created.is_paid = true;
        this.db.update_referral_payout(&created).await?;
    }

    let created = this
        .db
        .list_referral_payouts(id)
        .await?
        .into_iter()
        .find(|p| p.id == payout_id)
        .ok_or_else(|| ApiError::new("Failed to load created payout"))?;
    ApiData::ok(created.into())
}

/// Update / reconcile a payout record (mark paid, set invoice / preimage).
async fn admin_update_referral_payout(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, payout_id)): Path<(u64, u64)>,
    Json(req): Json<AdminUpdateReferralPayoutRequest>,
) -> ApiResult<AdminReferralPayoutInfo> {
    auth.require_permission(AdminResource::Referral, AdminAction::Update)?;

    let mut payout = this
        .db
        .list_referral_payouts(id)
        .await?
        .into_iter()
        .find(|p| p.id == payout_id)
        .ok_or_else(|| ApiError::not_found("Payout not found for this referral"))?;

    if let Some(is_paid) = req.is_paid {
        payout.is_paid = is_paid;
    }
    if let Some(output) = req.output {
        payout.output = output.filter(|s| !s.trim().is_empty());
    }
    if let Some(mode) = req.mode.as_deref() {
        payout.mode = lnvps_db::ReferralPayoutMode::from_str(mode)
            .map_err(|_| ApiError::new("Invalid payout mode"))?;
    }
    if let Some(pre_image) = req.pre_image {
        payout.pre_image = match pre_image.filter(|s| !s.trim().is_empty()) {
            Some(hex_str) => Some(
                hex::decode(hex_str.trim())
                    .map_err(|_| ApiError::bad_request("pre_image must be hex-encoded"))?,
            ),
            None => None,
        };
    }

    this.db.update_referral_payout(&payout).await?;

    let updated = this
        .db
        .list_referral_payouts(id)
        .await?
        .into_iter()
        .find(|p| p.id == payout_id)
        .ok_or_else(|| ApiError::new("Failed to load updated payout"))?;
    ApiData::ok(updated.into())
}
