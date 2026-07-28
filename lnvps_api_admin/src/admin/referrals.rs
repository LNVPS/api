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
use payments_rs::currency::{Currency, CurrencyAmount};
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
        payout_threshold: r.payout_threshold,
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

    if let Some(threshold) = req.payout_threshold {
        referral.payout_threshold = threshold;
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

    let mut payout = ReferralPayout {
        id: 0,
        referral_id: id,
        amount: req.amount,
        currency: currency.clone(),
        created: chrono::Utc::now(),
        fee: req.fee.unwrap_or(0),
        is_paid: false,
        mode: match req.mode.as_deref() {
            Some(m) => lnvps_db::ReferralPayoutMode::from_str(m)
                .map_err(|_| ApiError::new("Invalid payout mode"))?,
            None => lnvps_db::ReferralPayoutMode::default(),
        },
        output: req
            .output
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        pre_image: None,
        ..Default::default()
    };

    match apply_sent_side(&mut payout, &req) {
        Ok(()) => {}
        Err(e) => return ApiData::err(&e),
    }
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

/// Fill a new payout's sent side from the request, validating the two sides
/// against each other.
///
/// A payout that sent what it settles carries the settled figures verbatim and
/// no rate: a quote that never happened must not be recorded as one. A payout
/// that converted has to say what left the wallet and at what rate, otherwise
/// the record cannot be reconciled against the transfer afterwards.
fn apply_sent_side(
    payout: &mut ReferralPayout,
    req: &AdminCreateReferralPayoutRequest,
) -> Result<(), String> {
    let sent_currency = req
        .sent_currency
        .as_deref()
        .map(|c| c.trim().to_uppercase())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| payout.currency.clone());

    if sent_currency == payout.currency {
        if req.rate.is_some() || req.rate_collected.is_some() {
            return Err("rate is only valid when sent_currency differs from currency".to_string());
        }
        if req.sent_amount.is_some_and(|a| a != payout.amount)
            || req.sent_fee.is_some_and(|f| f != payout.fee)
        {
            return Err(
                "sent_amount and sent_fee must match amount and fee when the currency is the same"
                    .to_string(),
            );
        }
        *payout = std::mem::take(payout).unconverted();
        return Ok(());
    }

    let Some(sent_amount) = req.sent_amount.filter(|a| *a > 0) else {
        return Err("sent_amount is required when sent_currency differs from currency".to_string());
    };
    let Some(rate) = req.rate.filter(|r| *r > 0.0 && r.is_finite()) else {
        return Err(
            "rate is required and must be greater than 0 when sent_currency differs from currency"
                .to_string(),
        );
    };
    check_rate_against_amounts(payout.amount, &payout.currency, sent_amount, &sent_currency, rate)?;

    payout.sent_amount = sent_amount;
    payout.sent_fee = req.sent_fee.unwrap_or(0);
    payout.sent_currency = sent_currency;
    payout.rate = rate;
    payout.rate_collected = Some(req.rate_collected.unwrap_or_else(chrono::Utc::now));
    Ok(())
}

/// Tolerance between the supplied rate and the one the two amounts imply.
///
/// Wide enough for rounding, a stale quote and the spread on the transfer;
/// narrow enough that a wrong order of magnitude cannot pass.
const RATE_TOLERANCE: f32 = 0.10;

/// Reject a rate that the two amounts contradict.
///
/// The rate exists so the conversion is reproducible without a price feed, so a
/// record that disagrees with itself is worse than one carrying no rate at all.
/// Nothing here moves money — the balance nets on the settled amount.
///
/// A currency neither side of the ledger knows how to scale cannot be checked;
/// the record is still worth storing, so it passes.
fn check_rate_against_amounts(
    amount: u64,
    currency: &str,
    sent_amount: u64,
    sent_currency: &str,
    rate: f32,
) -> Result<(), String> {
    let (Ok(settled), Ok(sent)) = (
        Currency::from_str(currency),
        Currency::from_str(sent_currency),
    ) else {
        return Ok(());
    };

    let settled = CurrencyAmount::from_u64(settled, amount).value_f32();
    let sent = CurrencyAmount::from_u64(sent, sent_amount).value_f32();
    if settled <= 0.0 || sent <= 0.0 {
        return Ok(());
    }

    let implied = settled / sent;
    if (implied / rate - 1.0).abs() > RATE_TOLERANCE {
        return Err(format!(
            "rate {rate} disagrees with the amounts, which imply {implied}"
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn req(currency: &str, amount: u64) -> AdminCreateReferralPayoutRequest {
        AdminCreateReferralPayoutRequest {
            amount,
            currency: currency.to_string(),
            sent_currency: None,
            sent_amount: None,
            sent_fee: None,
            fee: None,
            rate: None,
            rate_collected: None,
            output: None,
            mode: None,
            is_paid: false,
        }
    }

    fn payout(currency: &str, amount: u64, fee: u64) -> ReferralPayout {
        ReferralPayout {
            referral_id: 1,
            amount,
            fee,
            currency: currency.to_string(),
            ..Default::default()
        }
    }

    /// A payout that sent what it settles mirrors the settled side and records
    /// no rate — a rate of 1 with a timestamp would claim a quote happened.
    #[test]
    fn same_currency_mirrors_the_settled_side() {
        let mut p = payout("BTC", 21_000, 7);
        apply_sent_side(&mut p, &req("BTC", 21_000)).unwrap();
        assert_eq!(p.sent_amount, 21_000);
        assert_eq!(p.sent_fee, 7);
        assert_eq!(p.sent_currency, "BTC");
        assert_eq!(p.rate, 1.0);
        assert!(p.rate_collected.is_none());
    }

    /// The sent side is what makes a cross-currency payout reconcilable against
    /// the transfer, so it cannot be left to a default.
    #[test]
    fn cross_currency_requires_the_sent_amount_and_a_usable_rate() {
        let mut r = req("EUR", 5_000);
        r.sent_currency = Some("BTC".to_string());
        r.rate = Some(90_000.0);
        let err = apply_sent_side(&mut payout("EUR", 5_000, 0), &r).unwrap_err();
        assert!(err.contains("sent_amount is required"), "{err}");

        r.sent_amount = Some(55_000_000);
        for bad in [None, Some(0.0), Some(-1.0), Some(f32::NAN)] {
            r.rate = bad;
            let err = apply_sent_side(&mut payout("EUR", 5_000, 0), &r).unwrap_err();
            assert!(err.contains("rate is required"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn cross_currency_records_both_sides_and_the_quote_time() {
        let mut r = req("EUR", 5_000);
        r.sent_currency = Some("btc".to_string());
        r.sent_amount = Some(55_000_000);
        r.sent_fee = Some(1_200);
        r.rate = Some(90_000.0);

        let mut p = payout("EUR", 5_000, 3);
        apply_sent_side(&mut p, &r).unwrap();
        assert_eq!(p.amount, 5_000);
        assert_eq!(p.fee, 3);
        assert_eq!(p.currency, "EUR");
        assert_eq!(p.sent_amount, 55_000_000);
        assert_eq!(p.sent_fee, 1_200);
        assert_eq!(p.sent_currency, "BTC");
        assert_eq!(p.rate, 90_000.0);
        assert!(p.rate_collected.is_some());
    }

    /// A caller-supplied quote time survives, so an out-of-band payment can be
    /// reconciled with the rate that actually applied when it was sent.
    #[test]
    fn cross_currency_keeps_a_supplied_quote_time() {
        let when = chrono::Utc::now() - chrono::Duration::days(2);
        let mut r = req("EUR", 5_000);
        r.sent_currency = Some("BTC".to_string());
        r.sent_amount = Some(55_000_000);
        r.rate = Some(90_000.0);
        r.rate_collected = Some(when);

        let mut p = payout("EUR", 5_000, 0);
        apply_sent_side(&mut p, &r).unwrap();
        assert_eq!(p.rate_collected, Some(when));
    }

    /// The rate is what makes the conversion reproducible, so a rate the two
    /// amounts contradict is rejected rather than stored.
    #[test]
    fn cross_currency_rejects_a_rate_the_amounts_contradict() {
        let mut r = req("EUR", 5_000);
        r.sent_currency = Some("BTC".to_string());
        r.sent_amount = Some(55_000_000);

        // 50.00 EUR for 0.00055 BTC implies ~90909 EUR/BTC.
        r.rate = Some(9_000.0);
        let err = apply_sent_side(&mut payout("EUR", 5_000, 0), &r).unwrap_err();
        assert!(err.contains("disagrees with the amounts"), "{err}");

        // Rounding and a stale quote stay inside the tolerance.
        r.rate = Some(90_000.0);
        apply_sent_side(&mut payout("EUR", 5_000, 0), &r).unwrap();
        r.rate = Some(85_000.0);
        apply_sent_side(&mut payout("EUR", 5_000, 0), &r).unwrap();
    }

    /// A currency the ledger cannot scale cannot be cross-checked, and the
    /// record is still worth storing.
    #[test]
    fn an_unknown_currency_skips_the_rate_check() {
        assert!(check_rate_against_amounts(5_000, "XAU", 55_000_000, "BTC", 1.0).is_ok());
        assert!(check_rate_against_amounts(5_000, "EUR", 55_000_000, "XAU", 1.0).is_ok());
        // A zero side gives no ratio to compare against.
        assert!(check_rate_against_amounts(0, "EUR", 55_000_000, "BTC", 90_000.0).is_ok());
    }

    /// Same-currency rows must stay identities: a rate or a mismatched sent
    /// figure there is a caller error, not something to silently normalise.
    #[test]
    fn same_currency_rejects_a_rate_or_a_diverging_sent_side() {
        let mut r = req("BTC", 21_000);
        r.rate = Some(1.0);
        let err = apply_sent_side(&mut payout("BTC", 21_000, 0), &r).unwrap_err();
        assert!(err.contains("rate is only valid"), "{err}");

        let mut r = req("BTC", 21_000);
        r.sent_currency = Some("btc".to_string());
        r.sent_amount = Some(20_000);
        let err = apply_sent_side(&mut payout("BTC", 21_000, 0), &r).unwrap_err();
        assert!(err.contains("must match amount and fee"), "{err}");

        let mut r = req("BTC", 21_000);
        r.sent_fee = Some(9);
        let err = apply_sent_side(&mut payout("BTC", 21_000, 7), &r).unwrap_err();
        assert!(err.contains("must match amount and fee"), "{err}");
    }
}
