use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use lnurl::lightning_address::LightningAddress;
use lnurl::pay::PayResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use lnvps_api_common::{ApiData, ApiError, ApiResult, Nip98Auth};
use lnvps_db::{Referral, ReferralCostUsage, ReferralPayout, ReferralPayoutMode};

use crate::api::RouterState;

pub fn router() -> Router<RouterState> {
    Router::new().route(
        "/api/v1/referral",
        get(v1_get_referral)
            .post(v1_signup_referral)
            .patch(v1_update_referral),
    )
}

/// Response type for a referral entry
#[derive(Serialize)]
pub struct ApiReferral {
    /// The referral code to share with others
    pub code: String,
    /// Lightning address for automatic payouts (used when `mode` is
    /// `lightning_address`)
    pub lightning_address: Option<String>,
    /// Payout method: `lightning_address`, `nwc`, or `account_credit`.
    pub mode: String,
    /// Per-referrer commission override, as a whole percentage of a referred
    /// VM's first payment. `null` means the referred VM's company default rate
    /// (`company.referral_rate`) applies instead.
    pub referral_rate: Option<f32>,
    /// When the referral was created
    pub created: chrono::DateTime<Utc>,
}

impl From<Referral> for ApiReferral {
    fn from(r: Referral) -> Self {
        Self {
            code: r.code,
            lightning_address: r.lightning_address,
            mode: r.mode.to_string(),
            referral_rate: r.referral_rate,
            created: r.created,
        }
    }
}

/// Per-currency earned amount from referrals
#[derive(Serialize)]
pub struct ApiReferralEarning {
    /// Currency code
    pub currency: String,
    /// Total commission earned in this currency: the sum, over each referred VM's
    /// first payment, of `payment * effective_rate%` (the referrer override or
    /// the referred VM's company default).
    pub amount: u64,
}

/// A single payout record
#[derive(Serialize)]
pub struct ApiReferralPayout {
    pub id: u64,
    pub amount: u64,
    pub currency: String,
    pub created: chrono::DateTime<Utc>,
    pub is_paid: bool,
    pub invoice: Option<String>,
}

impl From<ReferralPayout> for ApiReferralPayout {
    fn from(p: ReferralPayout) -> Self {
        Self {
            id: p.id,
            amount: p.amount,
            currency: p.currency,
            created: p.created,
            is_paid: p.is_paid,
            invoice: p.invoice,
        }
    }
}

/// Full referral state returned by GET /api/v1/referral
#[derive(Serialize)]
pub struct ApiReferralState {
    #[serde(flatten)]
    pub referral: ApiReferral,
    /// Per-currency breakdown of amounts earned from referrals
    pub earned: Vec<ApiReferralEarning>,
    /// Complete payout history (most recent first)
    pub payouts: Vec<ApiReferralPayout>,
    /// Number of referred VMs that made at least one payment
    pub referrals_success: u64,
    /// Number of referred VMs that never made a payment
    pub referrals_failed: u64,
}

impl ApiReferralState {
    fn build(
        referral: Referral,
        usage: Vec<ReferralCostUsage>,
        payouts: Vec<ReferralPayout>,
        referrals_failed: u64,
    ) -> Self {
        // Aggregate earned commission per currency (payment * effective_rate%).
        let mut by_currency: HashMap<String, u64> = HashMap::new();
        for u in &usage {
            *by_currency.entry(u.currency.clone()).or_insert(0) += u.commission();
        }
        let mut earned: Vec<ApiReferralEarning> = by_currency
            .into_iter()
            .map(|(currency, amount)| ApiReferralEarning { currency, amount })
            .collect();
        earned.sort_by(|a, b| a.currency.cmp(&b.currency));

        Self {
            referrals_success: usage.len() as u64,
            referrals_failed,
            referral: referral.into(),
            earned,
            payouts: payouts.into_iter().map(Into::into).collect(),
        }
    }
}

/// Request to sign up for the referral program
#[derive(Deserialize)]
pub struct ApiReferralSignupRequest {
    /// Lightning address for payouts (required when `mode` is `lightning_address`)
    pub lightning_address: Option<String>,
    /// Payout method: `lightning_address` (default) or `nwc`.
    pub mode: Option<String>,
}

/// Request to update referral payout options
#[derive(Deserialize)]
pub struct ApiReferralPatchRequest {
    /// Lightning address for payouts (None = clear, Some(s) = set)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub lightning_address: Option<Option<String>>,
    /// Payout method: `lightning_address`, `nwc`, or `account_credit`.
    pub mode: Option<String>,
}

/// Resolve and validate a requested payout `mode`, defaulting when omitted.
///
/// `account_credit` is a defined-but-unimplemented mode and is rejected until
/// the account-balance system exists.
fn parse_payout_mode(mode: Option<&str>) -> Result<Option<ReferralPayoutMode>, ApiError> {
    let Some(s) = mode else {
        return Ok(None);
    };
    let parsed = ReferralPayoutMode::from_str(s)
        .map_err(|_| ApiError::new("Invalid payout mode. Use 'lightning_address' or 'nwc'"))?;
    if parsed == ReferralPayoutMode::AccountCredit {
        return Err(ApiError::new(
            "Account credit payouts are not yet available",
        ));
    }
    Ok(Some(parsed))
}

/// Validate a lightning address by parsing its format and resolving the LNURL pay endpoint
async fn validate_lightning_address(addr: &str) -> Result<(), ApiError> {
    let ln_addr = LightningAddress::from_str(addr)
        .map_err(|_| ApiError::new("Invalid lightning address format"))?;

    let url = ln_addr.lnurlp_url();
    let rsp = reqwest::get(&url)
        .await
        .map_err(|_| ApiError::new("Failed to resolve lightning address"))?;

    if !rsp.status().is_success() {
        return Err(ApiError::new("Lightning address not found"));
    }

    rsp.json::<PayResponse>()
        .await
        .map(|_| ())
        .map_err(|_| ApiError::new("Lightning address returned invalid LNURL pay response"))
}

/// Generate a random 8-character base63 referral code (A-Za-z0-9_)
/// Whether the user has an enabled NWC payment method configured.
async fn user_has_nwc(this: &RouterState, uid: u64) -> bool {
    this.db
        .list_user_payment_methods(uid, Some("nwc"))
        .await
        .map(|m| m.iter().any(|pm| pm.enabled))
        .unwrap_or(false)
}

fn generate_referral_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
    let bytes: [u8; 8] = rand::random();
    bytes
        .iter()
        .map(|&b| ALPHABET[(b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Get current referral state (code, per-currency earnings, payout history, counts)
async fn v1_get_referral(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<ApiReferralState> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let referral = this
        .db
        .get_referral_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Not enrolled in referral program"))?;

    let (usage, payouts, referrals_failed) = tokio::try_join!(
        this.db.list_referral_usage(&referral.code),
        this.db.list_referral_payouts(referral.id),
        this.db.count_failed_referrals(&referral.code),
    )?;

    ApiData::ok(ApiReferralState::build(
        referral,
        usage,
        payouts,
        referrals_failed,
    ))
}

/// Sign up for the referral program
async fn v1_signup_referral(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<ApiReferralSignupRequest>,
) -> ApiResult<ApiReferral> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Check if already enrolled
    if this.db.get_referral_by_user(uid).await.is_ok() {
        return Err(ApiError::conflict("Already enrolled in referral program"));
    }

    // Resolve the payout mode, defaulting to lightning_address when omitted.
    let mode =
        parse_payout_mode(req.mode.as_deref())?.unwrap_or(ReferralPayoutMode::LightningAddress);

    // Validate the payout details required by the chosen mode.
    match mode {
        ReferralPayoutMode::LightningAddress => match req.lightning_address.as_deref() {
            Some(addr) if !addr.trim().is_empty() => validate_lightning_address(addr).await?,
            _ => {
                return ApiData::err(
                    "lightning_address is required when mode is 'lightning_address'",
                );
            }
        },
        ReferralPayoutMode::Nwc => {
            if !user_has_nwc(&this, uid).await {
                return ApiData::err("NWC connection is not configured on your account");
            }
        }
        ReferralPayoutMode::AccountCredit => unreachable!("rejected by parse_payout_mode"),
    }

    let code = generate_referral_code();
    let referral = Referral {
        id: 0,
        user_id: uid,
        code,
        lightning_address: req.lightning_address,
        mode,
        // Per-referrer commission override is admin-controlled; new enrollments
        // default to the referred VM's company rate (None = use company default).
        referral_rate: None,
        created: Utc::now(),
    };

    let id = this.db.insert_referral(&referral).await?;
    let created = Referral { id, ..referral };

    ApiData::ok(created.into())
}

/// Update referral payout options
async fn v1_update_referral(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<ApiReferralPatchRequest>,
) -> ApiResult<ApiReferral> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let mut referral = this
        .db
        .get_referral_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Not enrolled in referral program"))?;

    if let Some(ref addr) = req.lightning_address {
        if let Some(a) = addr {
            validate_lightning_address(a).await?;
        }
        referral.lightning_address = addr.clone();
    }
    if let Some(mode) = parse_payout_mode(req.mode.as_deref())? {
        if mode == ReferralPayoutMode::Nwc && !user_has_nwc(&this, uid).await {
            return ApiData::err("NWC connection is not configured on your account");
        }
        referral.mode = mode;
    }

    // The resulting configuration must have the details its mode needs.
    if referral.mode == ReferralPayoutMode::LightningAddress
        && referral
            .lightning_address
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
    {
        return ApiData::err("lightning_address is required when mode is 'lightning_address'");
    }

    this.db.update_referral(&referral).await?;

    ApiData::ok(referral.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_referral_code_length() {
        let code = generate_referral_code();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn test_parse_payout_mode() {
        // Omitted -> None (caller applies its own default / keeps existing)
        assert!(matches!(parse_payout_mode(None), Ok(None)));
        assert!(matches!(
            parse_payout_mode(Some("lightning_address")),
            Ok(Some(ReferralPayoutMode::LightningAddress))
        ));
        assert!(matches!(
            parse_payout_mode(Some("nwc")),
            Ok(Some(ReferralPayoutMode::Nwc))
        ));
        // account_credit is defined but not yet available -> error
        assert!(matches!(parse_payout_mode(Some("account_credit")), Err(_)));
        // unknown -> error
        assert!(matches!(parse_payout_mode(Some("paypal")), Err(_)));
    }

    #[test]
    fn test_generate_referral_code_alphabet() {
        const VALID: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
        for _ in 0..100 {
            let code = generate_referral_code();
            for c in code.chars() {
                assert!(VALID.contains(c), "Invalid base63 character: {}", c);
            }
        }
    }

    #[test]
    fn test_generate_referral_codes_are_random() {
        // Generate 20 codes and ensure they are not all identical
        let codes: Vec<String> = (0..20).map(|_| generate_referral_code()).collect();
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert!(unique.len() > 1, "All generated codes were identical");
    }

    #[tokio::test]
    async fn test_validate_lightning_address_rejects_invalid_format() {
        let result = validate_lightning_address("notanaddress").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_lightning_address_rejects_empty() {
        let result = validate_lightning_address("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_lightning_address_rejects_no_domain() {
        let result = validate_lightning_address("user@").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_lightning_address_rejects_no_user() {
        let result = validate_lightning_address("@domain.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_lightning_address_rejects_nonexistent_domain() {
        let result = validate_lightning_address("user@thisdomain.doesnotexist.invalid").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "requires live network access to zap.stream"]
    async fn test_validate_lightning_address_accepts_valid() {
        let result = validate_lightning_address("kieran@zap.stream").await;
        assert!(result.is_ok());
    }
}
