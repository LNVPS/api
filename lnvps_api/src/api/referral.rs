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
use lnvps_db::{Referral, ReferralCostUsage, ReferralPayout};

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
    /// Lightning address for automatic payouts
    pub lightning_address: Option<String>,
    /// Whether to use NWC for payouts
    pub use_nwc: bool,
    /// When the referral was created
    pub created: chrono::DateTime<Utc>,
}

impl From<Referral> for ApiReferral {
    fn from(r: Referral) -> Self {
        Self {
            code: r.code,
            lightning_address: r.lightning_address,
            use_nwc: r.use_nwc,
            created: r.created,
        }
    }
}

/// Per-currency earned amount from referrals
#[derive(Serialize)]
pub struct ApiReferralEarning {
    /// Currency code
    pub currency: String,
    /// Total earned amount in this currency (sum of first payments per referred VM)
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
        // Aggregate earned amounts per currency
        let mut by_currency: HashMap<String, u64> = HashMap::new();
        for u in &usage {
            *by_currency.entry(u.currency.clone()).or_insert(0) += u.amount;
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
    /// Lightning address for payouts (optional)
    pub lightning_address: Option<String>,
    /// Use NWC connection for payouts
    #[serde(default)]
    pub use_nwc: bool,
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
    /// Use NWC connection for payouts
    pub use_nwc: Option<bool>,
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
        .map_err(|_| ApiError::new("Not enrolled in referral program"))?;

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
        return ApiData::err("Already enrolled in referral program");
    }

    // Validate that at least one payout method is specified
    if req.lightning_address.is_none() && !req.use_nwc {
        return ApiData::err(
            "At least one payout method (lightning_address or use_nwc) is required",
        );
    }

    // Validate lightning address
    if let Some(ref addr) = req.lightning_address {
        validate_lightning_address(addr).await?;
    }

    // If use_nwc is requested, ensure user has NWC configured
    if req.use_nwc {
        let user = this.db.get_user(uid).await?;
        if user.nwc_connection_string.is_none() {
            return ApiData::err("NWC connection is not configured on your account");
        }
    }

    let code = generate_referral_code();
    let referral = Referral {
        id: 0,
        user_id: uid,
        code,
        lightning_address: req.lightning_address,
        use_nwc: req.use_nwc,
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
        .map_err(|_| ApiError::new("Not enrolled in referral program"))?;

    if let Some(ref addr) = req.lightning_address {
        if let Some(a) = addr {
            validate_lightning_address(a).await?;
        }
        referral.lightning_address = addr.clone();
    }
    if let Some(use_nwc) = req.use_nwc {
        if use_nwc {
            let user = this.db.get_user(uid).await?;
            if user.nwc_connection_string.is_none() {
                return ApiData::err("NWC connection is not configured on your account");
            }
        }
        referral.use_nwc = use_nwc;
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
    async fn test_validate_lightning_address_accepts_valid() {
        let result = validate_lightning_address("kieran@zap.stream").await;
        assert!(result.is_ok());
    }
}
