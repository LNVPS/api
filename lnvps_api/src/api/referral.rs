use crate::api::RouterState;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::{get, patch, post};
use chrono::Utc;
use lnvps_api_common::{ApiData, ApiError, ApiResult, Nip98Auth};
use lnvps_db::{Referral, ReferralSummary};
use serde::{Deserialize, Serialize};

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

/// Response type combining referral info and summary stats
#[derive(Serialize)]
pub struct ApiReferralState {
    #[serde(flatten)]
    pub referral: ApiReferral,
    /// Total amount pending payout (earned but not yet paid)
    pub pending_amount: u64,
    /// Total lifetime paid amount
    pub paid_amount: u64,
    /// Number of referrals that resulted in a paid subscription
    pub referrals_success: u64,
    /// Number of referrals that never paid
    pub referrals_failed: u64,
}

impl ApiReferralState {
    pub fn from_referral_and_summary(referral: Referral, summary: ReferralSummary) -> Self {
        Self {
            referral: referral.into(),
            pending_amount: summary.pending_amount,
            paid_amount: summary.paid_amount,
            referrals_success: summary.referrals_success,
            referrals_failed: summary.referrals_failed,
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

/// Generate a random 8-character base32 referral code
fn generate_referral_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bytes: [u8; 5] = rand::random();
    // Encode 5 bytes (40 bits) as 8 base32 characters (5 bits each)
    let bits = (bytes[0] as u64) << 32
        | (bytes[1] as u64) << 24
        | (bytes[2] as u64) << 16
        | (bytes[3] as u64) << 8
        | bytes[4] as u64;
    let mut code = String::with_capacity(8);
    for i in (0..8).rev() {
        let idx = ((bits >> (i * 5)) & 0x1f) as usize;
        code.push(ALPHABET[idx] as char);
    }
    code
}

/// Get current referral state (code, stats, payout info)
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

    let summary = this.db.get_referral_summary(referral.id).await?;

    ApiData::ok(ApiReferralState::from_referral_and_summary(referral, summary))
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
        return ApiData::err("At least one payout method (lightning_address or use_nwc) is required");
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

    if let Some(addr) = req.lightning_address {
        referral.lightning_address = addr;
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
        const VALID: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        for _ in 0..100 {
            let code = generate_referral_code();
            for c in code.chars() {
                assert!(VALID.contains(c), "Invalid base32 character: {}", c);
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
}
