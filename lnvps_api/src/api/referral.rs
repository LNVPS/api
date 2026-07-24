use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use lnurl::lightning_address::LightningAddress;
use lnurl::pay::PayResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
};
use lnvps_db::{Referral, ReferralCostUsage, ReferralPayout, ReferralPayoutMode};

use crate::api::RouterState;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/referral",
            get(v1_get_referral)
                .post(v1_signup_referral)
                .patch(v1_update_referral)
                .delete(v1_delete_referral),
        )
        .route("/api/v1/referral/usage", get(v1_get_referral_usage))
}

/// Response type for a referral entry
#[derive(Serialize)]
pub struct ApiReferral {
    /// The referral code to share with others
    pub code: String,
    /// Payout target address; its type is determined by `mode`: a Lightning
    /// address for `lightning_address`, an on-chain Bitcoin address for
    /// `on_chain`, absent for `nwc`.
    pub address: Option<String>,
    /// Payout method: `lightning_address`, `nwc`, `account_credit`, or
    /// `on_chain`.
    pub mode: String,
    /// Per-referrer commission override, as a whole percentage of a referred
    /// VM's first payment. `null` means the referred VM's company default rate
    /// (`company.referral_rate`) applies instead.
    pub referral_rate: Option<f32>,
    /// The commission rate (whole %) that currently applies to this referrer:
    /// the per-referrer `referral_rate` override when set, otherwise the default
    /// company's `referral_rate`. Note the rate actually paid on a given
    /// referral is resolved against the referred VM's own company, so this is
    /// the headline/default rate for display.
    pub effective_referral_rate: f32,
    /// When the referral was created
    pub created: chrono::DateTime<Utc>,
}

impl From<Referral> for ApiReferral {
    fn from(r: Referral) -> Self {
        Self {
            code: r.code,
            address: r.address,
            mode: r.mode.to_string(),
            // Fallback until resolved against the default company rate by the
            // handler (see `resolve_effective_rate`).
            effective_referral_rate: r.referral_rate.unwrap_or(0.0),
            referral_rate: r.referral_rate,
            created: r.created,
        }
    }
}

/// Resolve the commission rate that currently applies to a referrer: their
/// per-referrer override if set, otherwise the default (primary, lowest-id)
/// company's `referral_rate`.
async fn resolve_effective_rate(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    referral: &Referral,
) -> f32 {
    if let Some(r) = referral.referral_rate {
        return r;
    }
    db.list_companies()
        .await
        .ok()
        .and_then(|c| c.into_iter().next())
        .map(|c| c.referral_rate)
        .unwrap_or(0.0)
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
    /// Payment preimage (hex), present once a Lightning payout has settled.
    pub pre_image: Option<String>,
    /// On-chain payout outpoint (`"{txid}:{vout}"`), present once an on-chain
    /// payout has been broadcast. On-chain payouts are batched into one
    /// transaction, so rows share the txid but carry distinct vouts.
    pub outpoint: Option<String>,
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
            pre_image: p.pre_image.map(hex::encode),
            outpoint: p.outpoint,
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
        effective_rate: f32,
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

        let mut referral: ApiReferral = referral.into();
        referral.effective_referral_rate = effective_rate;
        Self {
            referrals_success: usage.len() as u64,
            referrals_failed,
            referral,
            earned,
            payouts: payouts.into_iter().map(Into::into).collect(),
        }
    }
}

/// A single referred VM's first payment and the commission earned from it.
///
/// The referred VM's id is intentionally omitted so a referrer cannot map
/// their commission back to specific customers' VMs.
#[derive(Serialize)]
pub struct ApiReferralUsage {
    /// When the first paid payment was made.
    pub created: chrono::DateTime<Utc>,
    /// The referred VM's first payment amount (smallest currency unit).
    pub amount: u64,
    /// Currency of the payment / commission.
    pub currency: String,
    /// Effective commission rate applied (whole %).
    pub effective_rate: f32,
    /// Commission earned = amount * effective_rate% (smallest currency unit).
    pub commission: u64,
}

/// Request to sign up for the referral program
#[derive(Deserialize)]
pub struct ApiReferralSignupRequest {
    /// Payout target address. Required and validated according to `mode`: a
    /// Lightning address for `lightning_address`, an on-chain Bitcoin address
    /// for `on_chain`. Not needed for `nwc`.
    pub address: Option<String>,
    /// Payout method: `lightning_address` (default), `nwc`, or `on_chain`.
    pub mode: Option<String>,
}

/// Request to update referral payout options
#[derive(Deserialize)]
pub struct ApiReferralPatchRequest {
    /// Payout target address (None = clear, Some(s) = set). Validated according
    /// to the effective `mode`: a Lightning address for `lightning_address`, an
    /// on-chain Bitcoin address for `on_chain`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub address: Option<Option<String>>,
    /// Payout method: `lightning_address`, `nwc`, `account_credit`, or
    /// `on_chain`.
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
    let parsed = ReferralPayoutMode::from_str(s).map_err(|_| {
        ApiError::new("Invalid payout mode. Use 'lightning_address', 'nwc', or 'on_chain'")
    })?;
    if parsed == ReferralPayoutMode::AccountCredit {
        return Err(ApiError::new(
            "Account credit payouts are not yet available",
        ));
    }
    Ok(Some(parsed))
}

/// Validate an on-chain Bitcoin address.
///
/// The address must be a **mainnet** address in release builds. In debug builds
/// (local/dev/test, e.g. the regtest e2e stack) a **regtest** address is also
/// accepted so payouts can be exercised end-to-end.
fn validate_onchain_address(addr: &str) -> Result<(), ApiError> {
    use bitcoin::{Address, Network};
    use std::str::FromStr;

    let parsed =
        Address::from_str(addr.trim()).map_err(|_| ApiError::new("Invalid Bitcoin address"))?;
    if parsed.is_valid_for_network(Network::Bitcoin) {
        return Ok(());
    }
    if cfg!(debug_assertions) {
        if parsed.is_valid_for_network(Network::Regtest) {
            return Ok(());
        }
        return Err(ApiError::new(
            "Bitcoin address must be a mainnet or regtest address",
        ));
    }
    Err(ApiError::new("Bitcoin address must be a mainnet address"))
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
    let pubkey = auth.pubkey();
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

    let effective_rate = resolve_effective_rate(&this.db, &referral).await;
    ApiData::ok(ApiReferralState::build(
        referral,
        effective_rate,
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
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Check if already enrolled
    if this.db.get_referral_by_user(uid).await.is_ok() {
        return Err(ApiError::conflict("Already enrolled in referral program"));
    }

    // Resolve the payout mode, defaulting to lightning_address when omitted.
    let mode =
        parse_payout_mode(req.mode.as_deref())?.unwrap_or(ReferralPayoutMode::LightningAddress);

    // Validate the payout address required by the chosen mode.
    match mode {
        ReferralPayoutMode::LightningAddress => match req.address.as_deref() {
            Some(addr) if !addr.trim().is_empty() => validate_lightning_address(addr).await?,
            _ => {
                return ApiData::err(
                    "address (a lightning address) is required when mode is 'lightning_address'",
                );
            }
        },
        ReferralPayoutMode::Nwc => {
            if !user_has_nwc(&this, uid).await {
                return ApiData::err("NWC connection is not configured on your account");
            }
        }
        ReferralPayoutMode::OnChain => match req.address.as_deref() {
            Some(addr) if !addr.trim().is_empty() => validate_onchain_address(addr)?,
            _ => {
                return ApiData::err(
                    "address (a Bitcoin address) is required when mode is 'on_chain'",
                );
            }
        },
        ReferralPayoutMode::AccountCredit => unreachable!("rejected by parse_payout_mode"),
    }

    let code = generate_referral_code();
    let referral = Referral {
        id: 0,
        user_id: uid,
        code,
        address: req.address,
        mode,
        // Per-referrer commission override is admin-controlled; new enrollments
        // default to the referred VM's company rate (None = use company default).
        referral_rate: None,
        created: Utc::now(),
    };

    let id = this.db.insert_referral(&referral).await?;
    let created = Referral { id, ..referral };

    let effective_rate = resolve_effective_rate(&this.db, &created).await;
    let mut api: ApiReferral = created.into();
    api.effective_referral_rate = effective_rate;
    ApiData::ok(api)
}

/// Update referral payout options
async fn v1_update_referral(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<ApiReferralPatchRequest>,
) -> ApiResult<ApiReferral> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let mut referral = this
        .db
        .get_referral_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Not enrolled in referral program"))?;

    // Validate a supplied address against the *effective* mode (the new mode if
    // being changed in this request, otherwise the existing one) so the address
    // type matches the payout method.
    let new_mode = parse_payout_mode(req.mode.as_deref())?;
    let effective_mode = new_mode.unwrap_or(referral.mode);
    if let Some(ref addr) = req.address {
        if let Some(a) = addr {
            match effective_mode {
                ReferralPayoutMode::LightningAddress => validate_lightning_address(a).await?,
                ReferralPayoutMode::OnChain => validate_onchain_address(a)?,
                // Other modes (nwc, account_credit) don't use an address.
                _ => {}
            }
        }
        referral.address = addr.clone();
    }
    if let Some(mode) = new_mode {
        if mode == ReferralPayoutMode::Nwc && !user_has_nwc(&this, uid).await {
            return ApiData::err("NWC connection is not configured on your account");
        }
        referral.mode = mode;
    }

    // Note: we intentionally do NOT require the resulting config to be immediately
    // payable (e.g. a lightning_address-mode referral may temporarily have no
    // address). The payout worker skips referrers whose method can't produce an
    // invoice, so an incomplete config simply defers payouts rather than losing
    // them. Signup still requires a valid method up-front.
    this.db.update_referral(&referral).await?;

    let effective_rate = resolve_effective_rate(&this.db, &referral).await;
    let mut api: ApiReferral = referral.into();
    api.effective_referral_rate = effective_rate;
    ApiData::ok(api)
}

/// Leave the referral program.
///
/// Blocked while any payout records exist: a **pending** payout must settle
/// first, and paid payout history is retained for accounting (so a referrer who
/// has ever been paid cannot delete their enrollment).
async fn v1_delete_referral(auth: Nip98Auth, State(this): State<RouterState>) -> ApiResult<()> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let referral = this
        .db
        .get_referral_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Not enrolled in referral program"))?;

    let payouts = this.db.list_referral_payouts(referral.id).await?;
    if payouts.iter().any(|p| !p.is_paid) {
        return Err(ApiError::conflict(
            "Cannot leave the referral program while a payout is pending",
        ));
    }
    if !payouts.is_empty() {
        return Err(ApiError::conflict(
            "Cannot leave the referral program because payout history exists",
        ));
    }

    this.db.delete_referral(referral.id).await?;
    ApiData::ok(())
}

/// Per-referred-VM breakdown: each referred VM's first payment and the
/// commission earned from it.
async fn v1_get_referral_usage(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiReferralUsage> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let referral = this
        .db
        .get_referral_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Not enrolled in referral program"))?;

    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (usage, total) = this
        .db
        .list_referral_usage_paginated(&referral.code, limit, offset)
        .await?;
    let out: Vec<ApiReferralUsage> = usage
        .into_iter()
        .map(|u| ApiReferralUsage {
            created: u.created,
            amount: u.amount,
            commission: u.commission(),
            effective_rate: u.effective_rate,
            currency: u.currency,
        })
        .collect();
    ApiPaginatedData::ok(out, total, limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_referral_code_length() {
        let code = generate_referral_code();
        assert_eq!(code.len(), 8);
    }

    #[tokio::test]
    async fn test_list_referral_usage_paginated_empty() {
        use lnvps_api_common::MockDb;
        use std::sync::Arc;

        let db: Arc<dyn lnvps_db::LNVpsDb> = Arc::new(MockDb::default());
        let (rows, total) = db
            .list_referral_usage_paginated("no-such-code", 50, 0)
            .await
            .unwrap();
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_resolve_effective_rate_uses_override() {
        use lnvps_api_common::MockDb;
        use std::sync::Arc;

        let db: Arc<dyn lnvps_db::LNVpsDb> = Arc::new(MockDb::default());
        let referral = Referral {
            referral_rate: Some(12.5),
            ..Default::default()
        };
        // Override is set, so the company default is ignored.
        assert_eq!(resolve_effective_rate(&db, &referral).await, 12.5);
    }

    #[tokio::test]
    async fn test_resolve_effective_rate_falls_back_to_company_default() {
        use lnvps_api_common::MockDb;
        use std::sync::Arc;

        let mock = MockDb::default();
        // Give the default (primary) company a 33% referral rate.
        {
            let mut companies = mock.companies.lock().await;
            if let Some(c) = companies.get_mut(&1) {
                c.referral_rate = 33.0;
            }
        }
        let db: Arc<dyn lnvps_db::LNVpsDb> = Arc::new(mock);
        let referral = Referral {
            referral_rate: None,
            ..Default::default()
        };
        assert_eq!(resolve_effective_rate(&db, &referral).await, 33.0);
    }

    #[test]
    fn test_validate_onchain_address() {
        // Mainnet always accepted.
        assert!(validate_onchain_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_ok());
        // Regtest accepted in debug builds (tests run with debug_assertions).
        let regtest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        assert_eq!(
            validate_onchain_address(regtest).is_ok(),
            cfg!(debug_assertions),
            "regtest is only valid in debug builds"
        );
        // Garbage rejected.
        assert!(validate_onchain_address("not-an-address").is_err());
        assert!(validate_onchain_address("").is_err());
        // Whitespace is trimmed.
        assert!(validate_onchain_address("  bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4  ").is_ok());
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
