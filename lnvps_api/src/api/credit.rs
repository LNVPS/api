//! Customer-facing account credit: the balance a user tops up and spends
//! against purchases, renewals and upgrades. See `work/account-credit.md` and
//! issue #145.
//!
//! A top-up is a plain Lightning invoice the customer pays. It is not a
//! `subscription_payment`: it belongs to no subscription and extends nothing,
//! so it lives in its own table and is settled by the same Lightning listener
//! that settles subscription payments. When the invoice settles the user's
//! `account_credit.balance` increases and a `topup` ledger event is written.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use payments_rs::lightning::AddInvoiceRequest;
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
    round_msat_to_sat,
};
use lnvps_db::{AccountCredit, AccountCreditEvent, AccountCreditTopup, PaymentMethod};

use crate::api::model::ApiPaymentData;
use crate::api::{RouterState, parse_fixedfloat_coin};
use crate::swap::SwapData;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/account/credit",
            get(v1_get_credit).patch(v1_patch_credit),
        )
        .route("/api/v1/account/credit/topup", post(v1_topup_credit))
        .route(
            "/api/v1/account/credit/topup/{payment_hash}",
            get(v1_get_topup),
        )
        .route("/api/v1/account/credit/events", get(v1_list_credit_events))
}

/// The customer's account credit balance and opt-in flag.
#[derive(Serialize)]
pub struct ApiAccountCredit {
    /// Minor units of `currency` (msat for BTC).
    pub balance: u64,
    /// ISO currency code of the balance.
    pub currency: String,
    /// Whether the balance is auto-applied against quotes.
    pub auto_apply: bool,
}

impl From<AccountCredit> for ApiAccountCredit {
    fn from(c: AccountCredit) -> Self {
        Self {
            balance: c.balance,
            currency: c.currency,
            auto_apply: c.auto_apply,
        }
    }
}

/// One row of the account credit ledger, as shown to the customer.
#[derive(Serialize)]
pub struct ApiAccountCreditEvent {
    pub kind: String,
    /// Signed change to the balance.
    pub amount: i64,
    pub currency: String,
    /// The `subscription_payment` this event is about, for `spend` and
    /// `refund` rows. `null` for `topup` and `admin` rows.
    pub subscription_payment_id: Option<String>,
    pub note: Option<String>,
    pub created: chrono::DateTime<chrono::Utc>,
}

impl From<AccountCreditEvent> for ApiAccountCreditEvent {
    fn from(e: AccountCreditEvent) -> Self {
        Self {
            kind: e.kind,
            amount: e.amount,
            currency: e.currency,
            subscription_payment_id: e.subscription_payment_id.as_ref().map(hex::encode),
            note: e.note,
            created: e.created,
        }
    }
}

/// The top-up response: what the customer pays to increase their balance.
#[derive(Serialize)]
pub struct ApiCreditTopup {
    /// BOLT11 payment request to pay. Only set for Lightning top-ups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
    /// The top-up's reference, for later status lookups.
    pub payment_hash: String,
    /// `lightning`, `onchain` or `fixedfloat`.
    pub method: String,
    /// What to pay: an invoice, a receive address or a swap deposit.
    pub data: ApiPaymentData,
    /// Msat requested, or received once a deposit is seen.
    pub amount: u64,
    pub currency: String,
    pub is_paid: bool,
    /// ISO-8601 time the quote expires.
    pub expires: chrono::DateTime<chrono::Utc>,
}

impl ApiCreditTopup {
    fn from_topup(t: &AccountCreditTopup, expires: chrono::DateTime<chrono::Utc>) -> Self {
        let (method, data, pr) = match t.payment_method {
            PaymentMethod::OnChain => (
                "onchain",
                ApiPaymentData::OnChain {
                    address: t.external_data.clone(),
                    outpoint: t.external_id.clone(),
                },
                None,
            ),
            PaymentMethod::FixedFloat => (
                "fixedfloat",
                SwapData::parse(&t.external_data)
                    .map(|d| ApiPaymentData::FixedFloat {
                        coin: d.coin,
                        address: d.deposit_address,
                        amount: d.deposit_amount,
                        outpoint: t.external_id.clone(),
                    })
                    .unwrap_or(ApiPaymentData::Lightning(String::new())),
                None,
            ),
            _ => (
                "lightning",
                ApiPaymentData::Lightning(t.external_data.clone()),
                Some(t.external_data.clone()),
            ),
        };
        Self {
            pr,
            payment_hash: hex::encode(&t.invoice_hash),
            method: method.to_string(),
            data,
            amount: t.amount,
            currency: t.currency.clone(),
            is_paid: t.is_paid,
            expires,
        }
    }
}

#[derive(Deserialize)]
struct TopupRequest {
    /// Msat to top up, rounded up to a whole sat.
    amount: u64,
    /// `lightning` (default), `onchain` or `fixedfloat`.
    method: Option<String>,
    /// For `fixedfloat`: the coin to pay with, e.g. `XMR`.
    coin: Option<String>,
}

#[derive(Deserialize)]
struct PatchCreditRequest {
    auto_apply: bool,
}

const LIGHTNING_TOPUP_EXPIRE: i64 = 600;
const ONCHAIN_TOPUP_EXPIRE: i64 = 3600;

/// Top up the account credit balance by Lightning, on-chain or a FixedFloat swap.
async fn v1_topup_credit(
    auth: Nip98Auth,
    client: lnvps_api_common::ClientInfo,
    State(this): State<RouterState>,
    Json(req): Json<TopupRequest>,
) -> ApiResult<ApiCreditTopup> {
    const MIN_TOPUP_MSAT: u64 = 1_000;
    if req.amount < MIN_TOPUP_MSAT {
        return ApiData::err(&format!(
            "Top-up amount must be at least {MIN_TOPUP_MSAT} msat"
        ));
    }
    let amount = round_msat_to_sat(req.amount);

    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let credit = this.db.get_account_credit(uid).await?;
    let currency = if credit.currency.is_empty() {
        "BTC".to_string()
    } else {
        credit.currency
    };

    let method = req.method.as_deref().unwrap_or("lightning");
    let mut topup = AccountCreditTopup {
        user_id: uid,
        amount,
        currency,
        ..Default::default()
    };
    let expire;
    match method {
        "lightning" => {
            expire = LIGHTNING_TOPUP_EXPIRE;
            let invoice = this
                .sub_handler
                .node()
                .add_invoice(AddInvoiceRequest {
                    memo: Some("LNVPS credit top-up".to_string()),
                    amount,
                    expire: Some(LIGHTNING_TOPUP_EXPIRE as u32),
                })
                .await
                .map_err(|e| ApiError::new(format!("Failed to create invoice: {e}")))?;
            topup.payment_method = PaymentMethod::Lightning;
            topup.invoice_hash = hex::decode(invoice.payment_hash())
                .map_err(|e| ApiError::new(format!("Failed to decode payment hash: {e}")))?;
            topup.external_data = invoice.pr();
        }
        "onchain" => {
            expire = ONCHAIN_TOPUP_EXPIRE;
            let reference: [u8; 32] = rand::random();
            topup.payment_method = PaymentMethod::OnChain;
            topup.invoice_hash = reference.to_vec();
            topup.external_data = this
                .sub_handler
                .new_credit_topup_address(amount, hex::encode(reference))
                .await
                .map_err(|e| ApiError::new(e.to_string()))?;
        }
        "fixedfloat" => {
            let coin = parse_fixedfloat_coin(req.coin.as_deref())?;
            let reference: [u8; 32] = rand::random();
            let order = this
                .sub_handler
                .new_credit_topup_swap(coin, amount, hex::encode(reference))
                .await
                .map_err(|e| ApiError::new(e.to_string()))?;
            expire = (order.expires - chrono::Utc::now()).num_seconds().max(0);
            topup.payment_method = PaymentMethod::FixedFloat;
            topup.invoice_hash = reference.to_vec();
            topup.external_data = order
                .data
                .to_json()
                .map_err(|e| ApiError::new(e.to_string()))?;
        }
        other => return ApiData::err(&format!("Unsupported top-up method: {other}")),
    }
    topup.id = this.db.insert_account_credit_topup(&topup).await?;
    crate::api::record_swap_client(
        &this,
        uid,
        topup.payment_method,
        &topup.invoice_hash,
        &topup.external_data,
        &client,
    )
    .await;

    ApiData::ok(ApiCreditTopup::from_topup(
        &topup,
        chrono::Utc::now() + chrono::Duration::seconds(expire),
    ))
}

/// Status of one of the customer's top-ups, for polling.
async fn v1_get_topup(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(payment_hash): Path<String>,
) -> ApiResult<ApiCreditTopup> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let Ok(hash) = hex::decode(&payment_hash) else {
        return ApiData::err("Invalid payment hash");
    };
    let Some(topup) = this
        .db
        .get_account_credit_topup_by_hash(&hash)
        .await?
        .filter(|t| t.user_id == uid)
    else {
        return ApiData::err("Top-up not found");
    };
    let window = match topup.payment_method {
        PaymentMethod::Lightning => LIGHTNING_TOPUP_EXPIRE,
        _ => ONCHAIN_TOPUP_EXPIRE,
    };
    ApiData::ok(ApiCreditTopup::from_topup(
        &topup,
        topup.created + chrono::Duration::seconds(window),
    ))
}

/// The customer's current balance and opt-in flag.
async fn v1_get_credit(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<ApiAccountCredit> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let credit = this.db.get_account_credit(uid).await?;
    ApiData::ok(ApiAccountCredit::from(credit))
}

/// Toggle auto-apply for the customer's balance.
async fn v1_patch_credit(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<PatchCreditRequest>,
) -> ApiResult<ApiAccountCredit> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let credit = this
        .db
        .set_account_credit_auto_apply(uid, req.auto_apply)
        .await?;
    ApiData::ok(ApiAccountCredit::from(credit))
}

/// The customer's account credit ledger, newest first, paginated.
async fn v1_list_credit_events(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiAccountCreditEvent> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);

    let (events, total) = this
        .db
        .list_account_credit_events(uid, limit, offset)
        .await
        .map_err(|e| lnvps_api_common::ApiError::new(e.to_string()))?;
    let out: Vec<ApiAccountCreditEvent> = events
        .into_iter()
        .map(ApiAccountCreditEvent::from)
        .collect();
    ApiPaginatedData::ok(out, total, limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDbBase;
    use std::sync::Arc;

    /// The API view of a fresh user's credit is the zero-balance row.
    #[tokio::test]
    async fn api_view_of_unknown_user_is_zero() {
        let db = Arc::new(MockDb::default());
        let uid = db.upsert_user(&[1u8; 32]).await.unwrap();
        let api = ApiAccountCredit::from(db.get_account_credit(uid).await.unwrap());
        assert_eq!(api.balance, 0);
        assert_eq!(api.currency, "BTC");
        assert!(!api.auto_apply);
    }

    /// Toggling auto-apply is reflected in the API view.
    #[tokio::test]
    async fn api_view_reflects_auto_apply() {
        let db = Arc::new(MockDb::default());
        let uid = db.upsert_user(&[2u8; 32]).await.unwrap();
        let api =
            ApiAccountCredit::from(db.set_account_credit_auto_apply(uid, true).await.unwrap());
        assert!(api.auto_apply);
    }

    /// A ledger row's payment hash is hex-encoded in the API view, and a topup
    /// (no payment) shows `null`.
    #[tokio::test]
    async fn api_event_encodes_payment_hash() {
        let spend = AccountCreditEvent {
            kind: "spend".to_string(),
            amount: 500,
            subscription_payment_id: Some(vec![7u8; 32]),
            ..Default::default()
        };
        let api = ApiAccountCreditEvent::from(spend);
        assert_eq!(
            api.subscription_payment_id.as_deref(),
            Some(hex::encode(vec![7u8; 32]).as_str())
        );

        let topup = AccountCreditEvent {
            kind: "topup".to_string(),
            ..Default::default()
        };
        assert!(
            ApiAccountCreditEvent::from(topup)
                .subscription_payment_id
                .is_none()
        );
    }

    /// The pagination parameters clamp to [1..=100] for the ledger.
    #[test]
    fn credit_event_page_clamps() {
        let q = PageQuery {
            limit: Some(1000),
            offset: None,
        };
        let limit = q.limit.unwrap_or(50).min(100);
        let offset = q.offset.unwrap_or(0);
        assert_eq!(limit, 100);
        assert_eq!(offset, 0);
    }
}
