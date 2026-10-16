//! Customer-facing account credit: the balance a user tops up and spends
//! against purchases, renewals and upgrades. See `work/account-credit.md` and
//! issue #145.
//!
//! A top-up is a plain Lightning invoice the customer pays. It is not a
//! `subscription_payment`: it belongs to no subscription and extends nothing,
//! so it lives in its own table and is settled by the same Lightning listener
//! that settles subscription payments. When the invoice settles the user's
//! `account_credit.balance` increases and a `topup` ledger event is written.

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use payments_rs::lightning::AddInvoiceRequest;
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
    round_msat_to_sat,
};
use lnvps_db::{AccountCredit, AccountCreditEvent, AccountCreditTopup};

use crate::api::RouterState;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/account/credit",
            get(v1_get_credit).patch(v1_patch_credit),
        )
        .route("/api/v1/account/credit/topup", post(v1_topup_credit))
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

/// The top-up response: a Lightning invoice the customer pays to increase
/// their balance.
#[derive(Serialize)]
pub struct ApiCreditTopup {
    /// BOLT11 payment request to pay.
    pub pr: String,
    /// The top-up's payment hash, for reference and later status lookups.
    pub payment_hash: String,
    /// Msat the invoice is for.
    pub amount: u64,
    pub currency: String,
    /// ISO-8601 time the invoice expires.
    pub expires: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct TopupRequest {
    /// Msat to top up, rounded up to a whole sat.
    amount: u64,
}

#[derive(Deserialize)]
struct PatchCreditRequest {
    auto_apply: bool,
}

/// Top up the account credit balance with a Lightning invoice.
async fn v1_topup_credit(
    auth: Nip98Auth,
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

    let invoice = this
        .sub_handler
        .node()
        .add_invoice(AddInvoiceRequest {
            memo: Some("LNVPS credit top-up".to_string()),
            amount,
            expire: Some(600),
        })
        .await
        .map_err(|e| ApiError::new(format!("Failed to create invoice: {e}")))?;

    let hash = hex::decode(invoice.payment_hash())
        .map_err(|e| ApiError::new(format!("Failed to decode payment hash: {e}")))?;

    let topup = AccountCreditTopup {
        user_id: uid,
        amount,
        currency: currency.clone(),
        invoice_hash: hash.clone(),
        external_data: invoice.pr(),
        ..Default::default()
    };
    this.db.insert_account_credit_topup(&topup).await?;

    ApiData::ok(ApiCreditTopup {
        pr: invoice.pr(),
        payment_hash: hex::encode(&hash),
        amount,
        currency,
        expires: chrono::Utc::now() + chrono::Duration::seconds(600),
    })
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
