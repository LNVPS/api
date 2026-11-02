//! Admin account credit: read a user's balance and ledger, and adjust it
//! (manual top-up or clawback). See `work/account-credit.md` and issue #145.

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery,
};
use lnvps_db::{AccountCredit, AccountCreditEvent, AdminAction, AdminResource};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/users/{id}/credit",
            get(admin_get_user_credit).patch(admin_adjust_user_credit),
        )
        .route(
            "/api/admin/v1/users/{id}/credit/events",
            get(admin_list_user_credit_events),
        )
}

/// A user's account credit balance, as shown to an admin.
#[derive(Serialize)]
pub struct AdminAccountCredit {
    pub user_id: u64,
    pub balance: u64,
    pub currency: String,
    pub auto_apply: bool,
    pub balances: Vec<AdminCreditBalance>,
}

#[derive(Serialize)]
pub struct AdminCreditBalance {
    pub balance: u64,
    pub currency: String,
}

impl From<AccountCredit> for AdminAccountCredit {
    fn from(c: AccountCredit) -> Self {
        Self::from_rows(c.user_id, vec![c])
    }
}

impl AdminAccountCredit {
    fn from_rows(user_id: u64, rows: Vec<AccountCredit>) -> Self {
        let btc = rows.iter().find(|c| c.currency == "BTC");
        Self {
            user_id,
            balance: btc.map(|c| c.balance).unwrap_or(0),
            currency: "BTC".to_string(),
            auto_apply: rows.iter().any(|c| c.auto_apply),
            balances: rows
                .into_iter()
                .map(|c| AdminCreditBalance {
                    balance: c.balance,
                    currency: c.currency,
                })
                .collect(),
        }
    }
}

/// One row of the account credit ledger.
#[derive(Serialize)]
pub struct AdminAccountCreditEvent {
    pub id: u64,
    pub kind: String,
    pub amount: i64,
    pub currency: String,
    pub subscription_payment_id: Option<String>,
    pub note: Option<String>,
    pub created: chrono::DateTime<chrono::Utc>,
}

impl From<AccountCreditEvent> for AdminAccountCreditEvent {
    fn from(e: AccountCreditEvent) -> Self {
        Self {
            id: e.id,
            kind: e.kind,
            amount: e.amount,
            currency: e.currency,
            subscription_payment_id: e.subscription_payment_id.as_ref().map(hex::encode),
            note: e.note,
            created: e.created,
        }
    }
}

#[derive(Deserialize)]
struct AdjustCreditRequest {
    /// Currency of the balance to adjust. Defaults to `BTC`.
    currency: Option<String>,
    /// Signed delta in minor units of `currency` (msat for BTC). Positive
    /// credits, negative claws back.
    delta: i64,
    /// Ledger `kind`: `topup`, `refund` (both positive only) or `admin`.
    #[serde(default = "default_kind")]
    kind: String,
    /// Free-form context stored on the ledger row.
    note: Option<String>,
}

fn default_kind() -> String {
    "admin".to_string()
}

const KINDS: [&str; 3] = ["topup", "refund", "admin"];

/// A user's account credit balance.
async fn admin_get_user_credit(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAccountCredit> {
    auth.require_permission(AdminResource::AccountCredit, AdminAction::View)?;
    let rows = this.db.list_account_credits(id).await?;
    ApiData::ok(AdminAccountCredit::from_rows(id, rows))
}

/// Shift a user's balance (manual top-up or clawback) and record it in the
/// ledger.
async fn admin_adjust_user_credit(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdjustCreditRequest>,
) -> ApiResult<AdminAccountCredit> {
    auth.require_permission(AdminResource::AccountCredit, AdminAction::Update)?;
    if req.delta == 0 {
        return ApiData::err("delta must be non-zero");
    }
    if !KINDS.contains(&req.kind.as_str()) {
        return ApiData::err("kind must be one of: topup, refund, admin");
    }
    if req.delta < 0 && req.kind != "admin" {
        return ApiData::err("a negative delta must use kind admin");
    }
    let currency = req.currency.as_deref().unwrap_or("BTC");
    if currency.parse::<payments_rs::currency::Currency>().is_err() {
        return ApiData::err("unknown currency");
    }
    this.db
        .adjust_account_credit(id, currency, req.delta, &req.kind, req.note.as_deref())
        .await
        .map_err(|e| ApiError::new(e.to_string()))?;
    let rows = this.db.list_account_credits(id).await?;
    ApiData::ok(AdminAccountCredit::from_rows(id, rows))
}

/// A user's account credit ledger, newest first, paginated.
async fn admin_list_user_credit_events(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<AdminAccountCreditEvent> {
    auth.require_permission(AdminResource::AccountCredit, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (events, total) = this
        .db
        .list_account_credit_events(id, limit, offset)
        .await
        .map_err(|e| ApiError::new(e.to_string()))?;
    let out: Vec<AdminAccountCreditEvent> = events
        .into_iter()
        .map(AdminAccountCreditEvent::from)
        .collect();
    ApiPaginatedData::ok(out, total, limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDbBase;
    use std::sync::Arc;

    /// The API view of a ledger row hex-encodes its payment hash.
    #[test]
    fn admin_event_encodes_payment_hash() {
        let e = AccountCreditEvent {
            kind: "spend".to_string(),
            amount: 100,
            subscription_payment_id: Some(vec![3u8; 32]),
            ..Default::default()
        };
        let api = AdminAccountCreditEvent::from(e);
        assert_eq!(
            api.subscription_payment_id.as_deref(),
            Some(hex::encode(vec![3u8; 32]).as_str())
        );
    }

    /// An admin adjustment via the DB layer is reflected in the API view.
    #[tokio::test]
    async fn admin_adjust_via_db_shows_in_api_view() {
        let db = Arc::new(MockDb::default());
        let row = db
            .adjust_account_credit(5, "BTC", 2500, "topup", Some("manual"))
            .await
            .unwrap();
        let (events, _) = db.list_account_credit_events(5, 10, 0).await.unwrap();
        assert_eq!(
            AdminAccountCreditEvent::from(events[0].clone()).amount,
            2500
        );
        db.adjust_account_credit(5, "BTC", -500, "admin", None)
            .await
            .unwrap();
        let (events, _) = db.list_account_credit_events(5, 10, 0).await.unwrap();
        assert_eq!(
            AdminAccountCreditEvent::from(events[0].clone()).amount,
            -500
        );
        let api = AdminAccountCredit::from(row);
        assert_eq!(api.user_id, 5);
        assert_eq!(api.balance, 2500);
        assert_eq!(db.get_account_credit(5, "BTC").await.unwrap().balance, 2000);
        assert_eq!(api.currency, "BTC");
    }

    /// The default ledger kind is `admin`.
    #[test]
    fn default_kind_is_admin() {
        assert_eq!(default_kind(), "admin");
        assert!(KINDS.contains(&"topup"));
        assert!(KINDS.contains(&"refund"));
        assert!(KINDS.contains(&"admin"));
    }
}
