use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::extract::{Query, State};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, TimeZone, Utc};
use lnvps_api_common::{ApiData, ApiResult, value_in_billing_currency};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<RouterState> {
    Router::new().route(
        "/api/admin/v1/credit/rebook_btc_refunds",
        post(admin_rebook_btc_refunds),
    )
}

pub fn refunds_in_source_currency_since() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 2, 10, 39, 24).unwrap()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RebookQuery {
    dry_run: Option<bool>,
    since: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct RebookLine {
    pub user_id: u64,
    pub refund_id: String,
    pub btc_amount: u64,
    pub billing_currency: String,
    pub billing_amount: u64,
    pub btc_already_spent: bool,
    pub rebooked: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct RebookReport {
    pub dry_run: bool,
    pub lines: Vec<RebookLine>,
}

async fn admin_rebook_btc_refunds(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<RebookQuery>,
    body: Option<Json<serde_json::Value>>,
) -> ApiResult<RebookReport> {
    auth.require_permission(AdminResource::AccountCredit, AdminAction::Update)?;
    let dry_run = q
        .dry_run
        .or_else(|| {
            body.as_ref()
                .and_then(|b| b.get("dry_run"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(true);
    let since = q.since.unwrap_or_else(refunds_in_source_currency_since);
    let report = rebook_btc_refunds(&this.db, since, dry_run).await?;
    ApiData::ok(report)
}

pub async fn rebook_btc_refunds(
    db: &std::sync::Arc<dyn LNVpsDb>,
    since: DateTime<Utc>,
    dry_run: bool,
) -> anyhow::Result<RebookReport> {
    let events = db
        .list_account_credit_events_by_kind("refund", "BTC", since)
        .await?;
    let mut report = RebookReport {
        dry_run,
        lines: Vec::new(),
    };
    for event in events {
        let Some(refund_id) = event.subscription_payment_id.clone() else {
            continue;
        };
        let Ok(refund) = db.get_subscription_payment(&refund_id).await else {
            continue;
        };
        let Some(original_id) = refund.refunded_payment_id.clone() else {
            continue;
        };
        let meta = refund.metadata.clone().unwrap_or_default();
        if meta["refund"]["by_owner_user_id"].is_null()
            || meta["refund"]["rebooked_to_billing"].as_bool() == Some(true)
            || meta["refund"]["billing_currency"].is_string()
        {
            continue;
        }
        let original = db.get_subscription_payment(&original_id).await?;
        if original.currency != "BTC" {
            continue;
        }
        let subscription = db.get_subscription(original.subscription_id).await?;
        if subscription.currency == "BTC" {
            continue;
        }
        let cash_share = meta["refund"]["returned_from_cash"]
            .as_u64()
            .unwrap_or(event.amount.max(0) as u64);
        let btc = cash_share.min(event.amount.max(0) as u64);
        let Some(billing) =
            value_in_billing_currency(btc, "BTC", &subscription.currency, original.rate)
        else {
            continue;
        };
        if btc == 0 || billing == 0 {
            continue;
        }
        let balance = db.get_account_credit(event.user_id, "BTC").await?.balance;
        let reserved = db.get_account_credit_reserved(event.user_id, "BTC").await?;
        let spent = balance.saturating_sub(reserved) < btc;
        let mut line = RebookLine {
            user_id: event.user_id,
            refund_id: hex::encode(&refund_id),
            btc_amount: btc,
            billing_currency: subscription.currency.clone(),
            billing_amount: billing,
            btc_already_spent: spent,
            rebooked: false,
        };
        if !dry_run && !spent {
            let note = format!("rebook of refund {}", line.refund_id);
            db.adjust_account_credit(event.user_id, "BTC", -(btc as i64), "admin", Some(&note))
                .await?;
            db.adjust_account_credit(
                event.user_id,
                &subscription.currency,
                billing as i64,
                "refund",
                Some(&note),
            )
            .await?;
            let mut marked = refund.clone();
            let mut m = marked.metadata.take().unwrap_or_default();
            m["refund"]["rebooked_to_billing"] = serde_json::json!(true);
            m["refund"]["billing_currency"] = serde_json::json!(subscription.currency);
            m["refund"]["billing_amount"] = serde_json::json!(billing);
            m["refund"]["original_currency"] = serde_json::json!("BTC");
            m["refund"]["original_amount"] = serde_json::json!(btc);
            m["refund"]["rate"] = serde_json::json!(original.rate);
            marked.metadata = Some(m);
            db.update_subscription_payment(&marked).await?;
            line.rebooked = true;
        }
        report.lines.push(line);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{
        LNVpsDbBase, PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionPayment,
        SubscriptionPaymentType,
    };
    use std::sync::Arc;

    async fn book_old_btc_refund(mock: &MockDb, user_id: u64) -> Vec<u8> {
        let (sub_id, _) = mock
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "vm".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: Some(Utc::now()),
                    is_active: true,
                    is_setup: true,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: lnvps_db::IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: lnvps_db::LineItemType::Vps,
                    name: "vm".to_string(),
                    description: None,
                    amount: 100,
                    setup_amount: 0,
                    configuration: None,
                    deactivated_at: None,
                    parent_line_item_id: None,
                }],
            )
            .await
            .unwrap();
        let original = SubscriptionPayment {
            id: vec![4u8; 32],
            subscription_id: sub_id,
            user_id,
            created: Utc::now(),
            expires: Utc::now(),
            amount: 12_500_000,
            currency: "BTC".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Renewal,
            external_data: "".into(),
            external_id: None,
            is_paid: true,
            rate: 80_000.0,
            time_value: Some(2_592_000),
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: Some(Utc::now()),
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        };
        mock.insert_subscription_payment(&original).await.unwrap();
        let mut refund = original.clone();
        refund.id = vec![5u8; 32];
        refund.payment_type = SubscriptionPaymentType::Refund;
        refund.amount = 6_250_000;
        refund.time_value = None;
        refund.refunded_payment_id = Some(original.id.clone());
        refund.metadata = Some(serde_json::json!({"refund": {
            "by_owner_user_id": user_id,
            "returned_from_cash": 6_250_000u64,
            "returned_as_credit": {"BTC": 6_250_000u64},
        }}));
        mock.insert_refund_to_credit(
            &refund,
            &[("BTC".to_string(), 6_250_000)],
            Some("VM deleted"),
        )
        .await
        .unwrap();
        refund.id
    }

    fn since() -> DateTime<Utc> {
        Utc::now() - chrono::Duration::days(1)
    }

    #[tokio::test]
    async fn a_dry_run_reports_and_changes_nothing() {
        let mock = MockDb::default();
        let user_id = mock.upsert_user(&[1u8; 32]).await.unwrap();
        book_old_btc_refund(&mock, user_id).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);

        let report = rebook_btc_refunds(&db, since(), true).await.unwrap();
        assert_eq!(report.lines.len(), 1);
        let line = &report.lines[0];
        assert_eq!(line.btc_amount, 6_250_000);
        assert_eq!(line.billing_currency, "EUR");
        assert_eq!(line.billing_amount, 500);
        assert!(!line.btc_already_spent);
        assert!(!line.rebooked);
        assert_eq!(
            db.get_account_credit(user_id, "BTC").await.unwrap().balance,
            6_250_000
        );
        assert_eq!(
            db.get_account_credit(user_id, "EUR").await.unwrap().balance,
            0
        );
    }

    #[tokio::test]
    async fn a_real_run_moves_the_btc_to_eur_once() {
        let mock = MockDb::default();
        let user_id = mock.upsert_user(&[1u8; 32]).await.unwrap();
        let refund_id = book_old_btc_refund(&mock, user_id).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);

        let report = rebook_btc_refunds(&db, since(), false).await.unwrap();
        assert!(report.lines[0].rebooked);
        assert_eq!(
            db.get_account_credit(user_id, "BTC").await.unwrap().balance,
            0
        );
        assert_eq!(
            db.get_account_credit(user_id, "EUR").await.unwrap().balance,
            500
        );
        let row = db.get_subscription_payment(&refund_id).await.unwrap();
        assert_eq!(row.metadata.unwrap()["refund"]["billing_amount"], 500);

        let again = rebook_btc_refunds(&db, since(), false).await.unwrap();
        assert!(again.lines.is_empty());
        assert_eq!(
            db.get_account_credit(user_id, "EUR").await.unwrap().balance,
            500
        );
    }

    #[tokio::test]
    async fn spent_btc_is_reported_and_left_alone() {
        let mock = MockDb::default();
        let user_id = mock.upsert_user(&[1u8; 32]).await.unwrap();
        book_old_btc_refund(&mock, user_id).await;
        mock.adjust_account_credit(user_id, "BTC", -6_000_000, "admin", None)
            .await
            .unwrap();
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);

        let report = rebook_btc_refunds(&db, since(), false).await.unwrap();
        assert!(report.lines[0].btc_already_spent);
        assert!(!report.lines[0].rebooked);
        assert_eq!(
            db.get_account_credit(user_id, "EUR").await.unwrap().balance,
            0
        );
    }
}
