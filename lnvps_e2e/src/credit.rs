//! E2E tests for the account credit system (issue #145).
//!
//! Covers the customer surface (balance, opt-in toggle, top-up invoice shape,
//! ledger) and the admin surface (read, adjust, clawback guard). Credit-funded
//! order flows are exercised by the unit tests in
//! `lnvps_api::subscription::credit_tests`, which run against the mock node
//! without standing up the API.

#[cfg(test)]
mod tests {
    use crate::client::*;
    use crate::db;
    use chrono::{Duration, Utc};
    use lnvps_db::{AccountCreditDebit, AccountCreditTopup, LNVpsDbBase, LNVpsDbMysql};
    use nostr::Keys;
    use reqwest::StatusCode;
    use serde_json::{Value, json};

    async fn setup() -> TestClient {
        bootstrap_admin().await.unwrap();
        admin_client()
    }

    async fn json_ok(resp: reqwest::Response) -> Value {
        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "Expected 200, body: {body}");
        serde_json::from_str(&body).unwrap()
    }

    /// A fresh customer identity with its user row ensured, and a client
    /// authenticated as it.
    async fn customer() -> (u64, TestClient) {
        let keys = Keys::generate();
        let pool = db::connect().await.unwrap();
        let uid = db::ensure_user(&pool, &keys).await.unwrap();
        pool.close().await;
        (uid, user_client_with_keys(keys))
    }

    /// A customer's credit row reads back zero with no opt-in before anything
    /// has happened.
    #[tokio::test]
    async fn credit_reads_zero_before_any_topup() {
        let _admin = setup().await;
        let (_uid, customer) = customer().await;

        let body = json_ok(customer.get_auth("/api/v1/account/credit").await.unwrap()).await;
        assert_eq!(body["data"]["balance"], 0);
        assert_eq!(body["data"]["currency"], "BTC");
        assert_eq!(body["data"]["auto_apply"], false);
    }

    /// The opt-in toggle round-trips.
    #[tokio::test]
    async fn auto_apply_toggles() {
        let _admin = setup().await;
        let (_uid, customer) = customer().await;

        let body = json_ok(
            customer
                .patch_auth("/api/v1/account/credit", &json!({"auto_apply": true}))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["auto_apply"], true);

        let body = json_ok(
            customer
                .patch_auth("/api/v1/account/credit", &json!({"auto_apply": false}))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["auto_apply"], false);
    }

    /// Toggling the opt-in leaves an existing balance and its currency alone.
    #[tokio::test]
    async fn auto_apply_toggle_keeps_the_balance() {
        let admin = setup().await;
        let (uid, customer) = customer().await;

        json_ok(
            admin
                .patch_auth(
                    &format!("/api/admin/v1/users/{uid}/credit"),
                    &json!({"delta": 3_000_000, "kind": "topup"}),
                )
                .await
                .unwrap(),
        )
        .await;

        let body = json_ok(
            customer
                .patch_auth("/api/v1/account/credit", &json!({"auto_apply": true}))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["balance"], 3_000_000);
        assert_eq!(body["data"]["currency"], "BTC");
        assert_eq!(body["data"]["auto_apply"], true);
    }

    /// A sub-minimum top-up is rejected with a 400.
    #[tokio::test]
    async fn sub_minimum_topup_is_rejected() {
        let _admin = setup().await;
        let (_uid, customer) = customer().await;

        let resp = customer
            .post_auth("/api/v1/account/credit/topup", &json!({"amount": 100}))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A top-up issues a Lightning invoice the customer can pay: a BTC BOLT11
    /// with the right amount and a 32-byte hex payment hash.
    #[tokio::test]
    async fn topup_issues_a_lightning_invoice() {
        let _admin = setup().await;
        let (_uid, customer) = customer().await;

        let body = json_ok(
            customer
                .post_auth(
                    "/api/v1/account/credit/topup",
                    &json!({"amount": 10_000_000}),
                )
                .await
                .unwrap(),
        )
        .await;
        let pr = body["data"]["pr"].as_str().expect("bolt11 string");
        assert!(pr.starts_with("lnbc"), "expected a BTC invoice, got {pr}");
        assert_eq!(body["data"]["amount"], 10_000_000);
        assert_eq!(body["data"]["currency"], "BTC");
        assert!(
            body["data"]["payment_hash"]
                .as_str()
                .is_some_and(|h| h.len() == 64),
            "payment hash is hex of 32 bytes"
        );
    }

    /// The admin can read a user's credit and ledger, and adjusting the balance
    /// moves it with a ledger row to show for it. A clawback past the balance is
    /// refused and leaves it untouched.
    #[tokio::test]
    async fn admin_can_read_and_adjust_credit() {
        let admin = setup().await;
        let (uid, customer) = customer().await;

        let body = json_ok(
            admin
                .get_auth(&format!("/api/admin/v1/users/{uid}/credit"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["balance"], 0);

        // Grant the user 5.00 EUR equivalent in sats.
        let body = json_ok(
            admin
                .patch_auth(
                    &format!("/api/admin/v1/users/{uid}/credit"),
                    &json!({"delta": 5_000_000, "kind": "topup", "note": "e2e grant"}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["balance"], 5_000_000);

        // The ledger shows the grant.
        let body = json_ok(
            admin
                .get_auth(&format!("/api/admin/v1/users/{uid}/credit/events"))
                .await
                .unwrap(),
        )
        .await;
        let events = body["data"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "topup");
        assert_eq!(events[0]["amount"], 5_000_000);
        assert_eq!(events[0]["note"], "e2e grant");

        let resp = admin
            .patch_auth(
                &format!("/api/admin/v1/users/{uid}/credit"),
                &json!({"delta": -1_000_000, "kind": "topup"}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A clawback larger than the balance is refused.
        let resp = admin
            .patch_auth(
                &format!("/api/admin/v1/users/{uid}/credit"),
                &json!({"delta": -5_000_001, "kind": "admin"}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        json_ok(
            admin
                .patch_auth(
                    &format!("/api/admin/v1/users/{uid}/credit"),
                    &json!({"delta": -1_000_000, "kind": "admin", "note": "clawback"}),
                )
                .await
                .unwrap(),
        )
        .await;

        let body = json_ok(customer.get_auth("/api/v1/account/credit").await.unwrap()).await;
        assert_eq!(body["data"]["balance"], 4_000_000);
        let body = json_ok(
            customer
                .get_auth("/api/v1/account/credit/events")
                .await
                .unwrap(),
        )
        .await;
        let amounts: Vec<i64> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["amount"].as_i64().unwrap())
            .collect();
        assert_eq!(amounts, vec![-1_000_000, 5_000_000]);
    }

    fn hold(user_id: u64, amount: u64, expires_in: i64) -> AccountCreditDebit {
        AccountCreditDebit {
            user_id,
            amount,
            currency: "BTC".to_string(),
            payment_amount: amount / 10_000,
            expires: Utc::now() + Duration::seconds(expires_in),
            ..Default::default()
        }
    }

    /// A refund to credit writes the refund row, the balance and a ledger event
    /// pointing at the row in one transaction, and a repeat with the same row
    /// id changes nothing. Also exercises `subscription_line_item.deactivated_at`.
    #[tokio::test]
    async fn mysql_refund_to_credit_is_atomic_and_once() {
        use lnvps_db::{
            LineItemType, PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionPayment,
            SubscriptionPaymentType,
        };
        let (uid, _customer) = customer().await;
        let pool = db::connect().await.unwrap();
        let db = db::lnvps_db().await.unwrap();

        let (sub_id, lines) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id: uid,
                    company_id: 1,
                    name: "refund e2e".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: true,
                    is_setup: true,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: lnvps_db::IntervalType::Hour,
                    setup_fee: 0,
                    auto_renewal_enabled: true,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: LineItemType::IpRange,
                    name: "x".to_string(),
                    description: None,
                    amount: 1,
                    setup_amount: 0,
                    configuration: None,
                    deactivated_at: None,
                    parent_line_item_id: None,
                }],
            )
            .await
            .unwrap();

        // The new column round-trips.
        let mut li = db.get_subscription_line_item(lines[0]).await.unwrap();
        assert!(li.is_active());
        li.deactivated_at = Some(Utc::now());
        db.update_subscription_line_item(&li).await.unwrap();
        assert!(
            !db.get_subscription_line_item(lines[0])
                .await
                .unwrap()
                .is_active()
        );
        // An add-on line round-trips its parent.
        let addon = db
            .insert_subscription_line_item(&SubscriptionLineItem {
                id: 0,
                subscription_id: sub_id,
                subscription_type: LineItemType::IpRange,
                name: "addon".to_string(),
                description: None,
                amount: 1,
                setup_amount: 0,
                configuration: None,
                deactivated_at: None,
                parent_line_item_id: Some(lines[0]),
            })
            .await
            .unwrap();
        assert_eq!(
            db.get_subscription_line_item(addon)
                .await
                .unwrap()
                .parent_line_item_id,
            Some(lines[0])
        );
        assert_eq!(
            db.get_subscription(sub_id).await.unwrap().interval_type,
            lnvps_db::IntervalType::Hour,
            "hour round-trips through the SMALLINT column"
        );

        let row = SubscriptionPayment {
            id: Keys::generate().public_key().to_bytes().to_vec(),
            subscription_id: sub_id,
            user_id: uid,
            created: Utc::now(),
            expires: Utc::now(),
            amount: 100,
            currency: "EUR".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Refund,
            external_data: "".into(),
            external_id: None,
            is_paid: true,
            rate: 1.0,
            time_value: None,
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
        assert!(
            db.insert_refund_to_credit(&row, 7_000, Some("e2e"))
                .await
                .unwrap()
        );
        assert!(
            !db.insert_refund_to_credit(&row, 7_000, Some("e2e"))
                .await
                .unwrap(),
            "the same refund row is not booked twice"
        );
        assert_eq!(db.get_account_credit(uid).await.unwrap().balance, 7_000);
        assert_eq!(ledger_sum(&pool, uid).await, 7_000);
        let linked: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT subscription_payment_id FROM account_credit_event WHERE user_id = ? AND kind = 'refund'",
        )
        .bind(uid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(linked, Some(row.id.clone()));
        pool.close().await;
    }

    async fn ledger_sum(pool: &sqlx::MySqlPool, user_id: u64) -> i64 {
        sqlx::query_scalar(
            "SELECT CAST(COALESCE(SUM(amount), 0) AS SIGNED) FROM account_credit_event WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn hold_on_payment(
        db: &LNVpsDbMysql,
        user_id: u64,
        amount: u64,
        expires_in: i64,
    ) -> Vec<u8> {
        let id = db
            .reserve_account_credit(&hold(user_id, amount, 3600))
            .await
            .unwrap()
            .expect("credit reserved");
        let payment: Vec<u8> = Keys::generate().public_key().to_bytes().to_vec();
        db.attach_account_credit_debit(id, &payment, Utc::now() + Duration::seconds(expires_in))
            .await
            .unwrap();
        payment
    }

    #[tokio::test]
    async fn mysql_credit_is_held_settled_once_and_balances_with_the_ledger() {
        let (uid, _customer) = customer().await;
        let pool = db::connect().await.unwrap();
        let db = db::lnvps_db().await.unwrap();
        db.adjust_account_credit(uid, 10_000_000, "topup", None)
            .await
            .unwrap();

        let payment = hold_on_payment(&db, uid, 6_000_000, 600).await;
        assert_eq!(
            db.get_account_credit_reserved(uid).await.unwrap(),
            6_000_000
        );
        assert!(
            db.reserve_account_credit(&hold(uid, 5_000_000, 600))
                .await
                .unwrap()
                .is_none(),
            "held credit is not promised twice"
        );
        assert!(
            db.adjust_account_credit(uid, -5_000_000, "admin", None)
                .await
                .is_err(),
            "a clawback cannot take held credit"
        );

        let spent = db
            .settle_account_credit_debit(&payment)
            .await
            .unwrap()
            .expect("settled");
        assert_eq!(spent.amount, 6_000_000);
        assert!(
            db.settle_account_credit_debit(&payment)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(db.get_account_credit(uid).await.unwrap().balance, 4_000_000);
        assert_eq!(db.get_account_credit_reserved(uid).await.unwrap(), 0);
        assert_eq!(ledger_sum(&pool, uid).await, 4_000_000);

        let released = db
            .reserve_account_credit(&hold(uid, 4_000_000, 600))
            .await
            .unwrap()
            .unwrap();
        db.release_account_credit_debit(released).await.unwrap();
        assert_eq!(db.get_account_credit_reserved(uid).await.unwrap(), 0);
        pool.close().await;
    }

    #[tokio::test]
    async fn mysql_a_late_settle_spends_only_unpromised_credit() {
        let (uid, _customer) = customer().await;
        let pool = db::connect().await.unwrap();
        let db = db::lnvps_db().await.unwrap();
        db.adjust_account_credit(uid, 10_000_000, "topup", None)
            .await
            .unwrap();

        let late = hold_on_payment(&db, uid, 8_000_000, -1).await;
        hold_on_payment(&db, uid, 7_000_000, 600).await;
        let spent = db
            .settle_account_credit_debit(&late)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(spent.amount, 3_000_000);
        assert_eq!(spent.payment_amount, 300);
        assert_eq!(db.get_account_credit(uid).await.unwrap().balance, 7_000_000);
        assert_eq!(ledger_sum(&pool, uid).await, 7_000_000);
        pool.close().await;
    }

    #[tokio::test]
    async fn mysql_concurrent_settles_lose_no_update() {
        let (uid, _customer) = customer().await;
        let pool = db::connect().await.unwrap();
        let db = db::lnvps_db().await.unwrap();
        db.adjust_account_credit(uid, 50_000_000, "topup", None)
            .await
            .unwrap();

        let mut payments = Vec::new();
        for _ in 0..10 {
            payments.push(hold_on_payment(&db, uid, 1_000_000, 600).await);
        }
        let mut topups = Vec::new();
        for _ in 0..10 {
            let hash: Vec<u8> = Keys::generate().public_key().to_bytes().to_vec();
            topups.push(
                db.insert_account_credit_topup(&AccountCreditTopup {
                    user_id: uid,
                    amount: 500_000,
                    currency: "BTC".to_string(),
                    invoice_hash: hash,
                    external_data: "lnbc".to_string(),
                    ..Default::default()
                })
                .await
                .unwrap(),
            );
        }

        let mut tasks = Vec::new();
        for p in payments {
            let db = db.clone();
            tasks.push(tokio::spawn(async move {
                db.settle_account_credit_debit(&p).await.unwrap();
            }));
        }
        for t in topups {
            let db = db.clone();
            tasks.push(tokio::spawn(async move {
                db.settle_account_credit_topup(t).await.unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        let balance = db.get_account_credit(uid).await.unwrap().balance;
        assert_eq!(balance, 50_000_000 - 10_000_000 + 5_000_000);
        assert_eq!(ledger_sum(&pool, uid).await, balance as i64);
        pool.close().await;
    }
}
