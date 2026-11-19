use super::*;
use chrono::Utc;
use std::sync::Arc;
use lnvps_db::LNVpsDbBase;

fn total(
    currency: &str,
    payment_type: ApiSubscriptionPaymentType,
    count: u64,
    amount: u64,
) -> AdminPaymentTotal {
    AdminPaymentTotal {
        currency: currency.to_string(),
        payment_type,
        count,
        amount,
        tax: 0,
    }
}

fn refund(
    currency: &str,
    amount: u64,
    destination: AdminRefundDestination,
    before_window: bool,
) -> AdminActivityRefund {
    AdminActivityRefund {
        id: "00".to_string(),
        subscription_id: 1,
        user_id: 1,
        currency: currency.to_string(),
        amount,
        tax: 0,
        gross: amount,
        refunded_at: Utc::now(),
        destination,
        credit_returned: BTreeMap::new(),
        original_payment_id: None,
        original_paid_at: None,
        original_before_window: before_window,
    }
}

#[test]
fn credit_refunds_of_older_payments_do_not_produce_a_bare_negative_net() {
    let totals = vec![
        total("EUR", ApiSubscriptionPaymentType::Purchase, 3, 10_795),
        total("EUR", ApiSubscriptionPaymentType::Refund, 8, 16_150),
    ];
    let refunds = vec![
        refund("BTC", 75_386_859, AdminRefundDestination::Credit, true),
        refund("EUR", 16_150, AdminRefundDestination::Credit, true),
    ];

    let summaries = summarise_currencies(&totals, &refunds);

    let eur = summaries.iter().find(|s| s.currency == "EUR").unwrap();
    assert_eq!(eur.revenue, 10_795);
    assert_eq!(eur.credit_refunds, 16_150);
    assert_eq!(eur.cash_refunds, 0);
    assert_eq!(eur.refunds_of_earlier_payments, 16_150);
    assert_eq!(eur.net, Some(10_795));
    assert!(eur.net_note.as_deref().unwrap().contains("credit"));

    let btc = summaries.iter().find(|s| s.currency == "BTC").unwrap();
    assert_eq!(btc.revenue, 0);
    assert_eq!(btc.credit_refunds, 75_386_859);
    assert_eq!(btc.net, Some(0));
    assert!(btc.net_note.is_some());
}

#[test]
fn cash_refunds_of_older_payments_hide_net_and_explain() {
    let totals = vec![total(
        "EUR",
        ApiSubscriptionPaymentType::Purchase,
        3,
        10_795,
    )];
    let refunds = vec![refund("EUR", 16_150, AdminRefundDestination::Cash, true)];

    let eur = &summarise_currencies(&totals, &refunds)[0];

    assert_eq!(eur.cash_refunds, 16_150);
    assert_eq!(eur.net, None);
    assert!(
        eur.net_note
            .as_deref()
            .unwrap()
            .contains("before this window")
    );
}

#[test]
fn cash_refunds_of_payments_in_window_are_netted() {
    let totals = vec![total("EUR", ApiSubscriptionPaymentType::Purchase, 1, 1_000)];
    let refunds = vec![refund("EUR", 400, AdminRefundDestination::Cash, false)];

    let eur = &summarise_currencies(&totals, &refunds)[0];

    assert_eq!(eur.net, Some(600));
    assert_eq!(eur.net_note, None);
}

#[tokio::test]
async fn activity_refund_reports_original_date_and_credit_destination() {
    let db: Arc<dyn LNVpsDb> = Arc::new(lnvps_api_common::MockDb::default());
    let now = Utc::now();
    let original_at = now - Duration::days(20);
    let mut original = super::tests::payment(
        7,
        1,
        100,
        lnvps_db::SubscriptionPaymentType::Purchase,
        Some(original_at),
    );
    original.id = vec![7u8; 32];
    original.created = original_at;
    db.insert_subscription_payment(&original).await.unwrap();
    let mut row = super::tests::payment(
        8,
        1,
        100,
        lnvps_db::SubscriptionPaymentType::Refund,
        Some(now),
    );
    row.refunded_payment_id = Some(original.id.clone());
    row.metadata = Some(serde_json::json!({"refund": {"returned_as_credit": {"BTC": 5000}}}));

    let out = activity_refund(&db, row, now - Duration::days(7)).await;

    assert_eq!(out.destination, AdminRefundDestination::Credit);
    assert_eq!(out.credit_returned["BTC"], 5000);
    assert_eq!(out.original_paid_at, Some(original_at));
    assert!(out.original_before_window);
}
