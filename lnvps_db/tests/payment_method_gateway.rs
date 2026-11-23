use lnvps_db::{
    IntervalType, LNVpsDbBase, LNVpsDbMysql, LineItemType, PaymentMethod, Subscription,
    SubscriptionLineItem, SubscriptionPayment, SubscriptionPaymentType, UserPaymentMethod,
};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

async fn db(name: &str) -> Option<LNVpsDbMysql> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute(format!("DROP DATABASE IF EXISTS {name}").as_str())
        .await
        .unwrap();
    pool.execute(format!("CREATE DATABASE {name}").as_str())
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/{name}")).await.unwrap();
    db.migrate().await.unwrap();
    Some(db)
}

fn card(user_id: u64, gateway_method_id: Option<u64>) -> UserPaymentMethod {
    UserPaymentMethod {
        user_id,
        provider: "stripe".into(),
        external_id: "pm_1".to_string().into(),
        external_customer_id: Some("cus_1".to_string().into()),
        gateway_method_id,
        enabled: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn gateway_method_id_round_trips_and_defaults_to_none() {
    let Some(db) = db("pm_gateway_roundtrip").await else {
        return;
    };
    let user = db.upsert_user(&[9u8; 32]).await.unwrap();
    let plain = db
        .insert_user_payment_method(&card(user, None))
        .await
        .unwrap();
    let linked = db
        .insert_user_payment_method(&card(user, Some(42)))
        .await
        .unwrap();
    assert_eq!(
        db.get_user_payment_method(plain)
            .await
            .unwrap()
            .gateway_method_id,
        None
    );
    assert_eq!(
        db.get_user_payment_method(linked)
            .await
            .unwrap()
            .gateway_method_id,
        Some(42)
    );

    let mut m = db.get_user_payment_method(plain).await.unwrap();
    m.gateway_method_id = Some(7);
    db.update_user_payment_method(&m).await.unwrap();
    assert_eq!(
        db.get_user_payment_method(plain)
            .await
            .unwrap()
            .gateway_method_id,
        Some(7)
    );
}

fn gateway_payment(
    id: u8,
    subscription_id: u64,
    user_id: u64,
    external_id: Option<&str>,
    is_paid: bool,
    expires_in_minutes: i64,
) -> SubscriptionPayment {
    let now = chrono::Utc::now();
    SubscriptionPayment {
        id: vec![id; 32],
        subscription_id,
        user_id,
        created: now,
        expires: now + chrono::Duration::minutes(expires_in_minutes),
        amount: 1000,
        currency: "EUR".to_string(),
        payment_method: PaymentMethod::Stripe,
        payment_type: SubscriptionPaymentType::Renewal,
        external_data: "{}".to_string().into(),
        external_id: external_id.map(str::to_string),
        is_paid,
        rate: 1.0,
        time_value: Some(60),
        metadata: None,
        tax: 0,
        processing_fee: 0,
        paid_at: None,
        tax_rate: None,
        tax_country_code: None,
        tax_treatment: None,
        tax_evidence: None,
        tax_breakdown: None,
        refunded_payment_id: None,
        renewal_source: None,
    }
}

#[tokio::test]
async fn expired_unpaid_gateway_payments_are_listed_and_nothing_else() {
    let Some(db) = db("pm_gateway_expiry").await else {
        return;
    };
    let user = db.upsert_user(&[8u8; 32]).await.unwrap();
    let (sub_id, _) = db
        .insert_subscription_with_line_items(
            &Subscription {
                id: 0,
                user_id: user,
                company_id: 1,
                name: "s".to_string(),
                description: None,
                created: chrono::Utc::now(),
                expires: None,
                is_active: false,
                is_setup: false,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: false,
                external_id: None,
            },
            vec![SubscriptionLineItem {
                id: 0,
                subscription_id: 0,
                subscription_type: LineItemType::Vps,
                name: "vm".to_string(),
                description: None,
                amount: 1000,
                setup_amount: 0,
                configuration: None,
                deactivated_at: None,
                parent_line_item_id: None,
            }],
        )
        .await
        .unwrap();
    for p in [
        gateway_payment(1, sub_id, user, Some("pgw:a"), false, -5),
        gateway_payment(2, sub_id, user, Some("pgw:b"), true, -5),
        gateway_payment(3, sub_id, user, Some("pgw:c"), false, 30),
        gateway_payment(4, sub_id, user, Some("in_process"), false, -5),
        gateway_payment(5, sub_id, user, None, false, -5),
        gateway_payment(6, sub_id, user, Some("pgw-cancelled:d"), false, -5),
    ] {
        db.insert_subscription_payment(&p).await.unwrap();
    }
    let listed = db
        .list_expired_unpaid_gateway_payments(chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, vec![1u8; 32]);
}

#[tokio::test]
async fn gateway_row_round_trips_and_payment_stats_count_only_that_company() {
    use lnvps_db::{
        GatewayOffSession, GatewayProviderConfig, LNVpsDbBase as _, PaymentMethodConfig,
        ProviderConfig,
    };
    let Some(db) = db("pm_gateway_row").await else {
        return;
    };
    let row = PaymentMethodConfig::new_with_config(
        1,
        PaymentMethod::Gateway,
        "Gateway".to_string(),
        false,
        ProviderConfig::Gateway(GatewayProviderConfig {
            url: "https://pay.example".to_string(),
            api_key: "k".to_string(),
            webhook_secret: "s".to_string(),
            tolerance_seconds: 300,
            off_session_renewals: GatewayOffSession::DryRun,
            handles: vec![PaymentMethod::Lightning, PaymentMethod::Stripe],
        }),
    );
    let id = db.insert_payment_method_config(&row).await.unwrap();
    let stored = db.get_payment_method_config(id).await.unwrap();
    assert_eq!(stored.payment_method, PaymentMethod::Gateway);
    assert_eq!(stored.provider_type, "gateway");
    assert!(!stored.enabled);
    let cfg = stored.get_provider_config().unwrap();
    let gw = cfg.as_gateway().unwrap();
    assert_eq!(gw.off_session_renewals, GatewayOffSession::DryRun);
    assert_eq!(
        gw.handles,
        vec![PaymentMethod::Lightning, PaymentMethod::Stripe]
    );

    let user = db.upsert_user(&[9u8; 32]).await.unwrap();
    let (sub_id, _) = db
        .insert_subscription_with_line_items(
            &Subscription {
                id: 0,
                user_id: user,
                company_id: 1,
                name: "s".to_string(),
                description: None,
                created: chrono::Utc::now(),
                expires: None,
                is_active: true,
                is_setup: false,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: false,
                external_id: None,
            },
            vec![SubscriptionLineItem {
                id: 0,
                subscription_id: 0,
                subscription_type: LineItemType::Vps,
                name: "vm".to_string(),
                description: None,
                amount: 1000,
                setup_amount: 0,
                configuration: None,
                deactivated_at: None,
                parent_line_item_id: None,
            }],
        )
        .await
        .unwrap();
    let mut paid = gateway_payment(1, sub_id, user, Some("pgw:a"), true, 10);
    paid.paid_at = Some(chrono::Utc::now());
    for p in [
        paid,
        gateway_payment(2, sub_id, user, Some("pgw:b"), false, 10),
        gateway_payment(3, sub_id, user, Some("in_process"), false, 10),
    ] {
        db.insert_subscription_payment(&p).await.unwrap();
    }
    let since = chrono::Utc::now() - chrono::Duration::hours(24);
    let (count, last) = db.gateway_payment_stats(1, since).await.unwrap();
    assert_eq!(count, 2);
    assert!(last.is_some());
    let (other, none) = db.gateway_payment_stats(2, since).await.unwrap();
    assert_eq!(other, 0);
    assert!(none.is_none());
}
