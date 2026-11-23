use super::*;
use crate::mocks::{MockNode, MockOnChainProvider};
use crate::payments::gateway::{
    GatewayEventOutcome, cancel_expired_gateway_payments, handle_gateway_event,
};
use crate::settings::mock_settings;
use lnvps_api_common::{
    ChannelWorkCommander, FakeGateway, GatewayEvent, MockDb, MockExchangeRate, VmStateCache,
    is_gateway_payment,
};
use lnvps_db::{
    GatewayOffSession, GatewayProviderConfig, IntervalType, LNVpsDbBase, LndConfig,
    PaymentMethodConfig, ProviderConfig,
};
use std::collections::HashMap;

const URL_A: &str = "https://gw-a.example";
const URL_B: &str = "https://gw-b.example";

struct Fixture {
    db: Arc<MockDb>,
    sub: SubscriptionHandler,
    fakes: HashMap<&'static str, Arc<FakeGateway>>,
    sub_ids: [u64; 2],
}

fn lnd_row(company: u64) -> PaymentMethodConfig {
    PaymentMethodConfig::new_with_config(
        company,
        PaymentMethod::Lightning,
        "LN".to_string(),
        true,
        ProviderConfig::Lnd(LndConfig {
            url: "https://lnd".to_string(),
            cert_path: "c".into(),
            macaroon_path: "m".into(),
        }),
    )
}

fn gateway_row(
    company: u64,
    url: &str,
    enabled: bool,
    handles: Vec<PaymentMethod>,
) -> PaymentMethodConfig {
    PaymentMethodConfig::new_with_config(
        company,
        PaymentMethod::Gateway,
        "Gateway".to_string(),
        enabled,
        ProviderConfig::Gateway(GatewayProviderConfig {
            url: url.to_string(),
            api_key: "key".to_string(),
            webhook_secret: "whsec".to_string(),
            tolerance_seconds: 300,
            off_session_renewals: GatewayOffSession::Off,
            handles,
        }),
    )
}

async fn subscription(db: &MockDb, user_id: u64, company_id: u64) -> u64 {
    db.insert_subscription_with_line_items(
        &Subscription {
            id: 0,
            user_id,
            company_id,
            name: "s".to_string(),
            description: None,
            created: Utc::now(),
            expires: None,
            is_active: true,
            is_setup: true,
            currency: "BTC".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: false,
            external_id: None,
        },
        vec![SubscriptionLineItem {
            id: 0,
            subscription_id: 0,
            subscription_type: LineItemType::IpRange,
            name: "hosting".to_string(),
            description: None,
            amount: 100_000,
            setup_amount: 0,
            configuration: None,
            deactivated_at: None,
            parent_line_item_id: None,
        }],
    )
    .await
    .unwrap()
    .0
}

async fn fixture() -> Fixture {
    let db = Arc::new(MockDb::default());
    let user_id = db.upsert_user(&[41u8; 32]).await.unwrap();
    db.insert_payment_method_config(&lnd_row(1)).await.unwrap();
    db.insert_payment_method_config(&lnd_row(2)).await.unwrap();
    let sub_ids = [
        subscription(&db, user_id, 1).await,
        subscription(&db, user_id, 2).await,
    ];
    let fakes: HashMap<&'static str, Arc<FakeGateway>> = [
        (URL_A, Arc::new(FakeGateway::default())),
        (URL_B, Arc::new(FakeGateway::default())),
    ]
    .into_iter()
    .collect();
    let by_url = fakes.clone();
    let sub = SubscriptionHandler::new(
        mock_settings(),
        db.clone(),
        Arc::new(MockNode::default()),
        Arc::new(MockOnChainProvider::default()),
        None,
        Arc::new(MockExchangeRate::default()),
        VatClient::new(),
        Arc::new(ChannelWorkCommander::new()),
        VmStateCache::new(),
    )
    .unwrap()
    .with_gateway_factory(Arc::new(move |c| {
        by_url.get(c.url.as_str()).cloned().unwrap() as Arc<dyn PaymentGateway>
    }));
    Fixture {
        db,
        sub,
        fakes,
        sub_ids,
    }
}

async fn renew_lightning(f: &Fixture, company_index: usize) -> Result<SubscriptionPayment> {
    f.sub
        .renew_subscription(f.sub_ids[company_index], PaymentMethod::Lightning, 1)
        .await
}

fn created(f: &Fixture, url: &str) -> usize {
    f.fakes[url].created.lock().unwrap().len()
}

fn paid_event(payment: &SubscriptionPayment) -> GatewayEvent {
    GatewayEvent {
        event_id: "ev1".into(),
        kind: "payment.paid".into(),
        reference: hex::encode(&payment.id),
        status: "paid".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn enabled_row_that_handles_lightning_creates_the_invoice_on_the_gateway() {
    let f = fixture().await;
    f.db.insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::Lightning]))
        .await
        .unwrap();

    let payment = renew_lightning(&f, 0).await.unwrap();

    assert!(is_gateway_payment(payment.external_id.as_deref()));
    assert_eq!(created(&f, URL_A), 1);
}

#[tokio::test]
async fn disabled_row_keeps_new_payments_in_process() {
    let f = fixture().await;
    f.db.insert_payment_method_config(&gateway_row(
        1,
        URL_A,
        false,
        vec![PaymentMethod::Lightning],
    ))
    .await
    .unwrap();

    let payment = renew_lightning(&f, 0).await.unwrap();

    assert!(!is_gateway_payment(payment.external_id.as_deref()));
    assert_eq!(created(&f, URL_A), 0);
}

#[tokio::test]
async fn method_missing_from_handles_stays_in_process() {
    let f = fixture().await;
    f.db.insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::OnChain]))
        .await
        .unwrap();

    let payment = renew_lightning(&f, 0).await.unwrap();

    assert!(!is_gateway_payment(payment.external_id.as_deref()));
    assert_eq!(created(&f, URL_A), 0);
}

#[tokio::test]
async fn only_the_company_with_a_row_goes_through_the_gateway() {
    let f = fixture().await;
    f.db.insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::Lightning]))
        .await
        .unwrap();

    let on_gateway = renew_lightning(&f, 0).await.unwrap();
    let in_process = renew_lightning(&f, 1).await.unwrap();

    assert!(is_gateway_payment(on_gateway.external_id.as_deref()));
    assert!(!is_gateway_payment(in_process.external_id.as_deref()));
    assert_eq!(created(&f, URL_A), 1);
    assert_eq!(created(&f, URL_B), 0);
}

#[tokio::test]
async fn each_company_uses_the_gateway_of_its_own_row() {
    let f = fixture().await;
    for (company, url) in [(1, URL_A), (2, URL_B)] {
        f.db.insert_payment_method_config(&gateway_row(
            company,
            url,
            true,
            vec![PaymentMethod::Lightning],
        ))
        .await
        .unwrap();
    }

    renew_lightning(&f, 0).await.unwrap();
    renew_lightning(&f, 1).await.unwrap();

    assert_eq!(created(&f, URL_A), 1);
    assert_eq!(created(&f, URL_B), 1);
}

#[tokio::test]
async fn a_row_wins_over_the_yaml_gateway() {
    let f = fixture().await;
    let yaml = Arc::new(FakeGateway::default());
    let sub = f.sub.clone().with_lightning_gateway(yaml.clone());
    f.db.insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::Lightning]))
        .await
        .unwrap();

    let payment = sub
        .renew_subscription(f.sub_ids[0], PaymentMethod::Lightning, 1)
        .await
        .unwrap();

    assert!(is_gateway_payment(payment.external_id.as_deref()));
    assert_eq!(created(&f, URL_A), 1);
    assert!(yaml.created.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_disabled_row_also_overrides_the_yaml_gateway() {
    let f = fixture().await;
    let yaml = Arc::new(FakeGateway::default());
    let sub = f.sub.clone().with_lightning_gateway(yaml.clone());
    f.db.insert_payment_method_config(&gateway_row(
        1,
        URL_A,
        false,
        vec![PaymentMethod::Lightning],
    ))
    .await
    .unwrap();

    let payment = sub
        .renew_subscription(f.sub_ids[0], PaymentMethod::Lightning, 1)
        .await
        .unwrap();

    assert!(!is_gateway_payment(payment.external_id.as_deref()));
    assert!(yaml.created.lock().unwrap().is_empty());
}

#[tokio::test]
async fn yaml_gateway_still_serves_a_company_without_a_row() {
    let f = fixture().await;
    let yaml = Arc::new(FakeGateway::default());
    let sub = f.sub.clone().with_lightning_gateway(yaml.clone());

    let payment = sub
        .renew_subscription(f.sub_ids[1], PaymentMethod::Lightning, 1)
        .await
        .unwrap();

    assert!(is_gateway_payment(payment.external_id.as_deref()));
    assert_eq!(yaml.created.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn in_flight_payment_settles_once_after_the_row_is_disabled() {
    let f = fixture().await;
    let row_id = f
        .db
        .insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::Lightning]))
        .await
        .unwrap();
    let payment = renew_lightning(&f, 0).await.unwrap();
    let mut row = f.db.get_payment_method_config(row_id).await.unwrap();
    row.enabled = false;
    f.db.update_payment_method_config(&row).await.unwrap();
    let db: Arc<dyn LNVpsDb> = f.db.clone();

    let _ = renew_lightning(&f, 0).await;
    assert_eq!(
        created(&f, URL_A),
        1,
        "a new payment must not reach the disabled gateway"
    );

    let event = paid_event(&payment);
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &event).await.unwrap(),
        GatewayEventOutcome::Settled
    );
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &event).await.unwrap(),
        GatewayEventOutcome::AlreadySettled
    );
}

#[tokio::test]
async fn expired_in_flight_payment_is_cancelled_on_its_own_gateway_after_disable() {
    let f = fixture().await;
    let row_id = f
        .db
        .insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::Lightning]))
        .await
        .unwrap();
    let mut payment = renew_lightning(&f, 0).await.unwrap();
    payment.expires = Utc::now() - chrono::Duration::seconds(5);
    f.db.update_subscription_payment(&payment).await.unwrap();
    let mut row = f.db.get_payment_method_config(row_id).await.unwrap();
    row.enabled = false;
    f.db.update_payment_method_config(&row).await.unwrap();
    let db: Arc<dyn LNVpsDb> = f.db.clone();

    let cancelled = cancel_expired_gateway_payments(&db, &f.sub).await.unwrap();

    assert_eq!(cancelled, 1);
    assert_eq!(f.fakes[URL_A].cancelled.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn gateway_failure_fails_the_renewal_without_a_payment_row() {
    let f = fixture().await;
    f.db.insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::Lightning]))
        .await
        .unwrap();
    *f.fakes[URL_A].fail.lock().unwrap() = true;
    let before =
        f.db.list_subscription_payments(f.sub_ids[0])
            .await
            .unwrap()
            .len();

    assert!(renew_lightning(&f, 0).await.is_err());

    assert_eq!(
        f.db.list_subscription_payments(f.sub_ids[0])
            .await
            .unwrap()
            .len(),
        before
    );
}

#[tokio::test]
async fn onchain_follows_the_row_handles_too() {
    let f = fixture().await;
    f.db.insert_payment_method_config(&gateway_row(1, URL_A, true, vec![PaymentMethod::OnChain]))
        .await
        .unwrap();
    let mut onchain = lnd_row(1);
    onchain.payment_method = PaymentMethod::OnChain;
    onchain.provider_type = "onchain".to_string();
    onchain.config = Some(serde_json::json!({
        "type": "onchain",
        "url": "https://lnd:10009",
        "cert_path": "c",
        "macaroon_path": "m"
    }));
    f.db.insert_payment_method_config(&onchain).await.unwrap();

    let payment = f
        .sub
        .renew_subscription(f.sub_ids[0], PaymentMethod::OnChain, 1)
        .await
        .unwrap();

    assert!(is_gateway_payment(payment.external_id.as_deref()));
    assert_eq!(f.fakes[URL_A].crypto.lock().unwrap().len(), 1);
}
