use super::*;
use crate::mocks::{MockNode, MockOnChainProvider, MockSwapProvider};
use crate::payments::gateway::{GatewayEventOutcome, handle_gateway_event};
use crate::settings::mock_settings;
use lnvps_api_common::{
    ChannelWorkCommander, FakeGateway, GatewayEvent, MockDb, MockExchangeRate, VmStateCache,
    is_gateway_payment,
};
use lnvps_db::{
    CommaSeparated, FixedFloatProviderConfig, IntervalType, LNVpsDbBase, PaymentMethodConfig,
    ProviderConfig,
};

struct Fixture {
    db: Arc<MockDb>,
    sub: SubscriptionHandler,
    fake: Arc<FakeGateway>,
    onchain: Arc<MockOnChainProvider>,
    swap: Arc<MockSwapProvider>,
    sub_id: u64,
    user_id: u64,
}

async fn fixture() -> Fixture {
    let db = Arc::new(MockDb::default());
    let onchain = Arc::new(MockOnChainProvider::default());
    let swap = Arc::new(MockSwapProvider::default());
    let fake = Arc::new(FakeGateway::default());
    let user_id = db.upsert_user(&[31u8; 32]).await.unwrap();
    let mut config = PaymentMethodConfig::new_with_config(
        1,
        PaymentMethod::FixedFloat,
        "FixedFloat".to_string(),
        true,
        ProviderConfig::FixedFloat(FixedFloatProviderConfig {
            api_key: "k".to_string(),
            api_secret: "s".to_string(),
            url: None,
            refcode: None,
            afftax: None,
        }),
    );
    config.supported_currencies = CommaSeparated::new(vec!["XMR".to_string()]);
    db.insert_payment_method_config(&config).await.unwrap();
    let (sub_id, _) = db
        .insert_subscription_with_line_items(
            &Subscription {
                id: 0,
                user_id,
                company_id: 1,
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
        .unwrap();
    let sub = SubscriptionHandler::new(
        mock_settings(),
        db.clone(),
        Arc::new(MockNode::default()),
        onchain.clone(),
        None,
        Arc::new(MockExchangeRate::default()),
        VatClient::new(),
        Arc::new(ChannelWorkCommander::new()),
        VmStateCache::new(),
    )
    .unwrap()
    .with_swap(Some(swap.clone() as Arc<dyn SwapProvider>))
    .with_onchain_gateway(fake.clone())
    .with_swap_gateway(fake.clone());
    Fixture {
        db,
        sub,
        fake,
        onchain,
        swap,
        sub_id,
        user_id,
    }
}

#[tokio::test]
async fn onchain_renewal_takes_its_address_from_the_gateway() {
    let f = fixture().await;
    let payment = f
        .sub
        .renew_subscription(f.sub_id, PaymentMethod::OnChain, 1)
        .await
        .unwrap();

    assert!(is_gateway_payment(payment.external_id.as_deref()));
    assert!(payment.external_data.as_str().starts_with("bc1qfake"));
    assert!(f.onchain.addresses.lock().await.is_empty());
    let requests = f.fake.crypto.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].payment_id, payment.id);
    assert_eq!(requests[0].customer_ref, f.user_id.to_string());
    assert_eq!(requests[0].metadata["subscription_id"], f.sub_id);
    assert_eq!(requests[0].coin, None);
}

#[tokio::test]
async fn onchain_renewal_without_a_gateway_still_uses_the_node_wallet() {
    let f = fixture().await;
    let sub = SubscriptionHandler::new(
        mock_settings(),
        f.db.clone(),
        Arc::new(MockNode::default()),
        f.onchain.clone(),
        None,
        Arc::new(MockExchangeRate::default()),
        VatClient::new(),
        Arc::new(ChannelWorkCommander::new()),
        VmStateCache::new(),
    )
    .unwrap();
    let payment = sub
        .renew_subscription(f.sub_id, PaymentMethod::OnChain, 1)
        .await
        .unwrap();
    assert_eq!(payment.external_id, None);
    assert_eq!(f.onchain.addresses.lock().await.len(), 1);
    assert!(f.fake.crypto.lock().unwrap().is_empty());
}

#[tokio::test]
async fn gateway_failure_fails_the_onchain_renewal_without_a_row() {
    let f = fixture().await;
    *f.fake.fail.lock().unwrap() = true;
    let before =
        f.db.list_subscription_payments(f.sub_id)
            .await
            .unwrap()
            .len();
    assert!(
        f.sub
            .renew_subscription(f.sub_id, PaymentMethod::OnChain, 1)
            .await
            .is_err()
    );
    assert_eq!(
        f.db.list_subscription_payments(f.sub_id)
            .await
            .unwrap()
            .len(),
        before
    );
}

#[tokio::test]
async fn fixedfloat_renewal_creates_the_swap_through_the_gateway() {
    let f = fixture().await;
    let payment = f
        .sub
        .renew_subscription_with_mode(
            f.sub_id,
            PaymentMethod::FixedFloat,
            1,
            RenewMode::FixedFloat {
                coin: Currency::XMR,
            },
        )
        .await
        .unwrap();

    assert!(is_gateway_payment(payment.external_id.as_deref()));
    let data = crate::swap::SwapData::parse(payment.external_data.as_str()).unwrap();
    assert_eq!(data.coin, "XMR");
    assert!(data.deposit_address.starts_with("4fakedeposit"));
    assert!(f.swap.requests.lock().await.is_empty());
    assert!(f.onchain.addresses.lock().await.is_empty());
    let requests = f.fake.crypto.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].coin.as_deref(), Some("XMR"));
}

#[tokio::test]
async fn fixedfloat_gateway_still_enforces_the_company_coin_list() {
    let f = fixture().await;
    let err = f
        .sub
        .renew_subscription_with_mode(
            f.sub_id,
            PaymentMethod::FixedFloat,
            1,
            RenewMode::FixedFloat {
                coin: Currency::LTC,
            },
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not accepted"), "{err}");
    assert!(f.fake.crypto.lock().unwrap().is_empty());
}

#[tokio::test]
async fn gateway_paid_event_settles_an_onchain_payment_once() {
    let f = fixture().await;
    let payment = f
        .sub
        .renew_subscription(f.sub_id, PaymentMethod::OnChain, 1)
        .await
        .unwrap();
    let db: Arc<dyn LNVpsDb> = f.db.clone();
    let event = GatewayEvent {
        event_id: "e1".into(),
        kind: "payment.paid".into(),
        reference: hex::encode(&payment.id),
        status: "paid".into(),
        ..Default::default()
    };
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &event).await.unwrap(),
        GatewayEventOutcome::Settled
    );
    assert!(
        f.db.get_subscription_payment(&payment.id)
            .await
            .unwrap()
            .is_paid
    );
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &event).await.unwrap(),
        GatewayEventOutcome::AlreadySettled
    );
}

#[tokio::test]
async fn credit_topups_take_address_and_swap_from_the_gateway() {
    let f = fixture().await;
    let reference = [9u8; 32];
    let mut onchain_config = f.db.list_payment_method_configs().await.unwrap().remove(0);
    onchain_config.id = 0;
    onchain_config.payment_method = PaymentMethod::OnChain;
    f.db.insert_payment_method_config(&onchain_config)
        .await
        .unwrap();
    let created = f
        .sub
        .new_credit_topup_address(f.user_id, reference, 1_000_000)
        .await
        .unwrap();
    assert!(is_gateway_payment(created.external_id.as_deref()));
    assert!(created.address.starts_with("bc1qfake"));

    let order = f
        .sub
        .new_credit_topup_swap(f.user_id, reference, Currency::XMR, 1_000_000)
        .await
        .unwrap();
    assert!(is_gateway_payment(order.external_id.as_deref()));

    let requests = f.fake.crypto.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].payment_id, reference.to_vec());
    assert_eq!(requests[0].metadata["payment_type"], "credit_topup");
    assert_eq!(requests[0].customer_ref, f.user_id.to_string());
}

#[tokio::test]
async fn gateway_paid_event_settles_a_fixedfloat_swap_once_and_unpaid_swaps_stay_unpaid() {
    let f = fixture().await;
    let payment = f
        .sub
        .renew_subscription_with_mode(
            f.sub_id,
            PaymentMethod::FixedFloat,
            1,
            RenewMode::FixedFloat {
                coin: Currency::XMR,
            },
        )
        .await
        .unwrap();
    let db: Arc<dyn LNVpsDb> = f.db.clone();
    let reference = hex::encode(&payment.id);

    let underpaid = GatewayEvent {
        event_id: "u1".into(),
        kind: "attempt.failed".into(),
        reference: reference.clone(),
        status: "pending".into(),
        reason: Some("underpaid".into()),
        ..Default::default()
    };
    handle_gateway_event(&db, &f.sub, &underpaid).await.unwrap();
    assert!(
        !f.db
            .get_subscription_payment(&payment.id)
            .await
            .unwrap()
            .is_paid
    );

    let fresh = f
        .sub
        .renew_subscription_with_mode(
            f.sub_id,
            PaymentMethod::FixedFloat,
            1,
            RenewMode::FixedFloat {
                coin: Currency::XMR,
            },
        )
        .await
        .unwrap();
    let paid = GatewayEvent {
        event_id: "p1".into(),
        kind: "payment.paid".into(),
        reference: hex::encode(&fresh.id),
        status: "paid".into(),
        ..Default::default()
    };
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &paid).await.unwrap(),
        GatewayEventOutcome::Settled
    );
    let expiry = f.db.get_subscription(f.sub_id).await.unwrap().expires;
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &paid).await.unwrap(),
        GatewayEventOutcome::AlreadySettled
    );
    assert_eq!(
        f.db.get_subscription(f.sub_id).await.unwrap().expires,
        expiry
    );
}

#[tokio::test]
async fn the_node_watcher_ignores_a_deposit_to_a_gateway_address() {
    let f = fixture().await;
    let payment = f
        .sub
        .renew_subscription(f.sub_id, PaymentMethod::OnChain, 1)
        .await
        .unwrap();
    let handler = crate::payments::onchain::OnChainPaymentHandler::new(
        f.onchain.clone(),
        f.db.clone(),
        f.sub.clone(),
    );
    handler
        .handle_deposit(payment.external_data.as_str(), "tx1", 0, 5_000_000)
        .await
        .unwrap();
    assert!(
        !f.db
            .get_subscription_payment(&payment.id)
            .await
            .unwrap()
            .is_paid
    );
}

#[tokio::test]
async fn gateway_paid_event_settles_a_credit_topup_once() {
    let f = fixture().await;
    let reference = [7u8; 32];
    f.db.insert_account_credit_topup(&lnvps_db::AccountCreditTopup {
        user_id: f.user_id,
        amount: 5_000_000,
        currency: "BTC".to_string(),
        payment_method: PaymentMethod::OnChain,
        invoice_hash: reference.to_vec(),
        external_data: "bc1qfake".to_string(),
        external_id: Some("pgw:abc".to_string()),
        ..Default::default()
    })
    .await
    .unwrap();
    let db: Arc<dyn LNVpsDb> = f.db.clone();
    let event = GatewayEvent {
        event_id: "e2".into(),
        kind: "payment.paid".into(),
        reference: hex::encode(reference),
        status: "paid".into(),
        ..Default::default()
    };
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &event).await.unwrap(),
        GatewayEventOutcome::Settled
    );
    assert_eq!(
        handle_gateway_event(&db, &f.sub, &event).await.unwrap(),
        GatewayEventOutcome::AlreadySettled
    );
    let topups =
        f.db.list_account_credit_topups_by_method(PaymentMethod::OnChain)
            .await
            .unwrap();
    assert!(topups[0].is_paid);
}
