use super::*;
use crate::api::model::ApiSubscriptionPayment;
use crate::mocks::{MockNode, MockOnChainProvider, MockSwapProvider};
use crate::settings::mock_settings;
use lnvps_api_common::{ChannelWorkCommander, FakeGateway, MockDb, MockExchangeRate, VmStateCache};
use lnvps_db::{
    CommaSeparated, FixedFloatProviderConfig, IntervalType, LNVpsDbBase, PaymentMethodConfig,
    ProviderConfig,
};
use payments_rs::fiat::{FiatPaymentInfo, LineItem};
use serde_json::{Value, json};
use std::future::Future;
use std::pin::Pin;

const GATEWAY_HOST: &str = "gw.example";

struct CardFiat;

impl FiatPaymentService for CardFiat {
    fn create_order(
        &self,
        _d: &str,
        _amount: CurrencyAmount,
        _li: Option<Vec<LineItem>>,
    ) -> Pin<Box<dyn Future<Output = Result<FiatPaymentInfo>> + Send>> {
        Box::pin(async {
            Ok(FiatPaymentInfo {
                external_id: "order_1".to_string(),
                raw_data: r#"{"token":"inproc-token"}"#.to_string(),
            })
        })
    }

    fn cancel_order(&self, _id: &str) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async { Ok(()) })
    }
}

struct World {
    sub: SubscriptionHandler,
    sub_id: u64,
    fake: Arc<FakeGateway>,
    db: Arc<MockDb>,
}

async fn world(through_gateway: bool) -> World {
    let db = Arc::new(MockDb::default());
    let user_id = db.upsert_user(&[77u8; 32]).await.unwrap();
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
                subscription_type: LineItemType::IpRange,
                name: "hosting".to_string(),
                description: None,
                amount: 1_000,
                setup_amount: 0,
                configuration: None,
                deactivated_at: None,
                parent_line_item_id: None,
            }],
        )
        .await
        .unwrap();
    let rates = Arc::new(MockExchangeRate::default());
    rates
        .set_rate(
            lnvps_api_common::Ticker::btc_rate("EUR").unwrap(),
            100_000.0,
        )
        .await;
    let fake = Arc::new(FakeGateway::default());
    let mut sub = SubscriptionHandler::new(
        mock_settings(),
        db.clone(),
        Arc::new(MockNode::default()),
        Arc::new(MockOnChainProvider::default()),
        Some(Arc::new(CardFiat)),
        rates,
        VatClient::new(),
        Arc::new(ChannelWorkCommander::new()),
        VmStateCache::new(),
    )
    .unwrap()
    .with_swap(Some(
        Arc::new(MockSwapProvider::default()) as Arc<dyn SwapProvider>
    ));
    sub.set_settle_timeout_for_test(Duration::ZERO);
    if through_gateway {
        sub = sub
            .with_lightning_gateway(fake.clone())
            .with_onchain_gateway(fake.clone())
            .with_swap_gateway(fake.clone())
            .with_card_gateway(fake.clone());
    }
    World {
        sub,
        sub_id,
        fake,
        db,
    }
}

async fn customer_json(
    w: &World,
    method: PaymentMethod,
    mode: RenewMode,
) -> Result<(Value, SubscriptionPayment)> {
    let payment = w
        .sub
        .renew_subscription_with_mode(w.sub_id, method, 1, mode)
        .await?;
    let json = serde_json::to_value(ApiSubscriptionPayment::from(payment.clone()))?;
    Ok((json, payment))
}

fn strip_volatile(mut v: Value) -> Value {
    let obj = v.as_object_mut().unwrap();
    for k in ["id", "created", "expires", "paid_at"] {
        obj.remove(k);
    }
    v
}

fn shape(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), shape(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(shape).collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        Value::Null => Value::Null,
    }
}

fn non_data(v: &Value) -> Value {
    let mut v = strip_volatile(v.clone());
    v.as_object_mut().unwrap().remove("data");
    v
}

fn assert_identical_contract(in_process: &Value, gateway: &Value) {
    assert_eq!(non_data(in_process), non_data(gateway));
    assert_eq!(shape(&in_process["data"]), shape(&gateway["data"]));
}

async fn both(method: PaymentMethod, mode: impl Fn() -> RenewMode) -> (Value, Value) {
    let a = world(false).await;
    let b = world(true).await;
    let (in_process, p1) = customer_json(&a, method, mode()).await.unwrap();
    let (gateway, p2) = customer_json(&b, method, mode()).await.unwrap();
    assert!(!lnvps_api_common::is_gateway_payment(
        p1.external_id.as_deref()
    ));
    assert!(lnvps_api_common::is_gateway_payment(
        p2.external_id.as_deref()
    ));
    assert_eq!(
        p1.expires - p1.created > chrono::Duration::zero(),
        p2.expires - p2.created > chrono::Duration::zero()
    );
    (in_process, gateway)
}

#[tokio::test]
async fn lightning_looks_the_same_through_the_gateway() {
    let (a, b) = both(PaymentMethod::Lightning, RenewMode::default).await;
    assert_identical_contract(&a, &b);
    assert!(b["data"]["lightning"].is_string());
}

#[tokio::test]
async fn onchain_looks_the_same_through_the_gateway() {
    let (a, b) = both(PaymentMethod::OnChain, RenewMode::default).await;
    assert_identical_contract(&a, &b);
    assert!(b["data"]["onchain"]["address"].is_string());
    assert!(b["data"]["onchain"].get("outpoint").is_none());
}

#[tokio::test]
async fn fixedfloat_looks_the_same_through_the_gateway() {
    let (a, b) = both(PaymentMethod::FixedFloat, || RenewMode::FixedFloat {
        coin: Currency::XMR,
    })
    .await;
    assert_identical_contract(&a, &b);
    let keys: Vec<&String> = b["data"]["fixedfloat"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    assert_eq!(keys, ["address", "amount", "coin"]);
}

#[tokio::test]
async fn revolut_card_looks_the_same_through_the_gateway() {
    let (a, b) = both(PaymentMethod::Revolut, RenewMode::default).await;
    assert_identical_contract(&a, &b);
    assert_eq!(
        b["data"]["revolut"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["token"]
    );
    assert!(!b["data"]["revolut"]["token"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn stripe_session_has_the_documented_shape() {
    let w = world(true).await;
    let (json, _) = customer_json(&w, PaymentMethod::Stripe, RenewMode::default())
        .await
        .unwrap();
    assert_eq!(
        json["data"]["stripe"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["session_id"]
    );
    assert!(
        json["data"]["stripe"]["session_id"]
            .as_str()
            .unwrap()
            .starts_with("cs_")
    );
}

#[tokio::test]
async fn card_attempt_never_uses_a_gateway_page() {
    let w = world(true).await;
    let (json, _) = customer_json(&w, PaymentMethod::Revolut, RenewMode::default())
        .await
        .unwrap();
    let requests = w.fake.cards.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let public_url = mock_settings().public_url;
    for url in [&requests[0].success_url, &requests[0].cancel_url] {
        let url = url.as_deref().unwrap();
        assert!(url.starts_with(public_url.trim_end_matches('/')), "{url}");
        assert!(!url.contains(GATEWAY_HOST));
    }
    assert!(!json.to_string().contains(GATEWAY_HOST));
}

#[tokio::test]
async fn customer_text_never_names_the_gateway() {
    let w = world(true).await;
    for method in [
        PaymentMethod::Lightning,
        PaymentMethod::OnChain,
        PaymentMethod::Revolut,
        PaymentMethod::Stripe,
    ] {
        let (json, _) = customer_json(&w, method, RenewMode::default())
            .await
            .unwrap();
        let text = json.to_string().to_lowercase();
        assert!(!text.contains(GATEWAY_HOST), "{method:?}");
        assert!(!text.contains("payment-gateway"), "{method:?}");
        assert!(!text.contains("checkout"), "{method:?}");
    }
    *w.fake.fail.lock().unwrap() = true;
    for method in [PaymentMethod::Revolut, PaymentMethod::Stripe] {
        let err = w
            .sub
            .renew_subscription(w.sub_id, method, 1)
            .await
            .unwrap_err();
        let api = lnvps_api_common::ApiError::from(err);
        let text = api.error.to_lowercase();
        assert!(!text.contains(GATEWAY_HOST));
        assert!(!text.contains("payment-gateway"));
    }
}

async fn show_seen_deposit(w: &World, payment: &SubscriptionPayment, reference: &str) -> Value {
    let db: Arc<dyn lnvps_db::LNVpsDb> = w.db.clone();
    let event = lnvps_api_common::GatewayEvent {
        event_id: "seen1".into(),
        kind: "attempt.received".into(),
        reference: hex::encode(&payment.id),
        status: "pending".into(),
        amount: Some(1),
        deposit: Some(reference.into()),
        ..Default::default()
    };
    crate::payments::gateway::handle_gateway_event(&db, &w.sub, &event)
        .await
        .unwrap();
    let stored = w.db.get_subscription_payment(&payment.id).await.unwrap();
    assert!(!stored.is_paid);
    serde_json::to_value(ApiSubscriptionPayment::from(stored)).unwrap()
}

#[tokio::test]
async fn onchain_seen_unconfirmed_shows_the_outpoint_like_in_process() {
    let w = world(true).await;
    let (before, payment) = customer_json(&w, PaymentMethod::OnChain, RenewMode::default())
        .await
        .unwrap();
    assert!(before["data"]["onchain"].get("outpoint").is_none());
    let json = show_seen_deposit(&w, &payment, "abc123:0").await;
    assert_eq!(json["data"]["onchain"]["outpoint"], "abc123:0");
    assert!(!json["is_paid"].as_bool().unwrap());
}

#[tokio::test]
async fn fixedfloat_seen_unconfirmed_shows_the_outpoint_like_in_process() {
    let w = world(true).await;
    let (before, payment) = customer_json(&w, PaymentMethod::FixedFloat, RenewMode::FixedFloat {
        coin: Currency::XMR,
    })
    .await
    .unwrap();
    assert!(before["data"]["fixedfloat"].get("outpoint").is_none());
    let json = show_seen_deposit(&w, &payment, "def456:1").await;
    assert_eq!(json["data"]["fixedfloat"]["outpoint"], "def456:1");
}

#[tokio::test]
async fn seen_deposit_event_twice_changes_nothing() {
    let w = world(true).await;
    let (_, payment) = customer_json(&w, PaymentMethod::OnChain, RenewMode::default())
        .await
        .unwrap();
    let first = show_seen_deposit(&w, &payment, "abc123:0").await;
    let second = show_seen_deposit(&w, &payment, "abc123:0").await;
    assert_eq!(first, second);
}
