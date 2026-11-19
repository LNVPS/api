//! Selling a VPN plan, and what each billing event has to make happen.

use anyhow::Result;
use async_trait::async_trait;
use lnvps_api_common::{MockDb, WorkJob};
use lnvps_db::{BillingState, IntervalType, Router, RouterKind, TunnelPool};

use super::*;

/// Records what was queued, so a test can assert the push happened rather than
/// that a function returned Ok.
#[derive(Default)]
struct RecordingCommander {
    sent: std::sync::Mutex<Vec<WorkJob>>,
}

impl RecordingCommander {
    fn sent(&self) -> Vec<WorkJob> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl WorkCommander for RecordingCommander {
    async fn send(&self, job: WorkJob) -> Result<String> {
        self.sent.lock().unwrap().push(job);
        Ok("1".to_string())
    }
    async fn recv(&self) -> Result<Vec<lnvps_api_common::WorkJobMessage>> {
        Ok(vec![])
    }
    async fn ack(&self, _id: &str) -> Result<()> {
        Ok(())
    }
}

/// A commander whose sends always fail, standing in for a Redis outage.
struct FailingCommander;

#[async_trait]
impl WorkCommander for FailingCommander {
    async fn send(&self, _job: WorkJob) -> Result<String> {
        Err(anyhow!("redis is down"))
    }
    async fn recv(&self) -> Result<Vec<lnvps_api_common::WorkJobMessage>> {
        Ok(vec![])
    }
    async fn ack(&self, _id: &str) -> Result<()> {
        Ok(())
    }
}

async fn a_service(db: &Arc<dyn LNVpsDb>, mock: &MockDb) -> Result<VpnService> {
    mock.companies
        .lock()
        .await
        .entry(1)
        .or_insert(lnvps_db::Company {
            id: 1,
            name: "LNVPS".to_string(),
            base_currency: "EUR".to_string(),
            ..Default::default()
        });
    let id = db
        .insert_vpn_service(&VpnService {
            name: "eu".to_string(),
            company_id: 1,
            amount: 500,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_amount: 0,
            default_device_limit: 5,
            enabled: true,
            ..Default::default()
        })
        .await?;
    Ok(db.get_vpn_service(id).await?)
}

/// Two interfaces on the service, so "every interface is pushed" is testable.
async fn two_pools(db: &Arc<dyn LNVpsDb>, mock: &MockDb, service: &VpnService) -> Result<Vec<u64>> {
    let mut out = vec![];
    for port in [51820u16, 51821] {
        let router_id = {
            let mut routers = mock.router.lock().await;
            let id = routers.keys().max().copied().unwrap_or(0) + 1;
            routers.insert(
                id,
                Router {
                    id,
                    name: format!("rs{id}"),
                    enabled: true,
                    kind: RouterKind::MockRouter,
                    url: "mock://rs".to_string(),
                    token: "t".into(),
                },
            );
            id
        };
        let pool_id = db
            .insert_tunnel_pool(&TunnelPool {
                router_id,
                region_id: 1,
                name: format!("vpn-{port}"),
                listen_addr: "rs.example".to_string(),
                listen_port: port,
                private_key: lnvps_api_common::generate_wireguard_keypair()?
                    .private_key
                    .into(),
                public_key: vec![0x33; 32],
                cidr4: Some("10.64.0.0/24".to_string()),
                mtu: 1420,
                enabled: true,
                ..Default::default()
            })
            .await?;
        db.link_vpn_service_pool(service.id, pool_id).await?;
        out.push(pool_id);
    }
    Ok(out)
}

/// The handler ignores the payment's contents entirely (billing state is read
/// back from the subscription), so this only has to be a valid row.
fn payment(subscription_id: u64, user_id: u64) -> lnvps_db::SubscriptionPayment {
    lnvps_db::SubscriptionPayment {
        id: vec![1; 32],
        subscription_id,
        user_id,
        created: Utc::now(),
        expires: Utc::now(),
        amount: 500,
        currency: "EUR".to_string(),
        payment_method: lnvps_db::PaymentMethod::Lightning,
        payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
        external_data: lnvps_db::EncryptedString::new(String::new()),
        external_id: None,
        is_paid: true,
        rate: 1.0,
        time_value: None,
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

fn handler(
    db: &Arc<dyn LNVpsDb>,
    line_item_id: u64,
    tx: Arc<dyn WorkCommander>,
) -> VpnLineItemHandler {
    VpnLineItemHandler::new(db.clone(), line_item_id, tx)
}

/// A plan is created unpaid and priced from the service, on a subscription of
/// its own that the customer then pays through the ordinary flow.
#[tokio::test]
async fn a_plan_is_sold_unpaid_at_the_services_price() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;

    let plan = create_vpn_plan(&db, uid, &service).await?;

    assert_eq!(plan.user_id, uid);
    assert_eq!(plan.vpn_service_id, service.id);
    assert_eq!(
        service.default_device_limit, 5,
        "the allowance is the service's; a plan has no number of its own"
    );

    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    assert_eq!(sub.company_id, service.company_id);
    assert_eq!(sub.currency, "EUR");
    assert_eq!(sub.interval_amount, 1);
    assert_eq!(
        sub.billing_state(Utc::now()),
        BillingState::Unpaid,
        "nothing reaches a route server before the money does"
    );

    let li = db
        .get_subscription_line_item(plan.subscription_line_item_id)
        .await?;
    assert_eq!(li.subscription_type, LineItemType::Vpn);
    assert_eq!(li.amount, 500);
    Ok(())
}

/// Regression: the plan's subscription was created `is_active = 1`, so an
/// unpaid plan was reported as an active subscription while `billing_state` on
/// the same object said `unpaid`. Payment is what sets both flags.
#[tokio::test]
async fn test_vpn_plan_subscription_is_inactive_until_paid() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;

    let plan = create_vpn_plan(&db, uid, &service).await?;
    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;

    assert!(
        !sub.is_active,
        "an unpaid plan is not an active subscription"
    );
    assert!(!sub.is_setup);
    assert!(
        db.list_subscriptions_active(uid).await?.is_empty(),
        "and it must not appear in the customer's active subscriptions"
    );
    Ok(())
}

/// A customer has one plan. Asking again while theirs is live must not sell a
/// second one, or they would be billed twice for one allowance.
#[tokio::test]
async fn asking_twice_does_not_sell_two_plans() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;

    let first = create_vpn_plan(&db, uid, &service).await?;
    let again = create_vpn_plan(&db, uid, &service).await?;

    assert_eq!(first.id, again.id);
    assert_eq!(
        first.subscription_line_item_id, again.subscription_line_item_id,
        "an unpaid plan is one to pay, not one to replace"
    );
    Ok(())
}

/// A returning customer keeps their row, and with it every device they
/// registered: paying again is all it takes, with no configs to redistribute.
#[tokio::test]
async fn a_lapsed_plan_is_repointed_and_keeps_its_devices() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;

    two_pools(&db, &mock, &service).await?;
    let plan = create_vpn_plan(&db, uid, &service).await?;
    let device = crate::provisioner::register_vpn_device(&db, &plan, "phone", &[7u8; 32]).await?;
    let peer = db.list_vpn_device_tunnels(device.id).await?.remove(0);

    // Pay it, then let it lapse.
    let mut sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    sub.is_setup = true;
    sub.expires = Some(Utc::now() - chrono::TimeDelta::days(2));
    db.update_subscription(&sub).await?;
    assert_eq!(sub.billing_state(Utc::now()), BillingState::Expired);

    let returned = create_vpn_plan(&db, uid, &service).await?;

    assert_eq!(returned.id, plan.id, "the row is reused, not replaced");
    assert_ne!(
        returned.subscription_line_item_id, plan.subscription_line_item_id,
        "a lapsed plan is billed by a fresh subscription"
    );
    let kept = db.list_vpn_devices(plan.id).await?;
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].id, device.id);
    assert_eq!(
        db.list_vpn_device_tunnels(kept[0].id).await?[0].address4,
        peer.address4,
        "the customer's config still works once they pay"
    );
    Ok(())
}

/// A service that has stopped selling sells nothing.
#[tokio::test]
async fn a_disabled_service_sells_nothing() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    db.update_vpn_service(&VpnService {
        enabled: false,
        ..service.clone()
    })
    .await?;
    let disabled = db.get_vpn_service(service.id).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;

    let err = create_vpn_plan(&db, uid, &disabled)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not selling"), "{err}");
    Ok(())
}

/// Every billing event pushes every interface on the service, because every one
/// of them changes the same thing: whether this plan's devices are in the peer
/// set. Without the push the customer waits for the next scheduled poll.
#[tokio::test]
async fn every_billing_event_pushes_every_interface() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let pools = two_pools(&db, &mock, &service).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let plan = create_vpn_plan(&db, uid, &service).await?;
    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    let li = db
        .get_subscription_line_item(plan.subscription_line_item_id)
        .await?;

    let tx = Arc::new(RecordingCommander::default());
    let h = handler(&db, plan.subscription_line_item_id, tx.clone());

    h.on_payment(&payment(sub.id, uid)).await?;
    h.on_expired(&sub, &li).await?;
    h.on_grace_period_exceeded(&sub, &li).await?;

    let queued: Vec<u64> = tx
        .sent()
        .into_iter()
        .map(|j| match j {
            WorkJob::ReconcileTunnelPeers { pool_id } => pool_id,
            other => panic!("unexpected job {other}"),
        })
        .collect();
    assert_eq!(
        queued,
        vec![pools[0], pools[1], pools[0], pools[1], pools[0], pools[1]],
        "paid, lapsed and grace-exceeded each push both interfaces"
    );
    Ok(())
}

/// A grace period must not delete the devices: the plan is reused if the
/// customer returns, and their keys and addresses surviving is what makes that
/// a payment rather than a re-setup.
#[tokio::test]
async fn a_grace_period_keeps_the_devices() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    two_pools(&db, &mock, &service).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let plan = create_vpn_plan(&db, uid, &service).await?;
    crate::provisioner::register_vpn_device(&db, &plan, "phone", &[7u8; 32]).await?;

    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    let li = db
        .get_subscription_line_item(plan.subscription_line_item_id)
        .await?;

    handler(
        &db,
        plan.subscription_line_item_id,
        Arc::new(RecordingCommander::default()),
    )
    .on_grace_period_exceeded(&sub, &li)
    .await?;

    assert_eq!(db.list_vpn_devices(plan.id).await?.len(), 1);
    Ok(())
}

/// A queue outage must not fail the payment callback: the customer has been
/// charged, and the reconcile is only an optimisation over the poll that
/// happens anyway.
#[tokio::test]
async fn a_queue_outage_does_not_fail_a_payment() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    two_pools(&db, &mock, &service).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let plan = create_vpn_plan(&db, uid, &service).await?;
    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;

    handler(
        &db,
        plan.subscription_line_item_id,
        Arc::new(FailingCommander),
    )
    .on_payment(&payment(sub.id, uid))
    .await?;
    Ok(())
}

/// A VPN line item with no plan behind it is a wiring bug, and has to say so
/// rather than quietly pushing nothing.
#[tokio::test]
async fn a_line_item_with_no_plan_is_an_error() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let plan = create_vpn_plan(&db, uid, &service).await?;
    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    let li = db
        .get_subscription_line_item(plan.subscription_line_item_id)
        .await?;

    let err = handler(&db, 9999, Arc::new(RecordingCommander::default()))
        .on_expired(&sub, &li)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no vpn_subscription row"), "{err}");
    Ok(())
}
