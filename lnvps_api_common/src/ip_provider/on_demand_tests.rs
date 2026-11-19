use super::*;
use crate::{CapacityError, HostCapacityService, MockDb, WorkCommander, WorkJob, WorkJobMessage};
use async_trait::async_trait;
use chrono::Utc;
use lnvps_db::{
    IpOrder, IpOrderState, IpProvider, IpProviderKind, IpProviderRegion, IpWhenNoIp, LNVpsDbBase,
    VmIpWait,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct Recorder {
    jobs: Mutex<Vec<WorkJob>>,
}

#[async_trait]
impl WorkCommander for Recorder {
    async fn send(&self, job: WorkJob) -> anyhow::Result<String> {
        self.jobs.lock().await.push(job);
        Ok("1".to_string())
    }
    async fn recv(&self) -> anyhow::Result<Vec<WorkJobMessage>> {
        Ok(vec![])
    }
    async fn ack(&self, _id: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

impl Recorder {
    async fn spawned(&self) -> Vec<u64> {
        self.jobs
            .lock()
            .await
            .iter()
            .filter_map(|j| match j {
                WorkJob::SpawnVm { vm_id } => Some(*vm_id),
                _ => None,
            })
            .collect()
    }

    async fn admin_titles(&self) -> Vec<String> {
        self.jobs
            .lock()
            .await
            .iter()
            .filter_map(|j| match j {
                WorkJob::SendAdminNotification { title, .. } => title.clone(),
                _ => None,
            })
            .collect()
    }

    async fn user_titles(&self) -> Vec<String> {
        self.jobs
            .lock()
            .await
            .iter()
            .filter_map(|j| match j {
                WorkJob::SendNotification { title, .. } => title.clone(),
                _ => None,
            })
            .collect()
    }

    async fn deleted(&self) -> Vec<u64> {
        self.jobs
            .lock()
            .await
            .iter()
            .filter_map(|j| match j {
                WorkJob::DeleteVm { vm_id, .. } => Some(*vm_id),
                _ => None,
            })
            .collect()
    }
}

struct Fixture {
    db: Arc<MockDb>,
    mock: MockIpProvider,
    rec: Arc<Recorder>,
    service: Arc<IpOrderService>,
}

fn provider(approval_required: bool, cap: u64) -> IpProvider {
    IpProvider {
        id: 0,
        name: "mock".to_string(),
        kind: IpProviderKind::Mock,
        enabled: true,
        url: String::new(),
        token: "".into(),
        subsidiary: "IE".to_string(),
        rir: "ripe".to_string(),
        gateway: "203.0.113.254".to_string(),
        access_policy_id: None,
        approval_required,
        monthly_spend_cap: cap,
        currency: "EUR".to_string(),
        enable_ranges_on_delivery: true,
    }
}

fn rule(when: IpWhenNoIp, sell_without_capacity: bool) -> IpProviderRegion {
    IpProviderRegion {
        provider_id: 1,
        region_id: 1,
        prefix_len: 32,
        quantity: 1,
        enabled: true,
        when_no_ip: when,
        sell_without_capacity,
        ..Default::default()
    }
}

async fn fixture(p: IpProvider, r: Option<IpProviderRegion>) -> Fixture {
    let db = Arc::new(MockDb::default());
    db.upsert_user(&[1u8; 32]).await.unwrap();
    db.insert_user_ssh_key(&lnvps_db::UserSshKey {
        id: 0,
        name: "k".to_string(),
        user_id: 1,
        created: Utc::now(),
        key_data: "ssh-ed25519 AAAA".into(),
    })
    .await
    .unwrap();
    db.ip_range.lock().await.remove(&1);
    db.insert_ip_provider(&p).await.unwrap();
    if let Some(r) = r {
        db.insert_ip_provider_region(&r).await.unwrap();
    }
    let mock = MockIpProvider::new("mock", 200);
    let shared = mock.clone();
    let rec = Arc::new(Recorder::default());
    let service = Arc::new(IpOrderService::with_builder(
        db.clone(),
        rec.clone(),
        Arc::new(move |_| Arc::new(shared.clone())),
    ));
    Fixture {
        db,
        mock,
        rec,
        service,
    }
}

async fn add_vm(f: &Fixture, id: u64) -> lnvps_db::Vm {
    let mut vm = MockDb::mock_vm();
    vm.id = id;
    f.db.insert_vm_with_id(&vm).await.unwrap();
    vm
}

async fn deliver(f: &Fixture, cidr: &str) {
    *f.mock.status.lock().await = ProviderOrderStatus::Delivered(vec![OwnedIp {
        cidr: cidr.to_string(),
        country: None,
        routed_to: None,
    }]);
}

async fn orders(f: &Fixture) -> Vec<IpOrder> {
    f.db.list_ip_orders(None, None, 100, 0).await.unwrap().0
}

#[tokio::test]
async fn region_with_free_ips_is_sold_unchanged() {
    let f = fixture(
        provider(false, 10_000),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    f.db.ip_range.lock().await.insert(
        1,
        MockDb::default()
            .ip_range
            .lock()
            .await
            .get(&1)
            .cloned()
            .unwrap(),
    );
    assert_eq!(
        sale_decision(f.db.as_ref(), 1, 1).await.unwrap(),
        IpSale::InStock
    );
    let vm = add_vm(&f, 1).await;
    assert!(f.service.gate_vm(&vm).await.unwrap());
    assert!(orders(&f).await.is_empty());
    assert!(f.db.list_vm_ip_waits(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn empty_region_with_reject_policy_refuses_at_quote_time() {
    let f = fixture(
        provider(false, 10_000),
        Some(rule(IpWhenNoIp::Reject, true)),
    )
    .await;
    let sale = sale_decision(f.db.as_ref(), 1, 1).await.unwrap();
    assert!(matches!(sale, IpSale::OutOfCapacity(m) if m.contains("out of capacity")));

    let template = MockDb::mock_template();
    let err = HostCapacityService::new(f.db.clone())
        .get_host_for_template_ip_aware(1, &template, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<CapacityError>(),
        Some(CapacityError::OutOfIpCapacity(_))
    ));
    assert!(orders(&f).await.is_empty());
    assert_eq!(f.mock.orders_placed(), 0);
}

#[tokio::test]
async fn empty_region_without_any_rule_refuses() {
    let f = fixture(provider(false, 10_000), None).await;
    assert!(matches!(
        sale_decision(f.db.as_ref(), 1, 1).await.unwrap(),
        IpSale::OutOfCapacity(_)
    ));
}

#[tokio::test]
async fn order_and_wait_orders_at_once_waits_then_serves_the_vm() {
    let f = fixture(
        provider(false, 10_000),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    assert_eq!(
        sale_decision(f.db.as_ref(), 1, 1).await.unwrap(),
        IpSale::WaitForIp
    );
    let template = MockDb::mock_template();
    HostCapacityService::new(f.db.clone())
        .get_host_for_template_ip_aware(1, &template, None)
        .await
        .expect("the purchase is accepted");

    let vm = add_vm(&f, 1).await;
    assert!(!f.service.gate_vm(&vm).await.unwrap());

    assert_eq!(
        f.mock.orders_placed(),
        1,
        "ordered without waiting for a tick"
    );
    let o = orders(&f).await;
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].state, IpOrderState::Ordered);
    let wait = f.db.get_vm_ip_wait(1).await.unwrap().unwrap();
    assert_eq!(wait.ip_order_id, Some(o[0].id));
    assert!(
        f.rec
            .admin_titles()
            .await
            .contains(&"VM waiting for an IP".to_string())
    );
    assert!(
        f.rec
            .user_titles()
            .await
            .iter()
            .any(|t| t.contains("Waiting for an IP"))
    );

    f.service.serve_waiting_vms().await.unwrap();
    assert!(f.rec.spawned().await.is_empty(), "nothing delivered yet");

    deliver(&f, "203.0.113.16/28").await;
    f.service.sweep().await.unwrap();
    assert_eq!(
        f.db.get_ip_order(o[0].id).await.unwrap().state,
        IpOrderState::Delivered
    );
    assert_eq!(f.rec.spawned().await, vec![1]);
    assert!(f.db.get_vm_ip_wait(1).await.unwrap().unwrap().released);
    assert!(
        f.rec
            .user_titles()
            .await
            .iter()
            .any(|t| t.contains("IP address ready"))
    );
    assert!(f.service.gate_vm(&vm).await.unwrap());
    assert_eq!(f.mock.orders_placed(), 1);
}

#[tokio::test]
async fn ten_concurrent_purchases_make_one_order_and_all_are_served() {
    let f = fixture(
        provider(false, 100_000),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    let mut vms = vec![];
    for id in 1..=10 {
        vms.push(add_vm(&f, id).await);
    }
    let results = futures::future::join_all(vms.iter().map(|v| f.service.gate_vm(v))).await;
    assert!(results.into_iter().all(|r| !r.unwrap()));
    assert_eq!(orders(&f).await.len(), 1);
    assert_eq!(f.mock.orders_placed(), 1);
    assert_eq!(f.db.list_vm_ip_waits(None).await.unwrap().len(), 10);

    deliver(&f, "203.0.113.16/28").await;
    f.service.sweep().await.unwrap();
    let mut spawned = f.rec.spawned().await;
    assert_eq!(spawned.len(), 10);
    spawned.sort();
    spawned.dedup();
    assert_eq!(spawned.len(), 10);
    assert_eq!(orders(&f).await.len(), 1, "delivery covered everyone");
}

#[tokio::test]
async fn the_order_is_sized_for_every_waiting_vm() {
    let f = fixture(
        provider(false, 100_000),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    for id in 1..=10 {
        add_vm(&f, id).await;
        f.db.insert_vm_ip_wait(&VmIpWait {
            id: 0,
            vm_id: id,
            region_id: 1,
            ip4_needed: 1,
            ip_order_id: None,
            released: false,
            created: Utc::now(),
        })
        .await
        .unwrap();
    }
    let results =
        futures::future::join_all((0..5).map(|_| f.service.ensure_region_capacity(1))).await;
    assert_eq!(
        results
            .into_iter()
            .filter(|r| r.as_ref().unwrap().is_some())
            .count(),
        1
    );
    let o = orders(&f).await;
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].quantity, 10);
}

#[tokio::test]
async fn waiting_vms_are_served_oldest_first() {
    let f = fixture(
        provider(false, 100_000),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    for (id, age) in [(1u64, 1i64), (2, 3), (3, 2)] {
        add_vm(&f, id).await;
        f.db.insert_vm_ip_wait(&VmIpWait {
            id: 0,
            vm_id: id,
            region_id: 1,
            ip4_needed: 1,
            ip_order_id: None,
            released: false,
            created: Utc::now() - chrono::Duration::minutes(age),
        })
        .await
        .unwrap();
    }
    f.db.ip_range.lock().await.insert(
        50,
        lnvps_db::IpRange {
            id: 50,
            cidr: "203.0.113.1/32".to_string(),
            gateway: "203.0.113.254".to_string(),
            enabled: true,
            region_id: 1,
            use_full_range: true,
            ..Default::default()
        },
    );
    f.service.serve_waiting_vms().await.unwrap();
    assert_eq!(f.rec.spawned().await, vec![2]);
}

#[tokio::test]
async fn approval_pending_refuses_the_purchase_unless_selling_without_capacity() {
    let f = fixture(
        provider(true, 10_000),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    let sale = sale_decision(f.db.as_ref(), 1, 1).await.unwrap();
    assert!(matches!(sale, IpSale::OutOfCapacity(m) if m.contains("approval")));
    assert!(orders(&f).await.is_empty());

    let f = fixture(
        provider(true, 10_000),
        Some(rule(IpWhenNoIp::OrderAndWait, true)),
    )
    .await;
    assert_eq!(
        sale_decision(f.db.as_ref(), 1, 1).await.unwrap(),
        IpSale::WaitForIp
    );
    let vm = add_vm(&f, 1).await;
    assert!(!f.service.gate_vm(&vm).await.unwrap());
    let o = orders(&f).await;
    assert_eq!(o[0].state, IpOrderState::AwaitingApproval);
    assert_eq!(f.mock.orders_placed(), 0);
    assert!(f.db.get_vm_ip_wait(1).await.unwrap().is_some());
}

#[tokio::test]
async fn a_second_waiting_vm_grows_the_order_awaiting_approval() {
    let f = fixture(
        provider(true, 10_000),
        Some(rule(IpWhenNoIp::OrderAndWait, true)),
    )
    .await;
    for id in 1..=3 {
        let vm = add_vm(&f, id).await;
        assert!(!f.service.gate_vm(&vm).await.unwrap());
    }
    let o = orders(&f).await;
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].quantity, 3);
}

#[tokio::test]
async fn spend_cap_already_used_refuses_the_purchase() {
    let f = fixture(
        provider(false, 300),
        Some(rule(IpWhenNoIp::OrderAndWait, false)),
    )
    .await;
    f.db.insert_ip_order(&IpOrder {
        provider: "mock".to_string(),
        region_id: 1,
        prefix_len: 32,
        quantity: 1,
        state: IpOrderState::Delivered,
        cost: 200,
        currency: "EUR".to_string(),
        created: Utc::now(),
        ..Default::default()
    })
    .await
    .unwrap();
    let sale = sale_decision(f.db.as_ref(), 1, 1).await.unwrap();
    assert!(matches!(sale, IpSale::OutOfCapacity(m) if m.contains("budget")));

    let f2 = fixture(
        provider(false, 300),
        Some(rule(IpWhenNoIp::OrderAndWait, true)),
    )
    .await;
    assert_eq!(
        sale_decision(f2.db.as_ref(), 1, 1).await.unwrap(),
        IpSale::WaitForIp
    );
}

#[tokio::test]
async fn order_failure_notifies_keeps_the_vm_waiting_and_refunds_after_the_timeout() {
    let mut r = rule(IpWhenNoIp::OrderAndWait, false);
    r.wait_refund_hours = 1;
    let f = fixture(provider(false, 10_000), Some(r)).await;
    *f.mock.fail_order.lock().await = Some("boom".to_string());
    let vm = add_vm(&f, 1).await;
    assert!(!f.service.gate_vm(&vm).await.unwrap());

    let o = orders(&f).await;
    assert_eq!(o[0].state, IpOrderState::Failed);
    assert!(
        f.rec
            .admin_titles()
            .await
            .contains(&"IP order failed".to_string())
    );
    assert!(f.db.get_vm_ip_wait(1).await.unwrap().is_some(), "not lost");

    f.service.serve_waiting_vms().await.unwrap();
    assert_eq!(
        orders(&f).await.len(),
        1,
        "a failed order is not retried blindly"
    );
    assert!(f.rec.deleted().await.is_empty(), "inside the timeout");

    f.db.vm_ip_waits.lock().await[0].created = Utc::now() - chrono::Duration::hours(2);
    f.service.serve_waiting_vms().await.unwrap();
    assert_eq!(f.rec.deleted().await, vec![1]);
    assert!(f.db.get_vm_ip_wait(1).await.unwrap().is_none());
}

#[tokio::test]
async fn no_refund_while_an_order_is_still_in_flight() {
    let mut r = rule(IpWhenNoIp::OrderAndWait, false);
    r.wait_refund_hours = 1;
    let f = fixture(provider(false, 10_000), Some(r)).await;
    let vm = add_vm(&f, 1).await;
    assert!(!f.service.gate_vm(&vm).await.unwrap());
    f.db.vm_ip_waits.lock().await[0].created = Utc::now() - chrono::Duration::hours(5);
    f.service.serve_waiting_vms().await.unwrap();
    assert!(f.rec.deleted().await.is_empty());
}

#[tokio::test]
async fn disabled_provider_means_the_region_is_out_of_capacity() {
    let mut p = provider(false, 10_000);
    p.enabled = false;
    let f = fixture(p, Some(rule(IpWhenNoIp::OrderAndWait, true))).await;
    assert!(matches!(
        sale_decision(f.db.as_ref(), 1, 1).await.unwrap(),
        IpSale::OutOfCapacity(_)
    ));
}
