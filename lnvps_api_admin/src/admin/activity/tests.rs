use super::*;
use crate::admin::model::Permission;
use axum::extract::{Query, State};
use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache};
use lnvps_db::{
    AppDeploymentDesiredState, AppDeploymentStatus, IntervalType, LNVpsDbBase, LineItemType,
    PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionPayment,
    SubscriptionPaymentType, VmHistory, VmHistoryActionType, VpnService, VpnSubscription,
};
use std::sync::Arc;

fn state(db: Arc<dyn LNVpsDb>) -> RouterState {
    RouterState {
        node_control: None,
        db,
        work_commander: Arc::new(ChannelWorkCommander::new()),
        feedback: None,
        vm_state_cache: VmStateCache::new(),
        exchange: Arc::new(MockExchangeRate::default()),
        vat: VatClient::new(),
    }
}

fn analytics_viewer() -> AdminAuth {
    AdminAuth {
        user_id: 1,
        pubkey: vec![1u8; 32],
        permissions: [Permission {
            resource: AdminResource::Analytics,
            action: AdminAction::View,
        }]
        .into_iter()
        .collect(),
        nip98_auth: None,
    }
}

fn query(days: u32, expiring_days: u32) -> Query<ActivityQuery> {
    Query(ActivityQuery {
        days: Some(days),
        expiring_days: Some(expiring_days),
        limit: None,
    })
}

async fn line_item(
    db: &MockDb,
    id: u64,
    kind: LineItemType,
    created: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
    is_setup: bool,
) -> u64 {
    db.subscriptions.lock().await.insert(
        id,
        Subscription {
            id,
            user_id: 1,
            company_id: 1,
            name: format!("sub {id}"),
            description: None,
            created,
            expires,
            is_active: is_setup,
            is_setup,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: false,
            external_id: None,
        },
    );
    db.subscription_line_items.lock().await.insert(
        id,
        SubscriptionLineItem {
            id,
            subscription_id: id,
            subscription_type: kind,
            name: format!("item {id}"),
            description: None,
            amount: 1000,
            setup_amount: 0,
            configuration: None,
        },
    );
    id
}

async fn vm(db: &MockDb, id: u64, line_item_id: u64, deleted: bool) {
    let mut vm = MockDb::mock_vm();
    vm.id = id;
    vm.subscription_line_item_id = line_item_id;
    vm.ssh_key_id = None;
    vm.deleted = deleted;
    db.vms.lock().await.insert(id, vm);
}

async fn deletion(db: &MockDb, vm_id: u64, at: DateTime<Utc>, reason: &str) {
    db.insert_vm_history(&VmHistory {
        id: 0,
        vm_id,
        action_type: VmHistoryActionType::Deleted,
        timestamp: at,
        initiated_by_user: None,
        previous_state: None,
        new_state: None,
        metadata: None,
        description: Some(reason.to_string()),
    })
    .await
    .unwrap();
}

fn payment(
    id: u8,
    subscription_id: u64,
    amount: u64,
    payment_type: SubscriptionPaymentType,
    paid_at: Option<DateTime<Utc>>,
) -> SubscriptionPayment {
    SubscriptionPayment {
        id: vec![id; 16],
        subscription_id,
        user_id: 1,
        created: paid_at.unwrap_or_else(Utc::now),
        expires: Utc::now(),
        amount,
        currency: "EUR".to_string(),
        payment_method: PaymentMethod::Lightning,
        payment_type,
        external_data: "".to_string().into(),
        external_id: None,
        is_paid: paid_at.is_some(),
        rate: 1.0,
        time_value: None,
        metadata: None,
        tax: amount / 10,
        processing_fee: 0,
        paid_at,
        tax_rate: None,
        tax_country_code: None,
        tax_treatment: None,
        tax_evidence: None,
        tax_breakdown: None,
        refunded_payment_id: None,
        renewal_source: None,
    }
}

async fn seeded() -> RouterState {
    let db = MockDb::default();
    let now = Utc::now();
    db.upsert_user(&[1u8; 32]).await.unwrap();

    let fresh = line_item(
        &db,
        10,
        LineItemType::Vps,
        now - days(1),
        Some(now + days(30)),
        true,
    )
    .await;
    vm(&db, 10, fresh, false).await;
    let unpaid = line_item(&db, 11, LineItemType::Vps, now - days(1), None, false).await;
    vm(&db, 11, unpaid, false).await;
    let old = line_item(
        &db,
        12,
        LineItemType::Vps,
        now - days(60),
        Some(now + days(2)),
        true,
    )
    .await;
    vm(&db, 12, old, false).await;
    let lapsed = line_item(
        &db,
        13,
        LineItemType::Vps,
        now - days(90),
        Some(now - days(2)),
        true,
    )
    .await;
    vm(&db, 13, lapsed, false).await;
    let gone = line_item(
        &db,
        14,
        LineItemType::Vps,
        now - days(90),
        Some(now - days(10)),
        true,
    )
    .await;
    vm(&db, 14, gone, true).await;
    deletion(&db, 14, now - days(3), "first attempt").await;
    deletion(&db, 14, now - days(2), "expired and exceeded grace period").await;
    let never_paid = line_item(&db, 15, LineItemType::Vps, now - days(2), None, false).await;
    vm(&db, 15, never_paid, true).await;
    deletion(&db, 15, now - days(1), "unpaid").await;
    let long_gone = line_item(&db, 16, LineItemType::Vps, now - days(90), None, true).await;
    vm(&db, 16, long_gone, true).await;
    deletion(&db, 16, now - days(30), "old").await;

    db.vpn_services.lock().await.insert(
        1,
        VpnService {
            id: 1,
            name: "Mullet".to_string(),
            company_id: 1,
            ..Default::default()
        },
    );
    let vpn = line_item(
        &db,
        20,
        LineItemType::Vpn,
        now - days(1),
        Some(now + days(30)),
        true,
    )
    .await;
    db.vpn_subscriptions.lock().await.insert(
        1,
        VpnSubscription {
            id: 1,
            vpn_service_id: 1,
            user_id: 1,
            subscription_line_item_id: vpn,
            created: now - days(1),
        },
    );
    let stale_vpn = line_item(&db, 21, LineItemType::Vpn, now - days(30), None, true).await;
    db.vpn_subscriptions.lock().await.insert(
        2,
        VpnSubscription {
            id: 2,
            vpn_service_id: 1,
            user_id: 1,
            subscription_line_item_id: stale_vpn,
            created: now - days(30),
        },
    );

    let app = line_item(
        &db,
        30,
        LineItemType::App,
        now - days(1),
        Some(now + days(30)),
        true,
    )
    .await;
    let unpaid_app = line_item(&db, 31, LineItemType::App, now - days(1), None, false).await;
    for (id, line_item_id) in [(1, app), (2, unpaid_app)] {
        db.app_deployments.lock().await.insert(
            id,
            lnvps_db::AppDeployment {
                id,
                user_id: 1,
                app_id: 1,
                cluster_id: 1,
                resource_multiplier: 1,
                subscription_line_item_id: line_item_id,
                name: format!("app{id}"),
                namespace: format!("app-{id}"),
                hostname: None,
                custom_domain: None,
                custom_domain_verified: false,
                config: None,
                desired_state: AppDeploymentDesiredState::Running,
                status: AppDeploymentStatus::Running,
                status_message: None,
                usage_cpu_milli: None,
                usage_memory_bytes: None,
                usage_storage_bytes: None,
                usage_collected: None,
                created: now - days(1),
                deleted: false,
            },
        );
    }

    for p in [
        payment(
            1,
            fresh,
            1000,
            SubscriptionPaymentType::Purchase,
            Some(now - days(1)),
        ),
        payment(
            2,
            vpn,
            500,
            SubscriptionPaymentType::Renewal,
            Some(now - days(2)),
        ),
        payment(
            3,
            vpn,
            300,
            SubscriptionPaymentType::Renewal,
            Some(now - days(3)),
        ),
        payment(
            4,
            fresh,
            200,
            SubscriptionPaymentType::Refund,
            Some(now - days(4)),
        ),
        payment(5, fresh, 9999, SubscriptionPaymentType::Purchase, None),
        payment(
            6,
            fresh,
            9999,
            SubscriptionPaymentType::Purchase,
            Some(now - days(30)),
        ),
    ] {
        db.insert_subscription_payment(&p).await.unwrap();
    }

    state(Arc::new(db))
}

fn ids(vms: &AdminActivitySection<AdminVmInfo>) -> Vec<u64> {
    vms.items.iter().map(|v| v.id).collect()
}

#[test]
fn router_is_constructible() {
    let _ = router();
}

#[tokio::test]
async fn reports_only_paid_activity_inside_the_window() {
    crate::verbose_errors_for_tests();
    let this = seeded().await;

    let report = admin_activity_report(analytics_viewer(), State(this), query(7, 7))
        .await
        .unwrap()
        .0
        .data;

    assert_eq!(report.new_users.total, 1);
    assert_eq!(report.new_users.items[0].pubkey, hex::encode([1u8; 32]));

    assert_eq!(ids(&report.new_vms), vec![10]);
    assert_eq!(report.new_vms.total, 1);

    assert_eq!(report.deleted_vms.total, 1);
    let deleted = &report.deleted_vms.items[0];
    assert_eq!(deleted.vm.id, 14);
    assert_eq!(
        deleted.delete_reason.as_deref(),
        Some("expired and exceeded grace period")
    );

    assert_eq!(ids(&report.expiring_vms), vec![13, 12]);

    assert_eq!(report.new_vpn_subscriptions.total, 1);
    assert_eq!(
        report.new_vpn_subscriptions.items[0].vpn_service_name,
        "Mullet"
    );

    assert_eq!(report.new_app_deployments.total, 1);
    assert_eq!(report.new_app_deployments.items[0].id, 1);

    let paid: Vec<u64> = report
        .payments
        .items
        .iter()
        .map(|p| p.payment.amount)
        .collect();
    assert_eq!(paid, vec![1000, 500, 300, 200]);
    assert_eq!(report.payments.items[1].subscription_name, "sub 20");
    assert_eq!(
        report.payments.items[0].payment.company_base_currency,
        "EUR"
    );

    let totals: Vec<(String, u64, u64, u64)> = report
        .payment_totals
        .iter()
        .map(|t| (format!("{:?}", t.payment_type), t.count, t.amount, t.tax))
        .collect();
    assert_eq!(
        totals,
        vec![
            ("Purchase".to_string(), 1, 1000, 100),
            ("Renewal".to_string(), 2, 800, 80),
            ("Refund".to_string(), 1, 200, 20),
        ]
    );
}

#[tokio::test]
async fn limit_caps_items_but_not_totals() {
    crate::verbose_errors_for_tests();
    let this = seeded().await;

    let report = admin_activity_report(
        analytics_viewer(),
        State(this),
        Query(ActivityQuery {
            days: Some(90),
            expiring_days: Some(1),
            limit: Some(1),
        }),
    )
    .await
    .unwrap()
    .0
    .data;

    assert_eq!(report.payments.items.len(), 1);
    assert_eq!(report.payments.total, 5);
    assert_eq!(report.deleted_vms.total, 2);
    assert_eq!(report.deleted_vms.items[0].vm.id, 14);
    assert_eq!(ids(&report.expiring_vms), vec![13]);
    assert_eq!(report.expiring_vms.total, 1);
    assert_eq!(report.new_vpn_subscriptions.total, 2);
}

#[tokio::test]
async fn rejects_out_of_range_windows_and_missing_permission() {
    let this = seeded().await;
    for (days, expiring_days) in [(0, 7), (7, 0), (MAX_DAYS + 1, 7), (7, MAX_DAYS + 1)] {
        assert!(
            admin_activity_report(
                analytics_viewer(),
                State(this.clone()),
                query(days, expiring_days)
            )
            .await
            .is_err()
        );
    }

    let nobody = AdminAuth {
        permissions: Default::default(),
        ..analytics_viewer()
    };
    assert!(
        admin_activity_report(nobody, State(this), query(7, 7))
            .await
            .is_err()
    );
}

fn days(n: i64) -> Duration {
    Duration::days(n)
}
