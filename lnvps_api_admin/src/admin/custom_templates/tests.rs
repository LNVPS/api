use super::*;
use crate::admin::model::Permission;
use chrono::Utc;
use lnvps_api_common::{
    ChannelWorkCommander, GB, MockDb, MockExchangeRate, VatClient, VmStateCache,
};
use lnvps_db::{
    AdminDb, IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, SubscriptionType,
    VmCustomPricing, VmCustomPricingDisk,
};

/// EUR plan: €1.50/core, €0.50/GB RAM, €0.05/GB SSD, €0.50 per IPv4, €0.05 per IPv6.
async fn seed_pricing(db: &MockDb, id_hint: u64) -> u64 {
    let pricing_id = db
        .insert_custom_pricing(&VmCustomPricing {
            id: 0,
            name: format!("plan-{id_hint}"),
            enabled: true,
            created: Utc::now(),
            expires: None,
            region_id: 1,
            currency: "EUR".to_string(),
            cpu_cost: 150,
            memory_cost: 50,
            ip4_cost: 50,
            ip6_cost: 5,
            min_cpu: 1,
            max_cpu: 16,
            min_memory: GB,
            max_memory: 64 * GB,
            min_ip4: 1,
            max_ip4: 4,
            min_ip6: 1,
            max_ip6: 4,
            ..Default::default()
        })
        .await
        .unwrap();

    db.insert_custom_pricing_disk(&VmCustomPricingDisk {
        id: 0,
        pricing_id,
        kind: DiskType::SSD,
        interface: DiskInterface::PCIe,
        cost: 5,
        min_disk_size: 5 * GB,
        max_disk_size: 1024 * GB,
    })
    .await
    .unwrap();

    pricing_id
}

fn template(pricing_id: u64) -> VmCustomTemplate {
    VmCustomTemplate {
        id: 0,
        cpu: 2,
        memory: 2 * GB,
        disk_size: 80 * GB,
        disk_type: DiskType::SSD,
        disk_interface: DiskInterface::PCIe,
        pricing_id,
        ip4_count: 1,
        ip6_count: 1,
        ..Default::default()
    }
}

/// A custom VM wired to a monthly subscription line item, as production has it.
async fn seed_vm(db: &MockDb, template_id: u64, amount: u64) -> (u64, u64) {
    let user_id = db.upsert_user(&[7u8; 32]).await.unwrap();
    let sub_id = db
        .insert_subscription(&Subscription {
            id: 0,
            user_id,
            company_id: 1,
            name: "vm sub".to_string(),
            description: None,
            created: Utc::now(),
            expires: None,
            is_active: true,
            is_setup: true,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: true,
            external_id: None,
        })
        .await
        .unwrap();
    let line_item_id = db
        .insert_subscription_line_item(&SubscriptionLineItem {
            id: 0,
            subscription_id: sub_id,
            subscription_type: SubscriptionType::Vps,
            name: "vm".to_string(),
            description: None,
            amount,
            setup_amount: 0,
            configuration: None,
        })
        .await
        .unwrap();

    let mut vm = MockDb::mock_vm();
    vm.user_id = user_id;
    vm.template_id = None;
    vm.custom_template_id = Some(template_id);
    vm.subscription_line_item_id = line_item_id;
    vm.ssh_key_id = None;
    let vm_id = db.insert_vm(&vm).await.unwrap();
    (vm_id, line_item_id)
}

fn state(db: &Arc<dyn LNVpsDb>) -> RouterState {
    RouterState {
        node_control: None,
        db: db.clone(),
        work_commander: Arc::new(ChannelWorkCommander::new()),
        feedback: None,
        vm_state_cache: VmStateCache::new(),
        exchange: Arc::new(MockExchangeRate::default()),
        vat: VatClient::new(),
    }
}

fn auth(action: AdminAction) -> AdminAuth {
    AdminAuth {
        user_id: 1,
        pubkey: vec![1u8; 32],
        permissions: [Permission {
            resource: AdminResource::VmCustomPricing,
            action,
        }]
        .into_iter()
        .collect(),
        nip98_auth: None,
    }
}

fn no_permissions() -> AdminAuth {
    AdminAuth {
        user_id: 1,
        pubkey: vec![1u8; 32],
        permissions: Default::default(),
        nip98_auth: None,
    }
}

/// The router exists and is merged with the same state as its siblings.
#[test]
fn router_is_constructible() {
    let _ = router();
}

#[tokio::test]
async fn get_custom_template_reports_specs_price_and_vms() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    let (vm_id, _) = seed_vm(&db, template_id, 0).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let this = state(&db);

    // 2 cores (300) + 2 GB (100) + 80 GB SSD (400) + 1x v4 (50) + 1x v6 (5)
    let out = admin_get_custom_template(
        auth(AdminAction::View),
        State(this.clone()),
        Path(template_id),
    )
    .await
    .unwrap();
    assert_eq!(out.0.data.cpu, 2);
    assert_eq!(out.0.data.price, 855);
    assert_eq!(out.0.data.currency, "EUR");
    assert_eq!(out.0.data.vm_ids, vec![vm_id]);
    assert_eq!(out.0.data.region_id, 1);

    // The permission gate is the same on read as on write.
    assert!(
        admin_get_custom_template(no_permissions(), State(this), Path(template_id))
            .await
            .is_err()
    );
}

/// The happy path: spec stored, line item repriced, upgrade job queued.
#[tokio::test]
async fn update_custom_template_reprices_and_queues_upgrade() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    let (vm_id, line_item_id) = seed_vm(&db, template_id, 855).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let this = state(&db);

    let out = admin_update_custom_template(
        auth(AdminAction::Update),
        State(this.clone()),
        Path(template_id),
        Json(UpdateCustomTemplateRequest {
            cpu: Some(4),
            memory: Some(8 * GB),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    // 4 cores (600) + 8 GB (400) + 80 GB SSD (400) + 50 + 5
    assert_eq!(out.0.data.renewal_amount, 1455);
    assert_eq!(out.0.data.template.cpu, 4);
    assert_eq!(out.0.data.template.memory, 8 * GB);
    assert_eq!(out.0.data.template.vm_ids, vec![vm_id]);
    assert_eq!(out.0.data.job_ids.len(), 1);

    let stored = db.get_custom_vm_template(template_id).await.unwrap();
    assert_eq!((stored.cpu, stored.memory), (4, 8 * GB));
    let line_item = db.get_subscription_line_item(line_item_id).await.unwrap();
    assert_eq!(line_item.amount, 1455);
}

/// A change the hypervisor does not care about must not stop and restart a VM.
#[tokio::test]
async fn update_without_host_impact_queues_no_job() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    let (_, line_item_id) = seed_vm(&db, template_id, 855).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let this = state(&db);

    let out = admin_update_custom_template(
        auth(AdminAction::Update),
        State(this.clone()),
        Path(template_id),
        Json(UpdateCustomTemplateRequest {
            ip4_count: Some(2),
            transfer_gb: Some(Some(5000)),
            firewall_rule_limit: Some(Some(64)),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert!(out.0.data.job_ids.is_empty());
    assert_eq!(out.0.data.template.ip4_count, 2);
    assert_eq!(out.0.data.template.transfer_gb, Some(5000));
    assert_eq!(out.0.data.template.firewall_rule_limit, Some(64));
    // One more IPv4 at €0.50
    assert_eq!(out.0.data.renewal_amount, 905);
    let line_item = db.get_subscription_line_item(line_item_id).await.unwrap();
    assert_eq!(line_item.amount, 905);

    // An IO cap, by contrast, is applied to the host.
    let out = admin_update_custom_template(
        auth(AdminAction::Update),
        State(this),
        Path(template_id),
        Json(UpdateCustomTemplateRequest {
            disk_iops_read: Some(Some(5000)),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(out.0.data.job_ids.len(), 1);
    assert_eq!(out.0.data.template.disk_iops_read, Some(5000));
}

#[tokio::test]
async fn update_custom_template_rejects_bad_requests() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    seed_vm(&db, template_id, 855).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let this = state(&db);

    let patch = |req: UpdateCustomTemplateRequest| {
        admin_update_custom_template(
            auth(AdminAction::Update),
            State(this.clone()),
            Path(template_id),
            Json(req),
        )
    };

    // Downgrades of the three resizable resources
    assert!(
        patch(UpdateCustomTemplateRequest {
            cpu: Some(1),
            ..Default::default()
        })
        .await
        .is_err()
    );
    assert!(
        patch(UpdateCustomTemplateRequest {
            memory: Some(GB),
            ..Default::default()
        })
        .await
        .is_err()
    );
    assert!(
        patch(UpdateCustomTemplateRequest {
            disk_size: Some(10 * GB),
            ..Default::default()
        })
        .await
        .is_err()
    );

    // Out of the plan's range
    assert!(
        patch(UpdateCustomTemplateRequest {
            cpu: Some(64),
            ..Default::default()
        })
        .await
        .is_err()
    );

    // A disk type the plan does not price at all
    assert!(
        patch(UpdateCustomTemplateRequest {
            disk_type: Some("hdd".to_string()),
            ..Default::default()
        })
        .await
        .is_err()
    );

    // Unknown enum spellings
    assert!(
        patch(UpdateCustomTemplateRequest {
            disk_interface: Some("usb".to_string()),
            ..Default::default()
        })
        .await
        .is_err()
    );

    // Permission gate
    assert!(
        admin_update_custom_template(
            no_permissions(),
            State(this.clone()),
            Path(template_id),
            Json(UpdateCustomTemplateRequest::default()),
        )
        .await
        .is_err()
    );

    // Unknown template
    assert!(
        admin_update_custom_template(
            auth(AdminAction::Update),
            State(this),
            Path(9999),
            Json(UpdateCustomTemplateRequest::default()),
        )
        .await
        .is_err()
    );

    // Nothing above was written
    let stored = db.get_custom_vm_template(template_id).await.unwrap();
    assert_eq!(
        (stored.cpu, stored.memory, stored.disk_size),
        (2, 2 * GB, 80 * GB)
    );
}

/// An orphaned template (no VM points at it) is editable and queues nothing.
#[tokio::test]
async fn update_orphan_template_touches_nothing_else() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let out = admin_update_custom_template(
        auth(AdminAction::Update),
        State(state(&db)),
        Path(template_id),
        Json(UpdateCustomTemplateRequest {
            cpu: Some(3),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert!(out.0.data.job_ids.is_empty());
    assert!(out.0.data.template.vm_ids.is_empty());
    assert_eq!(out.0.data.template.cpu, 3);
}

/// Moving a VM onto another plan reprices it without touching the host.
#[tokio::test]
async fn update_can_move_template_to_another_pricing_model() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let other_pricing_id = seed_pricing(&db, 2).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    seed_vm(&db, template_id, 855).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let out = admin_update_custom_template(
        auth(AdminAction::Update),
        State(state(&db)),
        Path(template_id),
        Json(UpdateCustomTemplateRequest {
            pricing_id: Some(other_pricing_id),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(out.0.data.template.pricing_id, other_pricing_id);
    assert!(out.0.data.job_ids.is_empty());
}

/// CPU manufacturer/architecture are reported when the spec pins them, and
/// omitted when it does not.
#[tokio::test]
async fn get_custom_template_reports_pinned_cpu() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let mut t = template(pricing_id);
    t.cpu_mfg = CpuMfg::Intel;
    t.cpu_arch = CpuArch::X86_64;
    t.cpu_features = vec![CpuFeature::AVX2].into();
    let template_id = db.insert_custom_vm_template(&t).await.unwrap();

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let out = admin_get_custom_template(
        auth(AdminAction::View),
        State(state(&db)),
        Path(template_id),
    )
    .await
    .unwrap();
    assert_eq!(out.0.data.cpu_mfg.as_deref(), Some("intel"));
    assert_eq!(out.0.data.cpu_arch.as_deref(), Some("x86_64"));
    assert_eq!(out.0.data.cpu_features, vec!["AVX2".to_string()]);
}

/// Nothing in the schema enforces one VM per template, so a shared row must
/// reprice and reconfigure every VM on it rather than only the first.
#[tokio::test]
async fn update_shared_template_applies_to_every_vm() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    let (vm_a, li_a) = seed_vm(&db, template_id, 855).await;
    let (vm_b, li_b) = seed_vm(&db, template_id, 855).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let out = admin_update_custom_template(
        auth(AdminAction::Update),
        State(state(&db)),
        Path(template_id),
        Json(UpdateCustomTemplateRequest {
            cpu: Some(4),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    assert_eq!(out.0.data.template.vm_ids, vec![vm_a, vm_b]);
    assert_eq!(out.0.data.job_ids.len(), 2);
    for li in [li_a, li_b] {
        assert_eq!(
            db.get_subscription_line_item(li).await.unwrap().amount,
            out.0.data.renewal_amount
        );
    }
}

/// A plan whose currency cannot be parsed passes range validation but cannot be
/// quoted: that must be a 400, not a template stored at an unknowable price.
#[tokio::test]
async fn update_rejects_a_spec_that_cannot_be_priced() {
    crate::verbose_errors_for_tests();
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let mut pricing = db.get_custom_pricing(pricing_id).await.unwrap();
    pricing.currency = "XYZ".to_string();
    db.update_custom_pricing(&pricing).await.unwrap();
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    assert!(
        admin_update_custom_template(
            auth(AdminAction::Update),
            State(state(&db)),
            Path(template_id),
            Json(UpdateCustomTemplateRequest {
                cpu: Some(4),
                ..Default::default()
            }),
        )
        .await
        .is_err()
    );
    // Unpriceable, so nothing was written.
    assert_eq!(db.get_custom_vm_template(template_id).await.unwrap().cpu, 2);
}

#[test]
fn apply_template_patch_maps_every_field() {
    let old = template(1);

    // CPU 0 is refused before the plan's min_cpu ever sees it, because a
    // zero-core VM is a nonsense spec on any plan.
    assert!(
        apply_template_patch(
            &old,
            UpdateCustomTemplateRequest {
                cpu: Some(0),
                ..Default::default()
            }
        )
        .is_err()
    );

    let new = apply_template_patch(
        &old,
        UpdateCustomTemplateRequest {
            cpu: Some(8),
            memory: Some(16 * GB),
            disk_size: Some(200 * GB),
            disk_type: Some("hdd".to_string()),
            disk_interface: Some("scsi".to_string()),
            pricing_id: Some(9),
            ip4_count: Some(2),
            ip6_count: Some(3),
            cpu_mfg: Some(Some("intel".to_string())),
            cpu_arch: Some(Some("x86_64".to_string())),
            cpu_features: Some(Some(vec!["AVX2".to_string()])),
            disk_iops_read: Some(Some(1)),
            disk_iops_write: Some(Some(2)),
            disk_mbps_read: Some(Some(3)),
            disk_mbps_write: Some(Some(4)),
            network_mbps: Some(Some(5)),
            cpu_limit: Some(Some(0.5)),
            firewall_rule_limit: Some(Some(64)),
            transfer_gb: Some(Some(6)),
        },
    )
    .unwrap();

    assert_eq!(new.cpu, 8);
    assert_eq!(new.memory, 16 * GB);
    assert_eq!(new.disk_size, 200 * GB);
    assert_eq!(new.disk_type, DiskType::HDD);
    assert_eq!(new.disk_interface, DiskInterface::SCSI);
    assert_eq!(new.pricing_id, 9);
    assert_eq!((new.ip4_count, new.ip6_count), (2, 3));
    assert_eq!(new.cpu_mfg.to_string(), "intel");
    assert_eq!(new.cpu_features.len(), 1);
    assert_eq!(new.disk_iops_read, Some(1));
    assert_eq!(new.disk_iops_write, Some(2));
    assert_eq!(new.disk_mbps_read, Some(3));
    assert_eq!(new.disk_mbps_write, Some(4));
    assert_eq!(new.network_mbps, Some(5));
    assert_eq!(new.cpu_limit, Some(0.5));
    assert_eq!(new.firewall_rule_limit, Some(64));
    assert_eq!(new.transfer_gb, Some(6));

    // Explicit nulls clear, rather than being ignored like an absent key.
    let cleared = apply_template_patch(
        &new,
        UpdateCustomTemplateRequest {
            cpu_mfg: Some(None),
            cpu_arch: Some(None),
            cpu_features: Some(None),
            disk_iops_read: Some(None),
            disk_iops_write: Some(None),
            disk_mbps_read: Some(None),
            disk_mbps_write: Some(None),
            network_mbps: Some(None),
            cpu_limit: Some(None),
            firewall_rule_limit: Some(None),
            transfer_gb: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(cleared.cpu_mfg, CpuMfg::Unknown);
    assert_eq!(cleared.cpu_arch, CpuArch::Unknown);
    assert!(cleared.cpu_features.is_empty());
    assert_eq!(cleared.disk_iops_read, None);
    assert_eq!(cleared.disk_iops_write, None);
    assert_eq!(cleared.disk_mbps_read, None);
    assert_eq!(cleared.disk_mbps_write, None);
    assert_eq!(cleared.network_mbps, None);
    assert_eq!(cleared.cpu_limit, None);
    assert_eq!(cleared.firewall_rule_limit, None);
    assert_eq!(cleared.transfer_gb, None);

    // An empty patch is a no-op, not a reset.
    let same = apply_template_patch(&old, UpdateCustomTemplateRequest::default()).unwrap();
    assert_eq!(same.cpu, old.cpu);
    assert_eq!(same.transfer_gb, old.transfer_gb);

    for bad in [
        UpdateCustomTemplateRequest {
            disk_type: Some("optane".to_string()),
            ..Default::default()
        },
        UpdateCustomTemplateRequest {
            disk_interface: Some("usb".to_string()),
            ..Default::default()
        },
        UpdateCustomTemplateRequest {
            cpu_mfg: Some(Some("acme".to_string())),
            ..Default::default()
        },
        UpdateCustomTemplateRequest {
            cpu_arch: Some(Some("z80".to_string())),
            ..Default::default()
        },
        UpdateCustomTemplateRequest {
            cpu_features: Some(Some(vec!["telepathy".to_string()])),
            ..Default::default()
        },
    ] {
        assert!(apply_template_patch(&old, bad).is_err());
    }
}

#[test]
fn reject_downgrade_allows_growth_only() {
    let old = template(1);
    assert!(reject_downgrade(&old, &old).is_ok());

    let mut grown = old.clone();
    grown.cpu += 1;
    grown.memory += GB;
    grown.disk_size += GB;
    assert!(reject_downgrade(&old, &grown).is_ok());

    for shrink in [
        VmCustomTemplate {
            cpu: 1,
            ..old.clone()
        },
        VmCustomTemplate {
            memory: GB,
            ..old.clone()
        },
        VmCustomTemplate {
            disk_size: GB,
            ..old.clone()
        },
    ] {
        assert!(reject_downgrade(&old, &shrink).is_err());
    }
}

#[test]
fn host_job_for_picks_the_cheapest_sufficient_job() {
    let vm = MockDb::mock_vm();
    let old = template(1);

    // Nothing the host cares about
    let mut priced_only = old.clone();
    priced_only.ip4_count = 2;
    priced_only.transfer_gb = Some(100);
    priced_only.firewall_rule_limit = Some(64);
    priced_only.pricing_id = 2;
    assert!(host_job_for(&vm, &old, &priced_only, 1).is_none());

    // Caps and disk shape: reconfigure
    let mut capped = old.clone();
    capped.network_mbps = Some(100);
    assert!(matches!(
        host_job_for(&vm, &old, &capped, 7),
        Some(WorkJob::ConfigureVm {
            admin_user_id: Some(7),
            ..
        })
    ));

    // Resizable resources: the full upgrade pipeline, carrying only what moved
    let mut bigger = old.clone();
    bigger.memory = 4 * GB;
    match host_job_for(&vm, &old, &bigger, 1) {
        Some(WorkJob::ProcessVmUpgrade { vm_id, config }) => {
            assert_eq!(vm_id, vm.id);
            assert_eq!(config.new_memory, Some(4 * GB));
            assert_eq!(config.new_cpu, None);
            assert_eq!(config.new_disk, None);
        }
        other => panic!("expected an upgrade job, got {other:?}"),
    }
}

#[tokio::test]
async fn reprice_vm_writes_only_on_change() {
    let db = MockDb::default();
    let pricing_id = seed_pricing(&db, 1).await;
    let template_id = db
        .insert_custom_vm_template(&template(pricing_id))
        .await
        .unwrap();
    let (vm_id, line_item_id) = seed_vm(&db, template_id, 500).await;

    let db: Arc<dyn LNVpsDb> = Arc::new(db);
    let vm = db.get_vm(vm_id).await.unwrap();

    reprice_vm(&db, &vm, 900).await.unwrap();
    assert_eq!(
        db.get_subscription_line_item(line_item_id)
            .await
            .unwrap()
            .amount,
        900
    );

    // Same amount again is a no-op rather than a redundant write.
    reprice_vm(&db, &vm, 900).await.unwrap();
    assert_eq!(
        db.get_subscription_line_item(line_item_id)
            .await
            .unwrap()
            .amount,
        900
    );

    // A VM whose line item is missing is an error, not a silent skip.
    let mut orphan = vm.clone();
    orphan.subscription_line_item_id = 9999;
    assert!(reprice_vm(&db, &orphan, 900).await.is_err());
}

#[tokio::test]
async fn queue_returns_the_stream_id() {
    let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
    let this = state(&db);
    assert!(
        queue(
            &this,
            WorkJob::ConfigureVm {
                vm_id: 1,
                admin_user_id: Some(1),
            }
        )
        .await
        .is_some()
    );
}

#[test]
fn spec_json_reports_the_billable_shape() {
    let t = template(3);
    let json = spec_json(&t);
    assert_eq!(json["cpu"], 2);
    assert_eq!(json["disk_type"], "ssd");
    assert_eq!(json["pricing_id"], 3);
    assert_eq!(json["ip6_count"], 1);
}
