use lnvps_db::{
    IntervalType, LNVpsDbBase, LNVpsDbMysql, LineItemType, Subscription, SubscriptionLineItem, Vm,
    VmAddonKind, VmAddonPrice,
};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

async fn db() -> Option<LNVpsDbMysql> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute("DROP DATABASE IF EXISTS vm_addons_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE vm_addons_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/vm_addons_test"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    for sql in [
        "insert ignore into company(id,name,email,base_currency) values(1,'C','c@example.com','EUR')",
        "insert into region(id,name,enabled,company_id) values(1,'R',1,1)",
        "insert into vm_host(id,kind,region_id,name,ip,cpu,memory,enabled,api_token) values(1,65535,1,'h','https://localhost',4,4294967296,1,'')",
        "insert into vm_host_disk(id,host_id,name,size,kind,interface,enabled) values(1,1,'d',1000000000000,1,2,1)",
        "insert into vm_os_image(id,distribution,flavour,version,enabled,url,release_date) values(1,0,'Server','24.04',1,'https://example.com/i.img','2024-04-25')",
        "insert into vm_cost_plan(id,name,amount,currency,interval_amount,interval_type) values(1,'p',200,'EUR',1,1)",
        "insert into vm_template(id,name,enabled,cpu,memory,disk_size,disk_type,disk_interface,cost_plan_id,region_id) values(1,'t',1,1,1073741824,42949672960,1,2,1,1)",
    ] {
        db.execute(sql).await.unwrap();
    }
    Some(db)
}

async fn vm_with_subscription(db: &LNVpsDbMysql) -> (u64, u64, u64) {
    let user_id = db.upsert_user(&[9u8; 32]).await.unwrap();
    let (sub_id, ids) = db
        .insert_subscription_with_line_items(
            &Subscription {
                id: 0,
                user_id,
                company_id: 1,
                name: "s".to_string(),
                description: None,
                created: chrono::Utc::now(),
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
    let vm_id = db
        .insert_vm(&Vm {
            host_id: 1,
            user_id,
            image_id: 1,
            template_id: Some(1),
            subscription_line_item_id: ids[0],
            disk_id: 1,
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    (vm_id, sub_id, ids[0])
}

#[tokio::test]
async fn set_vm_addon_creates_then_updates_one_child_line() {
    let Some(db) = db().await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    let (vm_id, sub_id, vm_line) = vm_with_subscription(&db).await;

    let first = db
        .set_vm_addon(vm_id, VmAddonKind::Snapshot, 2, 200, "VM - 2x snapshot")
        .await
        .unwrap();
    assert_eq!(first.quantity, 2);
    let line = db
        .get_subscription_line_item(first.subscription_line_item_id)
        .await
        .unwrap();
    assert_eq!(line.subscription_id, sub_id);
    assert_eq!(line.subscription_type, LineItemType::VmAddon);
    assert_eq!(line.parent_line_item_id, Some(vm_line));
    assert_eq!(line.amount, 200);
    assert!(line.is_active());

    let second = db
        .set_vm_addon(vm_id, VmAddonKind::Snapshot, 0, 0, "VM - 0x snapshot")
        .await
        .unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(
        second.subscription_line_item_id,
        first.subscription_line_item_id
    );
    let line = db
        .get_subscription_line_item(first.subscription_line_item_id)
        .await
        .unwrap();
    assert_eq!(line.amount, 0);
    assert!(!line.is_active());
    assert_eq!(
        db.list_vm_addons(vm_id).await.unwrap(),
        vec![second.clone()]
    );
    assert_eq!(
        db.get_vm_addon_by_line_item(line.id).await.unwrap(),
        Some(second)
    );

    db.hard_delete_vm(vm_id).await.unwrap();
    assert!(db.list_vm_addons(vm_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn addon_prices_are_unique_per_region_and_kind() {
    let Some(db) = db().await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    let price = VmAddonPrice {
        id: 0,
        region_id: 1,
        kind: VmAddonKind::Snapshot,
        currency: "MEUR".to_string(),
        monthly_amount: 1_000_000,
        max_quantity: 5,
        enabled: true,
        created: chrono::Utc::now(),
    };
    let id = db.insert_vm_addon_price(&price).await.unwrap();
    assert!(db.insert_vm_addon_price(&price).await.is_err());

    let mut stored = db.get_vm_addon_price(id).await.unwrap();
    assert_eq!(stored.currency, "MEUR");
    stored.monthly_amount = 7;
    stored.enabled = false;
    db.update_vm_addon_price(&stored).await.unwrap();
    let found = db
        .get_vm_addon_price_for_region(1, VmAddonKind::Snapshot)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.monthly_amount, 7);
    assert!(!found.enabled);
    let (rows, total) = db.list_vm_addon_prices(10, 0).await.unwrap();
    assert_eq!((rows.len(), total), (1, 1));
    db.delete_vm_addon_price(id).await.unwrap();
    assert!(
        db.get_vm_addon_price_for_region(1, VmAddonKind::Snapshot)
            .await
            .unwrap()
            .is_none()
    );
}
