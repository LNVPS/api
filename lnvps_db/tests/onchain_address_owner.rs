use lnvps_db::{
    EncryptedString, IntervalType, LNVpsDbBase, LNVpsDbMysql, LineItemType,
    OnchainAddressOwnerStatus, PaymentMethod, Subscription, SubscriptionLineItem,
    SubscriptionPayment, SubscriptionPaymentType, Vm,
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
    pool.execute("DROP DATABASE IF EXISTS onchain_owner_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE onchain_owner_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/onchain_owner_test"))
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

async fn unpaid_order_with_onchain_quote(
    db: &LNVpsDbMysql,
    address: &str,
    with_vm: bool,
) -> (u64, u64, Option<u64>) {
    let user_id = db.upsert_user(&[7u8; 32]).await.unwrap();
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
    let vm_id = if with_vm {
        Some(
            db.insert_vm(&Vm {
                host_id: 1,
                user_id,
                image_id: 1,
                template_id: Some(1),
                subscription_line_item_id: ids[0],
                disk_id: 1,
                mac_address: "aa:bb:cc:dd:ee:01".to_string(),
                ..Default::default()
            })
            .await
            .unwrap(),
        )
    } else {
        None
    };
    let now = chrono::Utc::now();
    db.insert_subscription_payment(&SubscriptionPayment {
        id: vec![3u8; 32],
        subscription_id: sub_id,
        user_id,
        created: now,
        expires: now,
        amount: 1_000_400,
        currency: "BTC".to_string(),
        payment_method: PaymentMethod::OnChain,
        payment_type: SubscriptionPaymentType::Purchase,
        external_data: EncryptedString::from(address),
        external_id: None,
        is_paid: false,
        rate: 1.0,
        time_value: Some(2592000),
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
    })
    .await
    .unwrap();
    (user_id, sub_id, vm_id)
}

#[tokio::test]
async fn purge_records_owner_and_late_deposit_credits_once() {
    let Some(db) = db().await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    let address = "bcrt1qlatedeposit";
    let (user_id, sub_id, vm_id) = unpaid_order_with_onchain_quote(&db, address, true).await;
    let vm_id = vm_id.unwrap();
    assert!(
        db.get_onchain_address_owner(address)
            .await
            .unwrap()
            .is_none()
    );

    db.hard_delete_vm(vm_id).await.unwrap();
    assert!(
        db.list_subscription_payments(sub_id)
            .await
            .unwrap()
            .is_empty()
    );

    let owner = db
        .get_onchain_address_owner(address)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.user_id, user_id);
    assert_eq!(owner.vm_id, Some(vm_id));
    assert_eq!(owner.subscription_id, Some(sub_id));
    assert_eq!(owner.amount, Some(1_001_000));
    assert_eq!(owner.currency.as_deref(), Some("BTC"));
    assert_eq!(owner.status, OnchainAddressOwnerStatus::Open);
    assert_eq!(owner.address.as_str(), address);

    assert!(
        db.mark_onchain_address_owner_notified(owner.id, "tx1:0")
            .await
            .unwrap()
    );
    assert!(
        !db.mark_onchain_address_owner_notified(owner.id, "tx1:0")
            .await
            .unwrap()
    );

    let note = "tx1:0: late on-chain payment after the order was removed";
    assert_eq!(
        db.credit_onchain_address_owner(owner.id, "tx1:0", 900_000, note)
            .await
            .unwrap(),
        Some(900_000)
    );
    assert_eq!(
        db.credit_onchain_address_owner(owner.id, "tx1:0", 900_000, note)
            .await
            .unwrap(),
        None
    );
    assert!(
        !db.mark_onchain_address_owner_notified(owner.id, "tx1:0")
            .await
            .unwrap()
    );
    assert!(
        db.mark_onchain_address_owner_notified(owner.id, "tx2:1")
            .await
            .unwrap()
    );
    assert_eq!(
        db.credit_onchain_address_owner(owner.id, "tx2:1", 100_000, note)
            .await
            .unwrap(),
        Some(1_000_000)
    );

    let credit = db.get_account_credit(user_id, "BTC").await.unwrap();
    assert_eq!(credit.balance, 1_000_000);
    let owner = db
        .get_onchain_address_owner(address)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.status, OnchainAddressOwnerStatus::Credited);
    assert_eq!(owner.credited_outpoint.as_deref(), Some("tx2:1"));
}

#[tokio::test]
async fn subscription_purge_records_owner() {
    let Some(db) = db().await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    let address = "bcrt1qsubpurge";
    let (user_id, sub_id, _) = unpaid_order_with_onchain_quote(&db, address, false).await;
    db.hard_delete_subscription(sub_id).await.unwrap();

    let owner = db
        .get_onchain_address_owner(address)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.user_id, user_id);
    assert_eq!(owner.subscription_id, Some(sub_id));
    assert_eq!(owner.vm_id, None);
}
