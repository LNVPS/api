use lnvps_db::{
    AdminDb, IpOrder, IpOrderState, IpProvider, IpProviderKind, IpProviderRegion, IpRange,
    LNVpsDbBase, LNVpsDbMysql,
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
    pool.execute("DROP DATABASE IF EXISTS ip_orders_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE ip_orders_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/ip_orders_test"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    for sql in [
        "insert ignore into company(id,name,email,base_currency) values(1,'C','c@example.com','EUR')",
        "insert into region(id,name,enabled,company_id) values(1,'R',1,1)",
    ] {
        db.execute(sql).await.unwrap();
    }
    Some(db)
}

fn order(key: Option<&str>) -> IpOrder {
    IpOrder {
        provider: "ovh".to_string(),
        region_id: 1,
        idempotency_key: key.map(|k| k.to_string()),
        country: Some("IE".to_string()),
        prefix_len: 32,
        quantity: 1,
        cost: 199,
        currency: "EUR".to_string(),
        created: chrono::Utc::now(),
        ..Default::default()
    }
}

#[tokio::test]
async fn ip_orders_migrate_and_round_trip() {
    let Some(db) = db().await else { return };
    ip_order_lifecycle_round_trips(&db).await;
    bought_range_links_to_its_order(&db).await;
    ip_provider_config_round_trips(&db).await;
}

async fn ip_order_lifecycle_round_trips(db: &LNVpsDbMysql) {
    let id = db.insert_ip_order(&order(Some("k1"))).await.unwrap();
    assert!(db.insert_ip_order(&order(Some("k1"))).await.is_err());
    let got = db.get_ip_order_by_key("k1").await.unwrap().unwrap();
    assert_eq!(got.id, id);
    assert_eq!(got.state, IpOrderState::AwaitingApproval);

    assert!(
        db.transition_ip_order(id, IpOrderState::AwaitingApproval, IpOrderState::Approved)
            .await
            .unwrap()
    );
    assert!(
        !db.transition_ip_order(id, IpOrderState::AwaitingApproval, IpOrderState::Approved)
            .await
            .unwrap()
    );

    let mut o = db.get_ip_order(id).await.unwrap();
    o.state = IpOrderState::Ordered;
    o.provider_order_id = Some("42".to_string());
    o.ordered_at = Some(chrono::Utc::now());
    db.update_ip_order(&o).await.unwrap();

    let since = chrono::Utc::now() - chrono::Duration::days(1);
    assert_eq!(db.sum_ip_order_cost_since(since, "EUR").await.unwrap(), 199);
    assert_eq!(db.sum_ip_order_cost_since(since, "USD").await.unwrap(), 0);

    let (rows, total) = db
        .list_ip_orders(Some(IpOrderState::Ordered), Some(1), 10, 0)
        .await
        .unwrap();
    assert_eq!((rows.len(), total), (1, 1));
    let (rows, _) = db
        .list_ip_orders(Some(IpOrderState::Failed), None, 10, 0)
        .await
        .unwrap();
    assert!(rows.is_empty());

    db.insert_ip_order_audit(id, "ordered", Some("42"), Some(1))
        .await
        .unwrap();
    assert_eq!(db.list_ip_order_audit(id).await.unwrap().len(), 1);
}

async fn bought_range_links_to_its_order(db: &LNVpsDbMysql) {
    let id = db.insert_ip_order(&order(None)).await.unwrap();
    let range_id = db
        .insert_ip_range(&IpRange {
            cidr: "203.0.113.5/32".to_string(),
            gateway: "203.0.113.254".to_string(),
            enabled: true,
            region_id: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        db.get_ip_range_by_cidr("203.0.113.5/32")
            .await
            .unwrap()
            .is_some()
    );
    let link = db
        .insert_ip_order_range(id, range_id, "203.0.113.5/32")
        .await
        .unwrap();
    assert!(
        db.insert_ip_order_range(id, range_id, "203.0.113.5/32")
            .await
            .is_err()
    );
    let found = db
        .get_ip_order_range_by_range(range_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, link);
    assert!(found.released_at.is_none());

    db.set_ip_range_enabled(range_id, false).await.unwrap();
    assert!(!db.get_ip_range(range_id).await.unwrap().enabled);

    db.mark_ip_order_range_released(link).await.unwrap();
    let found = db
        .get_ip_order_range_by_range(range_id)
        .await
        .unwrap()
        .unwrap();
    assert!(found.released_at.is_some());
    let (rows, total) = db.list_ip_order_ranges(10, 0).await.unwrap();
    assert_eq!((rows.len(), total), (1, 1));
    let _ = db.admin_get_ip_range(range_id).await.unwrap();
}

async fn ip_provider_config_round_trips(db: &LNVpsDbMysql) {
    let p = IpProvider {
        id: 0,
        name: "ovh".to_string(),
        kind: IpProviderKind::Ovh,
        enabled: true,
        url: "https://eu.api.ovh.com".to_string(),
        token: "a:b:c".into(),
        subsidiary: "IE".to_string(),
        rir: "ripe".to_string(),
        gateway: "203.0.113.254".to_string(),
        access_policy_id: None,
        approval_required: true,
        monthly_spend_cap: 5000,
        currency: "EUR".to_string(),
        enable_ranges_on_delivery: true,
    };
    let id = db.insert_ip_provider(&p).await.unwrap();
    assert!(db.insert_ip_provider(&p).await.is_err());
    let got = db.get_ip_provider_by_name("ovh").await.unwrap().unwrap();
    assert_eq!(got.id, id);
    assert_eq!(got.token.as_str(), "a:b:c");
    assert!(got.approval_required);

    let mut upd = got.clone();
    upd.enabled = false;
    upd.monthly_spend_cap = 10;
    db.update_ip_provider(&upd).await.unwrap();
    let got = db.get_ip_provider(id).await.unwrap();
    assert!(!got.enabled);
    assert_eq!(got.monthly_spend_cap, 10);

    let rule = IpProviderRegion {
        id: 0,
        provider_id: id,
        region_id: 1,
        country: Some("IE".to_string()),
        destination: None,
        prefix_len: 32,
        quantity: 2,
        auto_threshold: Some(5),
        enabled: true,
    };
    let rid = db.insert_ip_provider_region(&rule).await.unwrap();
    assert!(db.insert_ip_provider_region(&rule).await.is_err());
    let mut r = db.get_ip_provider_region(rid).await.unwrap();
    assert_eq!(r.quantity, 2);
    r.auto_threshold = None;
    db.update_ip_provider_region(&r).await.unwrap();
    assert_eq!(
        db.list_ip_provider_regions(Some(id), Some(1))
            .await
            .unwrap()[0]
            .auto_threshold,
        None
    );
    assert!(
        db.list_ip_provider_regions(Some(id), Some(9))
            .await
            .unwrap()
            .is_empty()
    );

    let mut o = IpOrder {
        provider: "ovh".to_string(),
        region_id: 1,
        prefix_len: 32,
        quantity: 1,
        created: chrono::Utc::now(),
        ..Default::default()
    };
    o.id = db.insert_ip_order(&o).await.unwrap();
    assert!(db.delete_ip_provider(id).await.is_err());

    let id2 = db
        .insert_ip_provider(&IpProvider {
            name: "other".to_string(),
            ..p.clone()
        })
        .await
        .unwrap();
    db.insert_ip_provider_region(&IpProviderRegion {
        provider_id: id2,
        ..rule.clone()
    })
    .await
    .unwrap();
    db.delete_ip_provider(id2).await.unwrap();
    assert!(
        db.list_ip_provider_regions(Some(id2), None)
            .await
            .unwrap()
            .is_empty()
    );
}
