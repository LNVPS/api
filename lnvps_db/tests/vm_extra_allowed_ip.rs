use lnvps_db::{LNVpsDbBase, LNVpsDbMysql, VmExtraAllowedIp};
use sqlx::migrate::Migrator;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Executor, MySqlPool};
use std::borrow::Cow;

const EXTRA_IP_MIGRATION: i64 = 20261124151350;
const VIP4: &str = "185.18.221.135";
const VIP6: &str = "2a13:2c0::4dbc:733d:4d68:2e08";

async fn fresh(name: &str) -> Option<(MySqlPool, String)> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute(format!("DROP DATABASE IF EXISTS {name}").as_str())
        .await
        .unwrap();
    pool.execute(format!("CREATE DATABASE {name}").as_str())
        .await
        .unwrap();
    pool.execute(format!("USE {name}").as_str()).await.unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    Some((pool, format!("{base}/{name}")))
}

async fn migrate(pool: &MySqlPool, upto: impl Fn(i64) -> bool) {
    let all = sqlx::migrate!("./migrations");
    let migrations: Vec<_> = all
        .migrations
        .iter()
        .filter(|m| upto(m.version))
        .cloned()
        .collect();
    let migrator = Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    };
    migrator.run(pool).await.unwrap();
}

async fn insert_vm(pool: &MySqlPool, id: u64, user_id: u64, deleted: bool) {
    sqlx::query(
        "INSERT INTO vm (id, host_id, user_id, image_id, template_id, ssh_key_id, disk_id, \
         mac_address, deleted, subscription_line_item_id) VALUES (?, 1, ?, 1, 1, 1, 1, '', ?, 1)",
    )
    .bind(id)
    .bind(user_id)
    .bind(deleted)
    .execute(pool)
    .await
    .unwrap();
}

async fn extras(pool: &MySqlPool) -> Vec<(u64, String, String)> {
    sqlx::query_as("SELECT vm_id, ip, comment FROM vm_extra_allowed_ip ORDER BY vm_id, ip")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn migration_applies_on_an_empty_database() {
    let Some((pool, _)) = fresh("extra_ip_empty").await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    migrate(&pool, |_| true).await;
    assert!(extras(&pool).await.is_empty());
    pool.execute("DROP DATABASE extra_ip_empty").await.unwrap();
}

#[tokio::test]
async fn migration_backfills_the_ingress_vips_on_the_k8s_vms_only() {
    let Some((pool, _)) = fresh("extra_ip_populated").await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    migrate(&pool, |v| v < EXTRA_IP_MIGRATION).await;
    pool.execute("SET FOREIGN_KEY_CHECKS = 0").await.unwrap();
    insert_vm(&pool, 2068, 1, false).await;
    insert_vm(&pool, 2069, 1, false).await;
    insert_vm(&pool, 2146, 1, false).await;
    insert_vm(&pool, 2070, 1, false).await;
    pool.execute("SET FOREIGN_KEY_CHECKS = 1").await.unwrap();
    migrate(&pool, |_| true).await;

    let mut want = Vec::new();
    for vm in [2068u64, 2069, 2146] {
        for ip in [VIP4, VIP6] {
            want.push((vm, ip.to_string(), "k8s ingress VIP".to_string()));
        }
    }
    want.sort();
    assert_eq!(extras(&pool).await, want);
    pool.execute("DROP DATABASE extra_ip_populated")
        .await
        .unwrap();
}

#[tokio::test]
async fn migration_skips_deleted_vms_and_vips_owned_by_another_user() {
    let Some((pool, _)) = fresh("extra_ip_other_user").await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    migrate(&pool, |v| v < EXTRA_IP_MIGRATION).await;
    pool.execute("SET FOREIGN_KEY_CHECKS = 0").await.unwrap();
    insert_vm(&pool, 2068, 1, false).await;
    insert_vm(&pool, 2069, 2, false).await;
    insert_vm(&pool, 2146, 1, true).await;
    insert_vm(&pool, 2147, 1, false).await;
    sqlx::query("INSERT INTO vm_ip_assignment (vm_id, ip_range_id, ip) VALUES (2068, 1, ?)")
        .bind(VIP4)
        .execute(&pool)
        .await
        .unwrap();
    pool.execute("SET FOREIGN_KEY_CHECKS = 1").await.unwrap();
    migrate(&pool, |_| true).await;

    let got: Vec<(u64, String)> = extras(&pool)
        .await
        .into_iter()
        .map(|e| (e.0, e.1))
        .collect();
    assert_eq!(
        got,
        vec![
            (2068, VIP4.to_string()),
            (2068, VIP6.to_string()),
            (2069, VIP6.to_string()),
        ]
    );
    pool.execute("DROP DATABASE extra_ip_other_user")
        .await
        .unwrap();
}

#[tokio::test]
async fn extra_allowed_ips_round_trip_per_vm() {
    let Some((pool, url)) = fresh("extra_ip_round_trip").await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    let db = LNVpsDbMysql::new(&url).await.unwrap();
    db.migrate().await.unwrap();
    pool.execute("SET FOREIGN_KEY_CHECKS = 0").await.unwrap();
    insert_vm(&pool, 10, 1, false).await;
    insert_vm(&pool, 11, 1, false).await;
    pool.execute("SET FOREIGN_KEY_CHECKS = 1").await.unwrap();

    let entry = |vm_id: u64, ip: &str| VmExtraAllowedIp {
        vm_id,
        ip: ip.to_string(),
        comment: "k8s ingress VIP".to_string(),
        ..Default::default()
    };
    let a = db
        .insert_vm_extra_allowed_ip(&entry(10, VIP4))
        .await
        .unwrap();
    db.insert_vm_extra_allowed_ip(&entry(10, VIP6))
        .await
        .unwrap();
    db.insert_vm_extra_allowed_ip(&entry(11, VIP4))
        .await
        .unwrap();
    assert!(
        db.insert_vm_extra_allowed_ip(&entry(10, VIP4))
            .await
            .is_err()
    );

    let listed = db.list_vm_extra_allowed_ips(10).await.unwrap();
    assert_eq!(
        listed.iter().map(|e| e.ip.as_str()).collect::<Vec<_>>(),
        vec![VIP4, VIP6]
    );
    assert_eq!(listed[0].comment, "k8s ingress VIP");

    assert!(db.delete_vm_extra_allowed_ip(11, a).await.is_err());
    db.delete_vm_extra_allowed_ip(10, a).await.unwrap();
    assert_eq!(db.list_vm_extra_allowed_ips(10).await.unwrap().len(), 1);
    assert_eq!(db.list_vm_extra_allowed_ips(11).await.unwrap().len(), 1);
    pool.execute("DROP DATABASE extra_ip_round_trip")
        .await
        .unwrap();
}
