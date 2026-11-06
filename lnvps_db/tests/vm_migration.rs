use lnvps_db::{LNVpsDbBase, LNVpsDbMysql, VmMigration, VmMigrationState};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

async fn db() -> Option<LNVpsDbMysql> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute("DROP DATABASE IF EXISTS vm_migration_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE vm_migration_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/vm_migration_test"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    db.execute("ALTER TABLE vm_migration DROP FOREIGN KEY fk_vm_migration_vm")
        .await
        .unwrap();
    Some(db)
}

#[tokio::test]
async fn one_active_migration_per_vm_and_round_trip() {
    let Some(db) = db().await else { return };
    let m = VmMigration {
        vm_id: 7,
        source_host_id: 1,
        source_disk_id: 1,
        target_host_id: 2,
        target_disk_id: 3,
        options: "{}".to_string(),
        initiated_by: Some(9),
        ..Default::default()
    };
    let id = db.insert_vm_migration(&m).await.unwrap();
    assert!(
        db.insert_vm_migration(&m).await.is_err(),
        "a second in-progress migration of the same VM must be refused by the database"
    );

    let mut active = db.get_active_vm_migration(7).await.unwrap().unwrap();
    assert_eq!(active.id, id);
    assert_eq!(active.initiated_by, Some(9));
    active.phase = "copy".to_string();
    active.bytes_copied = 42;
    active.checksum = Some("ab".repeat(32));
    active.state = VmMigrationState::Completed;
    active.source_retained = true;
    active.finished = Some(chrono::Utc::now());
    db.update_vm_migration(&active).await.unwrap();

    assert!(db.get_active_vm_migration(7).await.unwrap().is_none());
    let open = db.list_open_vm_migrations().await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].bytes_copied, 42);
    assert!(open[0].source_retained);

    db.insert_vm_migration(&m).await.unwrap();
    assert_eq!(db.list_vm_migrations(7).await.unwrap().len(), 2);
}
