use lnvps_db::audit::verify_chain;
use lnvps_db::{AuditFilter, LNVpsDbBase, LNVpsDbMysql, NewAuditEntry};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

async fn db() -> Option<(LNVpsDbMysql, sqlx::MySqlPool)> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute("DROP DATABASE IF EXISTS audit_log_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE audit_log_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let url = format!("{base}/audit_log_test");
    let db = LNVpsDbMysql::new(&url).await.unwrap();
    db.migrate().await.unwrap();
    let raw = MySqlPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    Some((db, raw))
}

#[tokio::test]
async fn appended_rows_chain_and_verify() {
    let Some((db, _)) = db().await else { return };
    for i in 0..5 {
        db.append_audit(NewAuditEntry::new("admin", Some(1), "admin.refund").target("vm", i))
            .await
            .unwrap();
    }
    let rows = db.audit_range(0, 100).await.unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(verify_chain(&rows, None).unwrap().last_id, 5);
    let found = db
        .list_audit(
            &AuditFilter {
                target_id: Some("3".into()),
                ..Default::default()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
}

#[tokio::test]
async fn the_database_refuses_updates_and_deletes() {
    let Some((db, raw)) = db().await else { return };
    db.append_audit(NewAuditEntry::new("user", Some(1), "auth.login"))
        .await
        .unwrap();
    assert!(
        raw.execute("update audit_log set actor_id = 2")
            .await
            .is_err()
    );
    assert!(raw.execute("delete from audit_log").await.is_err());
    assert_eq!(db.audit_range(0, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn concurrent_appends_keep_one_chain() {
    let Some((db, _)) = db().await else { return };
    let db = std::sync::Arc::new(db);
    let mut tasks = Vec::new();
    for i in 0..8u64 {
        let db = db.clone();
        tasks.push(tokio::spawn(async move {
            db.append_audit(NewAuditEntry::new("system", None, "x").target("n", i))
                .await
                .unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let rows = db.audit_range(0, 100).await.unwrap();
    assert_eq!(rows.len(), 8);
    assert!(verify_chain(&rows, None).is_ok());
}

#[tokio::test]
async fn old_ips_are_truncated_without_breaking_the_chain() {
    let Some((db, raw)) = db().await else { return };
    let mut e = NewAuditEntry::new("user", Some(1), "auth.login");
    e.ip = Some("203.0.113.77".into());
    let old = chrono::Utc::now().timestamp() - 120 * 86400;
    let sealed = lnvps_db::AuditEntry::seal(1, old, lnvps_db::audit::GENESIS_HASH, e.clone());
    sqlx::query("insert into audit_log (id, created, actor_type, actor_id, ip, action, prev_hash, hash) values (?,?,?,?,?,?,?,?)")
        .bind(sealed.id)
        .bind(sealed.created)
        .bind(&sealed.actor_type)
        .bind(sealed.actor_id)
        .bind(&sealed.ip)
        .bind(&sealed.action)
        .bind(&sealed.prev_hash)
        .bind(&sealed.hash)
        .execute(&raw)
        .await
        .unwrap();
    db.append_audit(e).await.unwrap();
    assert_eq!(db.truncate_audit_ips(90).await.unwrap(), 1);
    assert_eq!(db.truncate_audit_ips(90).await.unwrap(), 0);
    let rows = db.audit_range(0, 10).await.unwrap();
    assert_eq!(rows[0].ip.as_deref(), Some("203.0.113.0"));
    assert_eq!(rows[1].ip.as_deref(), Some("203.0.113.77"));
    assert!(verify_chain(&rows, None).is_ok());
    assert!(
        raw.execute("update audit_log set actor_id = 2")
            .await
            .is_err()
    );
}
