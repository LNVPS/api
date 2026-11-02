use sqlx::migrate::Migrator;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Executor, MySqlPool, Row};
use std::borrow::Cow;

const UNIQUE_MIGRATION: i64 = 20261024100000;

async fn pool() -> Option<MySqlPool> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute("DROP DATABASE IF EXISTS custom_domain_unique_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE custom_domain_unique_test")
        .await
        .unwrap();
    pool.execute("USE custom_domain_unique_test").await.unwrap();
    Some(pool)
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

async fn insert(
    pool: &MySqlPool,
    name: &str,
    domain: Option<&str>,
    deleted: bool,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO app_deployment (user_id, app_id, cluster_id, subscription_line_item_id, \
         name, namespace, custom_domain, custom_domain_verified, deleted) \
         VALUES (1, 1, 1, 1, ?, ?, ?, 1, ?)",
    )
    .bind(name)
    .bind(format!("ns-{name}"))
    .bind(domain)
    .bind(deleted)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn domain_of(pool: &MySqlPool, name: &str) -> (Option<String>, bool) {
    let row = sqlx::query(
        "SELECT custom_domain, CAST(custom_domain_verified AS UNSIGNED) FROM app_deployment WHERE name = ?",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    (row.get(0), row.get::<u64, _>(1) == 1)
}

#[tokio::test]
async fn migration_keeps_oldest_claim_and_unique_index_rejects_a_second() {
    let Some(pool) = pool().await else {
        eprintln!("LNVPS_TEST_DATABASE_URL not set, skipping");
        return;
    };
    migrate(&pool, |v| v < UNIQUE_MIGRATION).await;
    pool.execute("SET FOREIGN_KEY_CHECKS = 0").await.unwrap();

    insert(&pool, "oldest", Some("blog.example.org"), false)
        .await
        .unwrap();
    insert(&pool, "newer", Some("blog.example.org"), false)
        .await
        .unwrap();
    insert(&pool, "newest", Some("blog.example.org"), false)
        .await
        .unwrap();
    insert(&pool, "gone", Some("blog.example.org"), true)
        .await
        .unwrap();
    insert(&pool, "solo", Some("solo.example.org"), false)
        .await
        .unwrap();
    insert(&pool, "none-a", None, false).await.unwrap();
    insert(&pool, "none-b", None, false).await.unwrap();

    pool.execute("SET FOREIGN_KEY_CHECKS = 1").await.unwrap();
    migrate(&pool, |_| true).await;
    pool.execute("SET FOREIGN_KEY_CHECKS = 0").await.unwrap();

    assert_eq!(
        domain_of(&pool, "oldest").await,
        (Some("blog.example.org".to_string()), true)
    );
    assert_eq!(domain_of(&pool, "newer").await, (None, false));
    assert_eq!(domain_of(&pool, "newest").await, (None, false));
    assert_eq!(
        domain_of(&pool, "gone").await.0.as_deref(),
        Some("blog.example.org")
    );
    assert_eq!(
        domain_of(&pool, "solo").await.0.as_deref(),
        Some("solo.example.org")
    );

    assert!(
        insert(&pool, "thief", Some("blog.example.org"), false)
            .await
            .is_err()
    );
    insert(&pool, "none-c", None, false).await.unwrap();
    insert(&pool, "gone-too", Some("blog.example.org"), true)
        .await
        .unwrap();
    insert(&pool, "free", Some("free.example.org"), false)
        .await
        .unwrap();

    pool.execute("DROP DATABASE custom_domain_unique_test")
        .await
        .unwrap();
}
