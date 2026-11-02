use lnvps_db::{LNVpsDbBase, LNVpsDbMysql};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

#[tokio::test]
async fn concurrent_migrators_both_finish() {
    let Ok(url) = std::env::var("LNVPS_TEST_DATABASE_URL") else {
        return;
    };
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute("DROP DATABASE IF EXISTS concurrent_migrate_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE concurrent_migrate_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let target = format!("{base}/concurrent_migrate_test");
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let target = target.clone();
        tasks.push(tokio::spawn(async move {
            let db = LNVpsDbMysql::new(&target).await.unwrap();
            db.migrate().await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
}
