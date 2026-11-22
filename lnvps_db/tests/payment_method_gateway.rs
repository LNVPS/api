use lnvps_db::{LNVpsDbBase, LNVpsDbMysql, UserPaymentMethod};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

async fn db() -> Option<LNVpsDbMysql> {
    let url = std::env::var("LNVPS_TEST_DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    pool.execute("DROP DATABASE IF EXISTS pm_gateway_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE pm_gateway_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/pm_gateway_test"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    Some(db)
}

fn card(user_id: u64, gateway_method_id: Option<u64>) -> UserPaymentMethod {
    UserPaymentMethod {
        user_id,
        provider: "stripe".into(),
        external_id: "pm_1".to_string().into(),
        external_customer_id: Some("cus_1".to_string().into()),
        gateway_method_id,
        enabled: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn gateway_method_id_round_trips_and_defaults_to_none() {
    let Some(db) = db().await else { return };
    let user = db.upsert_user(&[9u8; 32]).await.unwrap();
    let plain = db
        .insert_user_payment_method(&card(user, None))
        .await
        .unwrap();
    let linked = db
        .insert_user_payment_method(&card(user, Some(42)))
        .await
        .unwrap();
    assert_eq!(
        db.get_user_payment_method(plain)
            .await
            .unwrap()
            .gateway_method_id,
        None
    );
    assert_eq!(
        db.get_user_payment_method(linked)
            .await
            .unwrap()
            .gateway_method_id,
        Some(42)
    );

    let mut m = db.get_user_payment_method(plain).await.unwrap();
    m.gateway_method_id = Some(7);
    db.update_user_payment_method(&m).await.unwrap();
    assert_eq!(
        db.get_user_payment_method(plain)
            .await
            .unwrap()
            .gateway_method_id,
        Some(7)
    );
}
