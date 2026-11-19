use lnvps_api::key_rotation::rotate_all;
use lnvps_db::{EncryptionContext, LNVpsDb, LNVpsDbBase, LNVpsDbMysql};
use sqlx::Executor;
use sqlx::mysql::MySqlPoolOptions;

const KEY_A: [u8; 32] = [0xaa; 32];
const KEY_B: [u8; 32] = [0xbb; 32];

fn init_global() -> &'static EncryptionContext {
    let _ =
        EncryptionContext::init_from_hex_with_previous(&hex::encode(KEY_B), &[hex::encode(KEY_A)]);
    EncryptionContext::get().unwrap()
}

async fn fresh_db(name: &str) -> Option<LNVpsDbMysql> {
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
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/{name}")).await.unwrap();
    db.migrate().await.unwrap();
    Some(db)
}

async fn raw(db: &LNVpsDbMysql, column: &str, id: u64) -> String {
    db.fetch_raw_strings(&format!("select id, {column} from users where id = {id}"))
        .await
        .unwrap()
        .remove(0)
        .1
}

const BILLING: [(&str, &str); 7] = [
    ("billing_name", "Ada Lovelace"),
    ("billing_address_1", "12 High Street"),
    ("billing_address_2", "Flat 3"),
    ("billing_city", "Dublin"),
    ("billing_state", "Leinster"),
    ("billing_postcode", "D02 X285"),
    ("billing_tax_id", "IE1234567T"),
];

async fn seed_user(db: &LNVpsDbMysql, pubkey: u8, stored: &dyn Fn(&str) -> String) -> u64 {
    let id = db.upsert_user(&[pubkey; 32]).await.unwrap();
    let sets: Vec<String> = BILLING
        .iter()
        .map(|(c, v)| format!("{c} = '{}'", stored(v)))
        .collect();
    db.execute(&format!(
        "update users set {} where id = {id}",
        sets.join(", ")
    ))
    .await
    .unwrap();
    id
}

fn assert_billing_reads_back(user: &lnvps_db::User) {
    assert_eq!(user.billing_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.billing_address_1.as_deref(), Some("12 High Street"));
    assert_eq!(user.billing_address_2.as_deref(), Some("Flat 3"));
    assert_eq!(user.billing_city.as_deref(), Some("Dublin"));
    assert_eq!(user.billing_state.as_deref(), Some("Leinster"));
    assert_eq!(user.billing_postcode.as_deref(), Some("D02 X285"));
    assert_eq!(user.billing_tax_id.as_deref(), Some("IE1234567T"));
}

#[tokio::test]
async fn legacy_plaintext_billing_reads_then_is_encrypted_by_rotation() {
    let ctx = init_global();
    let Some(db) = fresh_db("rotation_plaintext_test").await else {
        return;
    };
    let id = seed_user(&db, 1, &|v| v.to_string()).await;

    assert_eq!(raw(&db, "billing_tax_id", id).await, "IE1234567T");
    assert_billing_reads_back(&db.get_user(id).await.unwrap());

    let changed = rotate_all(&db, ctx).await.unwrap();
    assert!(changed >= 7);

    for (column, plain) in BILLING {
        let stored = raw(&db, column, id).await;
        assert!(
            stored.starts_with(&format!("ENC1:{}:", ctx.key_id())),
            "{column} not ciphertext: {stored}"
        );
        assert!(!stored.contains(plain));
    }
    assert_billing_reads_back(&db.get_user(id).await.unwrap());
    assert_eq!(rotate_all(&db, ctx).await.unwrap(), 0);
}

#[tokio::test]
async fn updating_a_user_writes_ciphertext_for_billing_fields() {
    let ctx = init_global();
    let Some(db) = fresh_db("rotation_write_test").await else {
        return;
    };
    let id = seed_user(&db, 2, &|v| v.to_string()).await;
    let user = db.get_user(id).await.unwrap();
    db.update_user(&user).await.unwrap();
    let stored = raw(&db, "billing_name", id).await;
    assert!(stored.starts_with(&format!("ENC1:{}:", ctx.key_id())));
    assert_billing_reads_back(&db.get_user(id).await.unwrap());
}

#[tokio::test]
async fn rotating_from_key_a_to_b_keeps_every_row_readable_after_a_is_dropped() {
    let ctx = init_global();
    let Some(db) = fresh_db("rotation_a_to_b_test").await else {
        return;
    };
    let ctx_a = EncryptionContext::from_raw_keys(KEY_A, &[]);
    let id = seed_user(&db, 3, &|v| ctx_a.encrypt(v).unwrap()).await;
    for (column, _) in BILLING {
        assert!(
            raw(&db, column, id)
                .await
                .starts_with(&format!("ENC1:{}:", ctx_a.key_id()))
        );
    }

    assert_billing_reads_back(&db.get_user(id).await.unwrap());

    let changed = rotate_all(&db, ctx).await.unwrap();
    assert!(changed >= 7);
    for (column, plain) in BILLING {
        let stored = raw(&db, column, id).await;
        assert!(
            stored.starts_with(&format!("ENC1:{}:", ctx.key_id())),
            "{column}"
        );
        let only_b = EncryptionContext::from_raw_keys(KEY_B, &[]);
        assert_eq!(only_b.decrypt(&stored).unwrap(), plain);
        assert!(ctx_a.decrypt(&stored).is_err());
    }
    assert_billing_reads_back(&db.get_user(id).await.unwrap());
}
