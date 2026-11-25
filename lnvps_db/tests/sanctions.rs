use chrono::Utc;
use lnvps_db::{
    LNVpsDbBase, LNVpsDbMysql, PaymentMethod, PaymentScreening, PaymentScreeningFilter,
    SanctionsField, SanctionsList, SanctionsMatch, SanctionsMatchFilter, SanctionsMatchStatus,
    SanctionsSubject, ScreeningMode,
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
    pool.execute("DROP DATABASE IF EXISTS sanctions_test")
        .await
        .unwrap();
    pool.execute("CREATE DATABASE sanctions_test")
        .await
        .unwrap();
    let base = url.rsplit_once('/').map(|(b, _)| b).unwrap_or(&url);
    let db = LNVpsDbMysql::new(&format!("{base}/sanctions_test"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    Some(db)
}

fn list(source: &str, sha: &str) -> SanctionsList {
    SanctionsList {
        source: source.into(),
        version: format!("v-{sha}"),
        sha256: sha.into(),
        entry_count: 1,
        entries: vec![1, 2, 3],
        fetched: Utc::now(),
        checked: Utc::now(),
        ..Default::default()
    }
}

fn hit(payment_ref: &str, status: SanctionsMatchStatus) -> SanctionsMatch {
    SanctionsMatch {
        subject: SanctionsSubject::Payment,
        user_id: Some(5),
        payment_ref: Some(payment_ref.into()),
        field: SanctionsField::Address,
        subject_value: "bc1qfixture".into(),
        subject_hash: vec![7u8; 32],
        list_source: "ofac_sdn".into(),
        list_version: "v".into(),
        list_fetched: Some(Utc::now()),
        entry_id: "90001".into(),
        entry_name: "Fixture".into(),
        score: 1.0,
        status,
        ..Default::default()
    }
}

#[tokio::test]
async fn lists_keep_the_latest_per_source_and_prune() {
    let Some(db) = db().await else { return };
    let a = db
        .insert_sanctions_list(&list("ofac_sdn", "a"))
        .await
        .unwrap();
    db.insert_sanctions_list(&list("eu_fsf", "e"))
        .await
        .unwrap();
    let b = db
        .insert_sanctions_list(&list("ofac_sdn", "b"))
        .await
        .unwrap();
    let latest = db.list_sanctions_lists().await.unwrap();
    assert_eq!(latest.len(), 2);
    assert_eq!(
        latest.iter().find(|l| l.source == "ofac_sdn").unwrap().id,
        b
    );
    assert_eq!(
        db.get_sanctions_list(a).await.unwrap().entries,
        vec![1, 2, 3]
    );
    db.touch_sanctions_list(b).await.unwrap();
    assert_eq!(db.prune_sanctions_lists("ofac_sdn", 1).await.unwrap(), 1);
    assert!(db.get_sanctions_list(a).await.is_err());
}

#[tokio::test]
async fn matches_dedupe_filter_and_resolve_once() {
    let Some(db) = db().await else { return };
    let id = db
        .insert_sanctions_match(&hit("tx:0", SanctionsMatchStatus::Held))
        .await
        .unwrap()
        .unwrap();
    assert!(
        db.insert_sanctions_match(&hit("tx:0", SanctionsMatchStatus::Held))
            .await
            .unwrap()
            .is_none()
    );
    let m = db.get_sanctions_match(id).await.unwrap();
    assert_eq!(m.subject_value.as_str(), "bc1qfixture");
    assert_eq!(m.status, SanctionsMatchStatus::Held);
    let filter = SanctionsMatchFilter {
        subject: Some(SanctionsSubject::Payment),
        open: Some(true),
        payment_ref: Some("tx:0".into()),
        user_id: Some(5),
        ..Default::default()
    };
    let (rows, total) = db.list_sanctions_matches(&filter, 10, 0).await.unwrap();
    assert_eq!((rows.len(), total), (1, 1));
    assert!(
        db.resolve_sanctions_match(id, SanctionsMatchStatus::Cleared, 9, "false positive")
            .await
            .unwrap()
    );
    assert!(
        !db.resolve_sanctions_match(id, SanctionsMatchStatus::Confirmed, 9, "again")
            .await
            .unwrap()
    );
    let m = db.get_sanctions_match(id).await.unwrap();
    assert_eq!(m.status, SanctionsMatchStatus::Cleared);
    assert_eq!(m.resolved_by, Some(9));
    assert_eq!(m.resolution_reason.as_deref(), Some("false positive"));
    let (_, open) = db.list_sanctions_matches(&filter, 10, 0).await.unwrap();
    assert_eq!(open, 0);
}

#[tokio::test]
async fn screenings_hold_and_release_once() {
    let Some(db) = db().await else { return };
    let row = PaymentScreening {
        payment_ref: "tx:1".into(),
        payment_id: Some(vec![3u8; 32]),
        user_id: Some(5),
        payment_method: PaymentMethod::OnChain,
        mode: ScreeningMode::Unscreened,
        provider: "official_lists".into(),
        held: true,
        address: Some("bcrt1qours".into()),
        amount_msat: Some(42_000),
        ..Default::default()
    };
    assert!(db.insert_payment_screening(&row).await.unwrap());
    assert!(!db.insert_payment_screening(&row).await.unwrap());
    let mut stored = db.get_payment_screening("tx:1").await.unwrap().unwrap();
    assert!(stored.is_held());
    assert_eq!(stored.address.as_ref().unwrap().as_str(), "bcrt1qours");
    stored.mode = ScreeningMode::Screened;
    stored.sources = Some("bc1qsrc".into());
    db.update_payment_screening(&stored).await.unwrap();
    let (rows, total) = db
        .list_payment_screenings(
            &PaymentScreeningFilter {
                payment_id: Some(vec![3u8; 32]),
                held: Some(true),
                ..Default::default()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!((rows.len(), total), (1, 1));
    assert_eq!(rows[0].mode, ScreeningMode::Screened);
    assert!(db.release_payment_screening("tx:1").await.unwrap());
    assert!(!db.release_payment_screening("tx:1").await.unwrap());
    assert!(
        !db.get_payment_screening("tx:1")
            .await
            .unwrap()
            .unwrap()
            .is_held()
    );
}
