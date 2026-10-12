use crate::api::RouterState;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get};
use chrono::{DateTime, Duration, Utc};
use lnvps_api_common::object_store::{ObjectStore, ObjectStoreConfig};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
};
use lnvps_compose::Compose;
use lnvps_db::{
    AppBackupMethod, AppBackupState, AppDeployment, AppDeploymentBackup, AppDeploymentStatus,
    LNVpsDb,
};
use serde::Serialize;

pub const MIN_MANUAL_BACKUP_INTERVAL_MINUTES: i64 = 60;
pub const DOWNLOAD_URL_MINUTES: i64 = 60;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/app-deployments/{id}/backups",
            get(v1_list_backups).post(v1_start_backup),
        )
        .route(
            "/api/v1/app-deployments/{id}/backups/{backup_id}",
            delete(v1_delete_backup),
        )
        .route(
            "/api/v1/app-deployments/{id}/backups/{backup_id}/download",
            get(v1_download_backup),
        )
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ApiAppBackup {
    pub id: u64,
    pub run_id: String,
    pub service: String,
    pub method: String,
    pub artifact: String,
    pub state: String,
    pub size_bytes: Option<u64>,
    pub message: Option<String>,
    pub scheduled: bool,
    pub created: DateTime<Utc>,
    pub started: Option<DateTime<Utc>>,
    pub completed: Option<DateTime<Utc>>,
}

impl From<AppDeploymentBackup> for ApiAppBackup {
    fn from(b: AppDeploymentBackup) -> Self {
        Self {
            id: b.id,
            run_id: b.run_id,
            service: b.service,
            method: b.method.to_string(),
            artifact: b.artifact,
            state: b.state.to_string(),
            size_bytes: b.size_bytes,
            message: b.message,
            scheduled: b.scheduled,
            created: b.created,
            started: b.started,
            completed: b.completed,
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ApiAppBackupDownload {
    pub url: String,
    pub filename: String,
    pub expires: DateTime<Utc>,
}

async fn v1_list_backups(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiAppBackup> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (page, total) = list_backups(this.db.as_ref(), uid, id, limit, offset).await?;
    ApiPaginatedData::ok(page, total, limit, offset)
}

async fn v1_start_backup(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<ApiAppBackup>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let enabled = this.settings.app_backups.is_some();
    ApiData::ok(start_backup(this.db.as_ref(), enabled, uid, id, Utc::now()).await?)
}

async fn v1_download_backup(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path((id, backup_id)): Path<(u64, u64)>,
) -> ApiResult<ApiAppBackupDownload> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let store = backup_store(this.settings.app_backups.as_ref())?;
    ApiData::ok(download_backup(this.db.as_ref(), &store, uid, id, backup_id, Utc::now()).await?)
}

async fn v1_delete_backup(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path((id, backup_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let store = backup_store(this.settings.app_backups.as_ref())?;
    delete_backup(this.db.as_ref(), &store, uid, id, backup_id).await?;
    ApiData::ok(())
}

pub fn backup_store(config: Option<&ObjectStoreConfig>) -> Result<ObjectStore, ApiError> {
    let config = config.ok_or_else(|| ApiError::new("Backups are not available"))?;
    ObjectStore::new(config.clone()).map_err(ApiError::internal)
}

async fn owned_deployment(db: &dyn LNVpsDb, uid: u64, id: u64) -> Result<AppDeployment, ApiError> {
    let d = db
        .get_app_deployment(id)
        .await
        .map_err(|_| ApiError::not_found("Deployment not found"))?;
    if d.user_id != uid || d.deleted {
        return Err(ApiError::not_found("Deployment not found"));
    }
    Ok(d)
}

async fn owned_backup(
    db: &dyn LNVpsDb,
    uid: u64,
    deployment_id: u64,
    backup_id: u64,
) -> Result<AppDeploymentBackup, ApiError> {
    owned_deployment(db, uid, deployment_id).await?;
    let backup = db
        .get_app_deployment_backup(backup_id)
        .await
        .map_err(|_| ApiError::not_found("Backup not found"))?;
    if backup.deployment_id != deployment_id {
        return Err(ApiError::not_found("Backup not found"));
    }
    Ok(backup)
}

pub async fn list_backups(
    db: &dyn LNVpsDb,
    uid: u64,
    deployment_id: u64,
    limit: u64,
    offset: u64,
) -> Result<(Vec<ApiAppBackup>, u64), ApiError> {
    owned_deployment(db, uid, deployment_id).await?;
    let (rows, total) = db
        .list_app_deployment_backups_paginated(deployment_id, limit, offset)
        .await?;
    Ok((rows.into_iter().map(ApiAppBackup::from).collect(), total))
}

pub async fn start_backup(
    db: &dyn LNVpsDb,
    enabled: bool,
    uid: u64,
    deployment_id: u64,
    now: DateTime<Utc>,
) -> Result<Vec<ApiAppBackup>, ApiError> {
    if !enabled {
        return Err(ApiError::new("Backups are not available"));
    }
    let deployment = owned_deployment(db, uid, deployment_id).await?;
    if deployment.status != AppDeploymentStatus::Running {
        return Err(ApiError::new(
            "Only a running deployment can be backed up. Start it, then try again.",
        ));
    }
    let app = db.get_app(deployment.app_id).await?;
    let compose = Compose::parse(&app.compose).map_err(ApiError::internal)?;
    let services = compose.backup_services();
    if services.is_empty() {
        return Err(ApiError::new("This app does not support backups"));
    }

    let existing = db.list_app_deployment_backups(deployment_id).await?;
    if existing
        .iter()
        .any(|b| matches!(b.state, AppBackupState::Pending | AppBackupState::Running))
    {
        return Err(ApiError::conflict("A backup is already in progress"));
    }
    if let Some(last) = existing
        .iter()
        .filter(|b| !b.scheduled)
        .map(|b| b.created)
        .max()
    {
        let next = last + Duration::minutes(MIN_MANUAL_BACKUP_INTERVAL_MINUTES);
        if next > now {
            return Err(ApiError::new(format!(
                "A backup was started less than {MIN_MANUAL_BACKUP_INTERVAL_MINUTES} minutes ago. \
                 Try again after {}.",
                next.format("%H:%M UTC")
            )));
        }
    }

    let run_id = uuid::Uuid::new_v4().to_string();
    let mut out = Vec::with_capacity(services.len());
    for (service, backup) in services {
        let mut row = AppDeploymentBackup {
            id: 0,
            deployment_id,
            run_id: run_id.clone(),
            service: service.to_string(),
            method: if backup.volume.is_some() {
                AppBackupMethod::Volume
            } else {
                AppBackupMethod::Command
            },
            artifact: backup.artifact_name(service),
            object_key: None,
            size_bytes: None,
            state: AppBackupState::Pending,
            message: None,
            scheduled: false,
            created: now,
            started: None,
            completed: None,
            deleted: false,
        };
        row.id = db.insert_app_deployment_backup(&row).await?;
        out.push(ApiAppBackup::from(row));
    }
    Ok(out)
}

pub async fn download_backup(
    db: &dyn LNVpsDb,
    store: &ObjectStore,
    uid: u64,
    deployment_id: u64,
    backup_id: u64,
    now: DateTime<Utc>,
) -> Result<ApiAppBackupDownload, ApiError> {
    let backup = owned_backup(db, uid, deployment_id, backup_id).await?;
    let key = match (&backup.state, &backup.object_key) {
        (AppBackupState::Completed, Some(key)) => key,
        _ => return Err(ApiError::new("This backup has no file to download")),
    };
    let ttl = Duration::minutes(DOWNLOAD_URL_MINUTES);
    let url = store
        .presign_get(
            key,
            ttl.to_std().map_err(ApiError::internal)?,
            Some(&backup.artifact),
        )
        .map_err(ApiError::internal)?;
    Ok(ApiAppBackupDownload {
        url,
        filename: backup.artifact,
        expires: now + ttl,
    })
}

pub async fn delete_backup(
    db: &dyn LNVpsDb,
    store: &ObjectStore,
    uid: u64,
    deployment_id: u64,
    backup_id: u64,
) -> Result<(), ApiError> {
    let backup = owned_backup(db, uid, deployment_id, backup_id).await?;
    if matches!(
        backup.state,
        AppBackupState::Pending | AppBackupState::Running
    ) {
        return Err(ApiError::conflict(
            "This backup is still running. Delete it once it has finished.",
        ));
    }
    if let Some(key) = &backup.object_key {
        store.delete(key).await.map_err(ApiError::internal)?;
    }
    db.delete_app_deployment_backup(backup.id).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{App, AppDeploymentDesiredState, IntervalType, LNVpsDbBase};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BACKED_UP: &str = "services:\n  db:\n    image: x\n    user: root\n    ports:\n      - { name: db, container: 5432, protocol: tcp, expose: none }\n    backup:\n      command: [\"sh\", \"-c\", \"pg_dumpall -h db\"]\n      artifact: app.sql\n  files:\n    image: y\n    user: \"1000\"\n    volumes:\n      - { name: data, path: /data, size: 1Gi }\n    backup:\n      volume: data\n";

    fn unwrap<T>(r: Result<T, ApiError>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{}", e.error),
        }
    }

    fn err<T>(r: Result<T, ApiError>) -> ApiError {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    async fn seed(compose: &str, status: AppDeploymentStatus) -> (MockDb, u64, u64, u64) {
        let db = MockDb::default();
        let owner = db.upsert_user(&[1u8; 32]).await.unwrap();
        let other = db.upsert_user(&[2u8; 32]).await.unwrap();
        db.apps.lock().await.insert(
            1,
            App {
                id: 1,
                name: "relay".to_string(),
                display_name: "Relay".to_string(),
                description: None,
                icon: None,
                repo_url: None,
                category: "Nostr relay".to_string(),
                seo_title: None,
                seo_description: None,
                compose: compose.to_string(),
                amount: 1000,
                currency: "USD".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_amount: 0,
                cpu_milli: 250,
                memory_bytes: 1024,
                storage_bytes: 2048,
                enabled: true,
                created: Utc::now(),
            },
        );
        let deployment = db
            .insert_app_deployment(&AppDeployment {
                id: 0,
                user_id: owner,
                app_id: 1,
                cluster_id: 1,
                resource_multiplier: 1,
                subscription_line_item_id: 0,
                name: "mine".to_string(),
                namespace: "ns".to_string(),
                hostname: None,
                custom_domain: None,
                custom_domain_verified: false,
                config: None,
                desired_state: AppDeploymentDesiredState::Running,
                status,
                status_message: None,
                usage_cpu_milli: None,
                usage_memory_bytes: None,
                usage_storage_bytes: None,
                usage_collected: None,
                created: Utc::now(),
                deleted: false,
            })
            .await
            .unwrap();
        (db, owner, other, deployment)
    }

    fn store(endpoint: &str) -> ObjectStore {
        ObjectStore::new(ObjectStoreConfig {
            endpoint: endpoint.to_string(),
            region: "us-east-1".to_string(),
            bucket: "backups".to_string(),
            access_key: "a".to_string(),
            secret_key: "s".to_string(),
            path_style: true,
        })
        .unwrap()
    }

    async fn complete(db: &MockDb, id: u64, key: &str) {
        let mut b = db.get_app_deployment_backup(id).await.unwrap();
        b.state = AppBackupState::Completed;
        b.object_key = Some(key.to_string());
        b.size_bytes = Some(42);
        db.update_app_deployment_backup(&b).await.unwrap();
    }

    #[tokio::test]
    async fn starting_a_run_records_one_pending_row_per_service() {
        let (db, owner, _, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        let now = Utc::now();
        let run = unwrap(start_backup(&db, true, owner, dep, now).await);
        assert_eq!(run.len(), 2);
        assert!(
            run.iter()
                .all(|b| b.run_id == run[0].run_id && b.state == "pending" && !b.scheduled)
        );
        let mut artifacts: Vec<_> = run
            .iter()
            .map(|b| (b.service.clone(), b.method.clone(), b.artifact.clone()))
            .collect();
        artifacts.sort();
        assert_eq!(
            artifacts,
            vec![
                ("db".into(), "command".into(), "app.sql.gz".into()),
                ("files".into(), "volume".into(), "files-data.tar.gz".into()),
            ]
        );

        let busy = err(start_backup(&db, true, owner, dep, now + Duration::hours(2)).await);
        assert_eq!(busy.code, axum::http::StatusCode::CONFLICT);

        for b in &run {
            complete(&db, b.id, "deployments/1/r/a").await;
        }
        let soon = err(start_backup(&db, true, owner, dep, now + Duration::minutes(10)).await);
        assert!(
            soon.error.contains("less than 60 minutes"),
            "{}",
            soon.error
        );
        assert_eq!(
            unwrap(start_backup(&db, true, owner, dep, now + Duration::minutes(61)).await).len(),
            2
        );
    }

    #[tokio::test]
    async fn a_run_is_refused_when_it_cannot_happen() {
        let (db, owner, other, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        assert!(
            err(start_backup(&db, false, owner, dep, Utc::now()).await)
                .error
                .contains("not available")
        );
        assert_eq!(
            err(start_backup(&db, true, other, dep, Utc::now()).await).code,
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            err(start_backup(&db, true, owner, 999, Utc::now()).await).code,
            axum::http::StatusCode::NOT_FOUND
        );

        let (db, owner, _, dep) = seed(BACKED_UP, AppDeploymentStatus::Stopped).await;
        assert!(
            err(start_backup(&db, true, owner, dep, Utc::now()).await)
                .error
                .contains("running deployment")
        );

        let (db, owner, _, dep) = seed(
            "services:\n  a:\n    image: x\n",
            AppDeploymentStatus::Running,
        )
        .await;
        assert!(
            err(start_backup(&db, true, owner, dep, Utc::now()).await)
                .error
                .contains("does not support")
        );
    }

    #[tokio::test]
    async fn listing_is_scoped_to_the_owner_and_paginated() {
        let (db, owner, other, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        unwrap(start_backup(&db, true, owner, dep, Utc::now()).await);
        let (page, total) = unwrap(list_backups(&db, owner, dep, 1, 0).await);
        assert_eq!((page.len(), total), (1, 2));
        assert!(list_backups(&db, other, dep, 50, 0).await.is_err());
    }

    #[tokio::test]
    async fn download_signs_a_url_only_for_a_finished_backup() {
        let (db, owner, other, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        let run = unwrap(start_backup(&db, true, owner, dep, Utc::now()).await);
        let s = store("https://s3.example.com");
        let now = Utc::now();

        assert!(
            err(download_backup(&db, &s, owner, dep, run[0].id, now).await)
                .error
                .contains("no file")
        );

        complete(&db, run[0].id, "deployments/1/run/app.sql.gz").await;
        let dl = unwrap(download_backup(&db, &s, owner, dep, run[0].id, now).await);
        assert!(
            dl.url
                .starts_with("https://s3.example.com/backups/deployments/1/run/app.sql.gz?")
        );
        assert!(dl.url.contains("response-content-disposition"));
        assert_eq!(dl.filename, run[0].artifact);
        assert_eq!(dl.expires, now + Duration::minutes(DOWNLOAD_URL_MINUTES));

        assert!(
            download_backup(&db, &s, other, dep, run[0].id, now)
                .await
                .is_err()
        );

        let (db2, owner2, _, dep2) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        let theirs = unwrap(start_backup(&db2, true, owner2, dep2, now).await);
        assert_eq!(
            err(download_backup(&db, &s, owner, dep, theirs[0].id + 100, now).await).code,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn a_backup_from_another_deployment_is_not_found() {
        let (db, owner, _, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        let run = unwrap(start_backup(&db, true, owner, dep, Utc::now()).await);
        let mut stray = db.get_app_deployment_backup(run[0].id).await.unwrap();
        stray.id = 0;
        stray.deployment_id = dep + 1;
        let stray = db.insert_app_deployment_backup(&stray).await.unwrap();
        let s = store("https://s3.example.com");
        assert_eq!(
            err(download_backup(&db, &s, owner, dep, stray, Utc::now()).await).code,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn delete_removes_the_object_then_the_row() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let s = store(&server.uri());
        let (db, owner, _, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        let run = unwrap(start_backup(&db, true, owner, dep, Utc::now()).await);

        assert_eq!(
            err(delete_backup(&db, &s, owner, dep, run[0].id).await).code,
            axum::http::StatusCode::CONFLICT
        );

        complete(&db, run[0].id, "deployments/1/run/app.sql.gz").await;
        unwrap(delete_backup(&db, &s, owner, dep, run[0].id).await);
        assert!(db.get_app_deployment_backup(run[0].id).await.is_err());

        let mut failed = db.get_app_deployment_backup(run[1].id).await.unwrap();
        failed.state = AppBackupState::Failed;
        db.update_app_deployment_backup(&failed).await.unwrap();
        unwrap(delete_backup(&db, &s, owner, dep, run[1].id).await);
    }

    #[tokio::test]
    async fn a_failed_object_delete_keeps_the_row() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let s = store(&server.uri());
        let (db, owner, _, dep) = seed(BACKED_UP, AppDeploymentStatus::Running).await;
        let run = unwrap(start_backup(&db, true, owner, dep, Utc::now()).await);
        complete(&db, run[0].id, "deployments/1/run/app.sql.gz").await;
        assert!(delete_backup(&db, &s, owner, dep, run[0].id).await.is_err());
        assert!(db.get_app_deployment_backup(run[0].id).await.is_ok());
    }

    #[test]
    fn the_store_is_only_built_when_configured() {
        assert!(err(backup_store(None)).error.contains("not available"));
        let config = ObjectStoreConfig {
            endpoint: "https://s3.example.com".to_string(),
            region: "us-east-1".to_string(),
            bucket: "b".to_string(),
            access_key: "a".to_string(),
            secret_key: "s".to_string(),
            path_style: true,
        };
        assert!(backup_store(Some(&config)).is_ok());
        let mut broken = config;
        broken.access_key.clear();
        assert_eq!(
            err(backup_store(Some(&broken))).code,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
