use anyhow::Result;
use clap::Parser;
use config::{Config as ConfigBuilder, File};
use kube::Client;
use lnvps_api_common::{
    ObjectStore, ObjectStoreConfig, RedisWorkCommander, WorkCommander, WorkJob, app_cluster_stream,
};
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;
use tokio::sync::Notify;

mod app_backups;
mod app_deployments;
mod metrics;
mod nostr_domains;

use crate::metrics::PrometheusClient;

/// Environment variable holding the hex-encoded database encryption key. Must
/// match the API's key (`lnvps_api::settings::ENCRYPTION_KEY_ENV`) so the
/// operator can decrypt columns the API encrypted (e.g. `app_deployment.config`).
const ENCRYPTION_KEY_ENV: &str = "LNVPS_ENCRYPTION_KEY";

/// Overrides `db` from the config file, so a deployment can keep its
/// non-sensitive settings in a ConfigMap and read the DSN from a Secret.
const DATABASE_URL_ENV: &str = "LNVPS_DATABASE_URL";

/// Object storage credentials, for the same reason as [`DATABASE_URL_ENV`]:
/// the config file lives in a ConfigMap, and a bucket key does not belong in
/// one. The environment wins over anything in the file.
const BACKUP_ACCESS_KEY_ENV: &str = "LNVPS_BACKUP_ACCESS_KEY";
const BACKUP_SECRET_KEY_ENV: &str = "LNVPS_BACKUP_SECRET_KEY";

/// Database field-encryption configuration (mirrors the API's `EncryptionConfig`
/// so both sides use the same key).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EncryptionConfig {
    /// Path to the encryption key file.
    pub key_file: PathBuf,
    /// Automatically generate the key if the file doesn't exist.
    #[serde(default)]
    pub auto_generate: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// MYSQL connection string. Optional here because the DSN carries a
    /// password and belongs in a Secret rather than the config file; see
    /// [`DATABASE_URL_ENV`].
    #[serde(default)]
    pub db: String,

    /// Kubernetes namespace to watch (defaults to "default" if not specified)
    pub namespace: Option<String>,

    /// The app cluster this operator serves. When set, the operator reconciles
    /// `app_deployment` rows whose `cluster_id` matches this into Kubernetes.
    /// When unset, app-deployment reconciliation is disabled.
    pub app_cluster_id: Option<u64>,

    /// Reconciliation interval in seconds (defaults to 60)
    pub reconcile_interval: Option<u64>,

    /// How long to wait before the next app-deployment sweep while at least one
    /// deployment is still transitioning (defaults to 5 seconds, and is capped
    /// at `reconcile_interval`). Steady-state deployments stay on
    /// `reconcile_interval`.
    pub transition_reconcile_interval: Option<u64>,

    /// Error retry interval in seconds (defaults to 30)
    pub error_retry_interval: Option<u64>,

    /// Enable verbose logging
    pub verbose: Option<bool>,

    /// Service name for nostr domain ingress
    pub service_name: Option<String>,

    /// Service port name for nostr domain ingress
    pub port_name: Option<String>,

    /// Cert-manager cluster issuer name
    pub cluster_issuer: Option<String>,

    /// Ingress class name (optional, defaults to "nginx")
    pub ingress_class: Option<String>,

    /// Name of a shared TLS secret, mirrored into every deployment namespace,
    /// holding a wildcard certificate for the apps domain (optional).
    ///
    /// When set, a deployment's default host serves that certificate and the
    /// operator does not ask cert-manager to issue one, so onboarding is not
    /// capped by the ACME account's weekly certificate limit for the registered
    /// domain. The cluster is responsible for issuing the wildcard and
    /// mirroring the secret in; the operator only references it. Custom domains
    /// are unaffected and keep their own certificate.
    ///
    /// When unset, each deployment's default host gets its own certificate.
    pub app_tls_secret: Option<String>,

    /// Namespace the ingress controller runs in — the app-deployment isolation
    /// NetworkPolicy allows inbound traffic from it (optional, defaults to
    /// "ingress-nginx"). Must match the `kubernetes.io/metadata.name` label of
    /// that namespace.
    pub ingress_namespace: Option<String>,

    /// Additional ingress annotations (optional)
    pub annotations: Option<HashMap<String, String>>,

    /// Database field-encryption key (optional). Required to read encrypted
    /// columns such as `app_deployment.config`; must match the API's key. The
    /// `LNVPS_ENCRYPTION_KEY` env var (hex) takes precedence over this file.
    pub encryption: Option<EncryptionConfig>,

    /// Prometheus to read deployment resource usage from (optional; issue
    /// #278). When unset, no usage is collected and the API reports usage as
    /// unknown; everything else reconciles as before.
    pub prometheus: Option<PrometheusConfig>,

    /// Object storage for app-deployment backup artifacts (optional). Without
    /// it, backups are disabled: nothing is scheduled and nothing runs, which
    /// is the behaviour of every operator that shipped before backups existed.
    pub backups: Option<BackupConfig>,

    /// Redis URL carrying reconcile triggers for this operator's app cluster
    /// (optional; issue #254).
    ///
    /// When set — and `app_cluster_id` is set — the operator consumes
    /// `app-cluster-{id}` and reconciles a deployment as soon as its payment
    /// settles, instead of at the next poll. When unset the operator behaves
    /// exactly as before: the periodic reconcile is the only trigger, and it
    /// remains the backstop either way.
    pub redis: Option<String>,
}

/// Where backup artifacts go, and how the Jobs that produce them are bounded.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BackupConfig {
    /// S3-compatible bucket the artifacts are uploaded to.
    #[serde(flatten)]
    pub store: ObjectStoreConfig,

    /// Image that tars, compresses and uploads. Defaults to a stock `curl`
    /// image, whose busybox userland already has `tar` and `gzip`. Override to
    /// pin it by digest, or to point at an internal mirror.
    pub uploader_image: Option<String>,

    /// How long a signed upload URL stays valid, in hours (default 6).
    pub upload_url_expiry_hours: Option<u64>,

    /// How long a backup Job may run, in hours (default 5). Kept below the
    /// URL's life so a Job cannot outlive its own upload URL and then fail
    /// with a signature error that reads as a storage fault.
    pub job_deadline_hours: Option<u64>,

    /// How many backup Jobs may run at once on this cluster (default 3).
    /// Every app on the same daily schedule comes due in the same minute, and
    /// each Job reads a whole volume on a node that is also serving customers'
    /// apps.
    pub max_concurrent: Option<usize>,
}

/// Prometheus the operator queries for deployment usage.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrometheusConfig {
    /// Base URL of the Prometheus HTTP API, e.g. `http://prometheus.monitoring:9090`.
    pub url: String,

    /// Per-query timeout in seconds (defaults to 10). Usage collection is
    /// best-effort, so it must not hold up a reconcile pass.
    pub timeout_seconds: Option<u64>,
}

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// Path to the config file
    #[clap(short, long)]
    config: Option<PathBuf>,
}

pub struct Context {
    pub client: Client,
    pub db: Arc<dyn LNVpsDb>,
    pub settings: Settings,
    /// Usage source, built once so its connection pool survives between
    /// reconcile passes. `None` when no Prometheus is configured.
    pub metrics: Option<PrometheusClient>,
    /// Backup artifact storage. `None` when no bucket is configured, which
    /// disables backups entirely.
    pub object_store: Option<ObjectStore>,
}

impl Settings {
    /// Image the backup uploader container runs.
    pub fn backup_uploader_image(&self) -> &str {
        self.backups
            .as_ref()
            .and_then(|b| b.uploader_image.as_deref())
            .unwrap_or(app_backups::DEFAULT_UPLOADER_IMAGE)
    }

    /// How many backup Jobs may be in flight on this cluster.
    pub fn max_concurrent_backups(&self) -> usize {
        self.backups
            .as_ref()
            .and_then(|b| b.max_concurrent)
            .unwrap_or(app_backups::DEFAULT_MAX_CONCURRENT_BACKUPS)
            .max(1)
    }

    /// How long a signed upload URL is good for.
    pub fn backup_url_expiry(&self) -> Duration {
        Duration::from_secs(
            3600 * self
                .backups
                .as_ref()
                .and_then(|b| b.upload_url_expiry_hours)
                .unwrap_or(app_backups::DEFAULT_UPLOAD_URL_HOURS)
                .max(1),
        )
    }

    /// How long a backup Job may run before Kubernetes kills it. Never longer
    /// than the upload URL it was given.
    pub fn backup_job_deadline(&self) -> Duration {
        let configured = Duration::from_secs(
            3600 * self
                .backups
                .as_ref()
                .and_then(|b| b.job_deadline_hours)
                .unwrap_or(app_backups::DEFAULT_JOB_DEADLINE_HOURS)
                .max(1),
        );
        configured.min(self.backup_url_expiry())
    }
}

/// Default gap between app-deployment sweeps while something is transitioning.
const DEFAULT_TRANSITION_RECONCILE_SECS: u64 = 5;

/// How long the fast cadence may last before dropping back to the steady one.
///
/// A workload that is merely not ready reads as transitioning, so an app whose
/// readiness probe never passes would otherwise hold the whole cluster at the
/// fast cadence forever. Provisioning that has not finished within this window
/// is stuck, not slow, and is not worth sweeping for.
const FAST_CADENCE_WINDOW: Duration = Duration::from_secs(300);

/// The DSN to connect with: the environment wins over the config file, so the
/// credential can live in a Secret while the rest of the config stays in a
/// ConfigMap.
fn database_url(configured: &str, from_env: Option<String>) -> Result<String> {
    let env = from_env.unwrap_or_default();
    let url = if env.trim().is_empty() {
        configured.trim()
    } else {
        env.trim()
    };
    if url.is_empty() {
        anyhow::bail!(
            "no database connection string: set {DATABASE_URL_ENV} or `db` in the config"
        );
    }
    Ok(url.to_string())
}

/// Apply environment-supplied bucket credentials over whatever the config file
/// carried, so the keys can live in a Secret while the rest stays in a
/// ConfigMap. An empty or unset variable leaves the file's value alone.
fn backup_credentials(
    mut config: ObjectStoreConfig,
    access_key: Option<String>,
    secret_key: Option<String>,
) -> ObjectStoreConfig {
    if let Some(key) = access_key.filter(|k| !k.trim().is_empty()) {
        config.access_key = key.trim().to_string();
    }
    if let Some(key) = secret_key.filter(|k| !k.trim().is_empty()) {
        config.secret_key = key.trim().to_string();
    }
    config
}

#[tokio::main]
async fn main() -> Result<()> {
    // kube (via hyper-rustls) and sqlx's TLS both use rustls, but the dependency
    // tree exposes a crypto provider without auto-selecting a process default,
    // so rustls panics on first TLS use. Install the ring provider explicitly
    // before any TLS connection (DB or Kubernetes API).
    let _ = rustls::crypto::ring::default_provider().install_default();

    env_logger::init();
    info!("Starting LNVPS Kubernetes Operator");
    let args = Args::parse();

    // Load configuration
    let settings: Settings = ConfigBuilder::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()?
        .try_deserialize()?;

    // Initialize database field encryption before reading any EncryptedString
    // columns (e.g. app_deployment.config). Prefer the env var, else the key
    // file from settings — the key MUST match the API's or decryption fails.
    if let Ok(hex_key) = std::env::var(ENCRYPTION_KEY_ENV) {
        lnvps_db::EncryptionContext::init_from_hex(&hex_key)?;
        info!("Database encryption initialized from environment");
    } else if let Some(ref enc) = settings.encryption {
        lnvps_db::EncryptionContext::init_from_file(&enc.key_file, enc.auto_generate)?;
        info!("Database encryption initialized from key file");
    } else if settings.app_cluster_id.is_some() {
        // App reconciliation needs to decrypt app_deployment.config.
        warn!(
            "app-cluster-id is set but no encryption key is configured (LNVPS_ENCRYPTION_KEY or `encryption.key-file`); app deployment config cannot be decrypted"
        );
    }

    let db_url = database_url(&settings.db, std::env::var(DATABASE_URL_ENV).ok())?;
    let db = LNVpsDbMysql::new(&db_url).await?;
    let client = Client::try_default().await?;

    let metrics = match &settings.prometheus {
        Some(cfg) => Some(PrometheusClient::new(
            &cfg.url,
            Duration::from_secs(cfg.timeout_seconds.unwrap_or(10)),
        )?),
        None => None,
    };

    // Backups are opt-in: without a bucket, nothing is scheduled and nothing
    // runs, which is how every operator behaved before backups existed.
    let object_store = match settings.backups.as_ref() {
        Some(cfg) => Some(ObjectStore::new(backup_credentials(
            cfg.store.clone(),
            std::env::var(BACKUP_ACCESS_KEY_ENV).ok(),
            std::env::var(BACKUP_SECRET_KEY_ENV).ok(),
        ))?),
        None => {
            if settings.app_cluster_id.is_some() {
                info!("No backup storage configured; app deployment backups are disabled");
            }
            None
        }
    };

    let context = Arc::new(Context {
        client: client.clone(),
        db: Arc::new(db) as Arc<dyn LNVpsDb>,
        settings: settings.clone(),
        metrics,
        object_store,
    });

    info!("LNVPS Operator is running and watching for resources...");

    // Initial reconciliation of nostr domains
    info!("Starting initial nostr domain reconciliation...");
    if let Err(e) = nostr_domains::reconcile_nostr_domains(&context).await {
        error!("Failed to reconcile nostr domains: {}", e);
    }
    // Shared with the trigger listener so a payment-triggered sweep that leaves
    // a deployment provisioning also puts the timer on the fast cadence.
    let transitioning: Arc<Mutex<BTreeSet<u64>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let wake = Arc::new(Notify::new());
    match app_deployments::reconcile_app_deployments(&context).await {
        Ok(t) => *transitioning.lock().unwrap() = t,
        Err(e) => error!("Failed to reconcile app deployments: {}", e),
    }

    // Neither interval may be zero: that is a tight sweep loop against the API
    // server, not a fast poll.
    let reconcile_interval = Duration::from_secs(context.settings.reconcile_interval.unwrap_or(60))
        .max(Duration::from_secs(1));
    // Never below a second, and never above the steady interval it exists to
    // beat.
    let transition_interval = Duration::from_secs(
        context
            .settings
            .transition_reconcile_interval
            .unwrap_or(DEFAULT_TRANSITION_RECONCILE_SECS),
    )
    .clamp(Duration::from_secs(1), reconcile_interval);
    let max_fast_sweeps = (FAST_CADENCE_WINDOW.as_secs() / transition_interval.as_secs()).max(1);

    // Nostr domains follow DNS, which nothing here can hurry, so they stay on
    // the steady interval while app deployments run their own cadence.
    let nostr_context = context.clone();
    let nostr_task = async move {
        let mut interval = tokio::time::interval(reconcile_interval);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(e) = nostr_domains::reconcile_nostr_domains(&nostr_context).await {
                error!("Failed to reconcile nostr domains: {}", e);
            }
        }
    };

    let app_context = context.clone();
    let app_transitioning = transitioning.clone();
    let app_wake = wake.clone();
    let reconciliation_task = async move {
        let mut fast_sweeps = 0;
        let mut watched: BTreeSet<u64> = BTreeSet::new();
        loop {
            let current = app_transitioning.lock().unwrap().clone();
            // A deployment we were not already watching is fresh work and gets
            // its own fast window; a deployment wedged mid-transition burns its
            // budget once and cannot spend the next one's.
            if current.iter().any(|id| !watched.contains(id)) {
                fast_sweeps = 0;
            }
            watched = current;
            let fast = !watched.is_empty() && fast_sweeps < max_fast_sweeps;
            tokio::select! {
                _ = tokio::time::sleep(if fast { transition_interval } else { reconcile_interval }) => {}
                // Someone else swept: re-read what is transitioning now rather
                // than waiting out a delay chosen before that was known.
                _ = app_wake.notified() => continue,
            }
            if fast {
                fast_sweeps += 1;
            }
            match app_deployments::reconcile_app_deployments(&app_context).await {
                Ok(t) => *app_transitioning.lock().unwrap() = t,
                Err(e) => {
                    error!("Failed to reconcile app deployments: {}", e);
                    // An unknown outcome is not a reason to poll fast forever.
                    app_transitioning.lock().unwrap().clear();
                }
            }
            // After the deployments, so a backup Job is only ever created for a
            // deployment this pass has already reconciled.
            if let Err(e) = app_backups::reconcile_app_backups(&app_context).await {
                error!("Failed to reconcile app backups: {}", e);
            }
        }
    };

    // Immediate reconcile on payment (#254). Optional: without a Redis URL the
    // periodic loop above is the only trigger, which is the behaviour that
    // shipped before this.
    let trigger_task = trigger_listener(context.clone(), transitioning.clone(), wake.clone());

    // TODO: Add back the controller logic here

    tokio::select! {
        _ = reconciliation_task => {
            warn!("Reconciliation task stopped unexpectedly");
        }
        _ = nostr_task => {
            warn!("Nostr domain reconciliation task stopped unexpectedly");
        }
        _ = trigger_task => {
            warn!("Reconcile-trigger listener stopped unexpectedly");
        }
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("LNVPS Operator shutting down");
    Ok(())
}

/// Consume this cluster's reconcile-trigger stream, reconciling on demand
/// (issue #254).
///
/// Returns immediately (and so parks forever in the `select!`) when the
/// operator has no Redis URL or serves no app cluster — an operator that only
/// handles nostr domains has nothing to listen for.
///
/// A trigger names one deployment, but this runs the same full reconcile the
/// timer does. That keeps one code path: the sweep is already idempotent, it
/// re-reads the deployment's current row rather than trusting the message, and
/// a stale or duplicated trigger therefore costs a sweep rather than producing
/// a different outcome from the periodic one.
async fn trigger_listener(
    ctx: Arc<Context>,
    transitioning: Arc<Mutex<BTreeSet<u64>>>,
    wake: Arc<Notify>,
) {
    let (Some(redis_url), Some(cluster_id)) =
        (ctx.settings.redis.clone(), ctx.settings.app_cluster_id)
    else {
        info!("Reconcile triggers disabled (no redis url or app cluster); polling only");
        std::future::pending::<()>().await;
        return;
    };
    let stream = app_cluster_stream(cluster_id);
    // One consumer group per cluster, and a consumer name that is unique per
    // process: two operators serving the same cluster then share the work
    // rather than each reconciling every trigger.
    let consumer = format!("operator-{}", uuid::Uuid::new_v4());
    let connected =
        RedisWorkCommander::new_for_stream(&redis_url, &stream, "operator", &consumer).await;
    let commander = match connected {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Could not connect to redis at {redis_url} for {stream}: {e} — falling back to \
                 the periodic reconcile only"
            );
            std::future::pending::<()>().await;
            return;
        }
    };
    info!("Listening for reconcile triggers on {stream} as {consumer}");

    loop {
        let jobs = match commander.recv().await {
            Ok(j) => j,
            Err(e) => {
                // A dropped connection must not kill the listener: the periodic
                // reconcile keeps deployments correct meanwhile, and the next
                // read re-establishes the connection.
                warn!("Reconcile-trigger read failed on {stream}: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        // One sweep per batch, not per message: the sweep already covers every
        // deployment on this cluster, so five payments landing together are one
        // reconcile rather than five identical ones.
        let triggers: Vec<u64> = jobs
            .iter()
            .filter_map(|m| match m.job {
                WorkJob::ReconcileAppDeployment { deployment_id } => Some(deployment_id),
                _ => None,
            })
            .collect();
        for m in jobs
            .iter()
            .filter(|m| !matches!(m.job, WorkJob::ReconcileAppDeployment { .. }))
        {
            warn!("Ignoring unexpected job on {stream}: {}", m.job);
        }
        if !triggers.is_empty() {
            info!("Reconcile trigger for app deployment(s) {triggers:?}");
            match app_deployments::reconcile_app_deployments(&ctx).await {
                Ok(t) => {
                    *transitioning.lock().unwrap() = t;
                    wake.notify_one();
                }
                Err(e) => error!("Triggered reconcile failed: {e}"),
            }
        }
        for msg in &jobs {
            // Acked either way: a job this operator cannot act on must not be
            // redelivered forever, and a failed reconcile is retried by the
            // periodic loop rather than by the stream.
            if let Err(e) = commander.ack(&msg.id).await {
                warn!("Could not ack {} on {stream}: {e}", msg.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DSN is a credential, so a deployment can supply it from a Secret
    /// through the environment; the config file stays the fallback.
    #[test]
    fn database_url_prefers_the_environment() {
        assert_eq!(
            database_url("mysql://from-config", Some("mysql://from-env".into())).unwrap(),
            "mysql://from-env"
        );
        assert_eq!(
            database_url("mysql://from-config", None).unwrap(),
            "mysql://from-config"
        );
        // An env var set to nothing is not a connection string.
        assert_eq!(
            database_url("mysql://from-config", Some("  ".into())).unwrap(),
            "mysql://from-config"
        );
        assert!(database_url("", None).is_err());
        assert!(database_url("", Some(String::new())).is_err());
    }

    fn load(name: &str) -> Settings {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), name);
        ConfigBuilder::builder()
            .add_source(File::from(PathBuf::from(path)))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap_or_else(|e| panic!("{name} must deserialize into Settings: {e}"))
    }

    /// The shipped example configs must stay in sync with the `Settings` struct
    /// (kebab-case keys, valid types) so the documented reference never drifts.
    #[test]
    fn example_configs_deserialize() {
        // Full reference exercises every field, including the app-deployment
        // and encryption settings.
        let full = load("config.yaml");
        assert!(full.app_cluster_id.is_some());
        assert!(full.encryption.is_some());
        assert_eq!(full.ingress_namespace.as_deref(), Some("ingress-nginx"));
        assert_eq!(full.redis.as_deref(), Some("redis://localhost:6379"));
        let prom = full.prometheus.clone().expect("prometheus example");
        assert_eq!(prom.url, "http://prometheus.monitoring:9090");
        assert_eq!(prom.timeout_seconds, Some(10));
        assert_eq!(
            full.encryption.clone().unwrap().key_file,
            PathBuf::from("/etc/lnvps/encryption.key")
        );
        let backups = full.backups.clone().expect("backups example");
        assert_eq!(backups.store.bucket, "lnvps-app-backups");
        assert_eq!(backups.store.region, "eu-central-1");
        assert!(backups.store.path_style);
        assert_eq!(full.backup_url_expiry(), Duration::from_secs(6 * 3600));
        assert_eq!(full.backup_job_deadline(), Duration::from_secs(5 * 3600));
        assert_eq!(full.backup_uploader_image(), "curlimages/curl:8.11.1");
        assert_eq!(full.max_concurrent_backups(), 2);

        // Minimal config (app-deployment keys commented out) still loads.
        let minimal = load("config.minimal.yaml");
        assert!(minimal.app_cluster_id.is_none());
        assert!(minimal.encryption.is_none());
        // No redis: the periodic reconcile is the only trigger, which is what
        // the operator did before #254.
        assert!(minimal.redis.is_none());
        // No prometheus: no usage is collected and the API reports it unknown.
        assert!(minimal.prometheus.is_none());
        // No backups: nothing is scheduled and nothing runs.
        assert!(minimal.backups.is_none());
        // The defaults still answer, so the code paths that read them do not
        // have to care whether backups are configured.
        assert_eq!(minimal.backup_url_expiry(), Duration::from_secs(6 * 3600));
        assert_eq!(
            minimal.backup_uploader_image(),
            app_backups::DEFAULT_UPLOADER_IMAGE
        );
    }

    /// A bucket key does not belong in a ConfigMap, so the environment wins --
    /// but an unset or blank variable must not blank a configured credential.
    #[test]
    fn backup_credentials_prefer_the_environment() {
        let base = ObjectStoreConfig {
            endpoint: "https://s3.example.com".to_string(),
            region: "us-east-1".to_string(),
            bucket: "b".to_string(),
            access_key: "from-config".to_string(),
            secret_key: "from-config".to_string(),
            path_style: true,
        };
        let overridden = backup_credentials(
            base.clone(),
            Some("from-env".to_string()),
            Some("  secret  ".to_string()),
        );
        assert_eq!(overridden.access_key, "from-env");
        assert_eq!(overridden.secret_key, "secret");

        let untouched = backup_credentials(base, None, Some("   ".to_string()));
        assert_eq!(untouched.access_key, "from-config");
        assert_eq!(untouched.secret_key, "from-config");
    }

    /// A Job that outlived its upload URL would fail with a signature error
    /// that reads as a storage fault, so the deadline is capped at the URL.
    #[test]
    fn a_job_never_outlives_its_upload_url() {
        let settings = |url_hours: u64, job_hours: u64| Settings {
            db: String::new(),
            namespace: None,
            app_cluster_id: None,
            reconcile_interval: None,
            transition_reconcile_interval: None,
            error_retry_interval: None,
            verbose: None,
            service_name: None,
            port_name: None,
            cluster_issuer: None,
            ingress_class: None,
            app_tls_secret: None,
            ingress_namespace: None,
            annotations: None,
            encryption: None,
            prometheus: None,
            backups: Some(BackupConfig {
                store: ObjectStoreConfig {
                    endpoint: "https://s3.example.com".to_string(),
                    region: "us-east-1".to_string(),
                    bucket: "b".to_string(),
                    access_key: "k".to_string(),
                    secret_key: "s".to_string(),
                    path_style: true,
                },
                uploader_image: None,
                upload_url_expiry_hours: Some(url_hours),
                job_deadline_hours: Some(job_hours),
                max_concurrent: None,
            }),
            redis: None,
        };
        assert_eq!(
            settings(2, 9).backup_job_deadline(),
            Duration::from_secs(2 * 3600),
            "a longer deadline than the URL is capped at the URL"
        );
        assert_eq!(
            settings(9, 2).backup_job_deadline(),
            Duration::from_secs(2 * 3600)
        );
        // Zero is not a duration anything can finish in.
        assert_eq!(
            settings(0, 0).backup_url_expiry(),
            Duration::from_secs(3600)
        );
    }
}
