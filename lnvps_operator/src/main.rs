use anyhow::Result;
use clap::Parser;
use config::{Config as ConfigBuilder, File};
use kube::Client;
use lnvps_api_common::{RedisWorkCommander, WorkCommander, WorkJob, app_cluster_stream};
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::signal;
use tokio::sync::Notify;

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

    let context = Arc::new(Context {
        client: client.clone(),
        db: Arc::new(db) as Arc<dyn LNVpsDb>,
        settings: settings.clone(),
        metrics,
    });

    info!("LNVPS Operator is running and watching for resources...");

    // Initial reconciliation of nostr domains
    info!("Starting initial nostr domain reconciliation...");
    if let Err(e) = nostr_domains::reconcile_nostr_domains(&context).await {
        error!("Failed to reconcile nostr domains: {}", e);
    }
    // Shared with the trigger listener so a payment-triggered sweep that leaves
    // a deployment provisioning also puts the timer on the fast cadence.
    let transitioning = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(Notify::new());
    match app_deployments::reconcile_app_deployments(&context).await {
        Ok(t) => transitioning.store(t, Ordering::Relaxed),
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
        loop {
            let fast = app_transitioning.load(Ordering::Relaxed) && fast_sweeps < max_fast_sweeps;
            tokio::select! {
                _ = tokio::time::sleep(if fast { transition_interval } else { reconcile_interval }) => {}
                // A trigger is a fresh reason to watch closely: start the wait
                // again, and give it a full fast window.
                _ = app_wake.notified() => {
                    fast_sweeps = 0;
                    continue;
                }
            }
            if fast {
                fast_sweeps += 1;
            }
            match app_deployments::reconcile_app_deployments(&app_context).await {
                Ok(t) => {
                    // Only a settled cluster re-arms the fast window, so a
                    // deployment stuck mid-transition cannot hold the cadence.
                    if !t {
                        fast_sweeps = 0;
                    }
                    app_transitioning.store(t, Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed to reconcile app deployments: {}", e);
                    // An unknown outcome is not a reason to poll fast forever.
                    app_transitioning.store(false, Ordering::Relaxed);
                    fast_sweeps = 0;
                }
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
async fn trigger_listener(ctx: Arc<Context>, transitioning: Arc<AtomicBool>, wake: Arc<Notify>) {
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
                    transitioning.store(t, Ordering::Relaxed);
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
            full.encryption.unwrap().key_file,
            PathBuf::from("/etc/lnvps/encryption.key")
        );

        // Minimal config (app-deployment keys commented out) still loads.
        let minimal = load("config.minimal.yaml");
        assert!(minimal.app_cluster_id.is_none());
        assert!(minimal.encryption.is_none());
        // No redis: the periodic reconcile is the only trigger, which is what
        // the operator did before #254.
        assert!(minimal.redis.is_none());
        // No prometheus: no usage is collected and the API reports it unknown.
        assert!(minimal.prometheus.is_none());
    }
}
