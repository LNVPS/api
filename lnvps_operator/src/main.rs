use anyhow::Result;
use clap::Parser;
use config::{Config as ConfigBuilder, File};
use kube::Client;
use lnvps_db::{LNVpsDb, LNVpsDbMysql};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

mod app_deployments;
mod nostr_domains;

/// Environment variable holding the hex-encoded database encryption key. Must
/// match the API's key (`lnvps_api::settings::ENCRYPTION_KEY_ENV`) so the
/// operator can decrypt columns the API encrypted (e.g. `app_deployment.config`).
const ENCRYPTION_KEY_ENV: &str = "LNVPS_ENCRYPTION_KEY";

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
    /// MYSQL connection string
    pub db: String,

    /// Kubernetes namespace to watch (defaults to "default" if not specified)
    pub namespace: Option<String>,

    /// The app cluster this operator serves. When set, the operator reconciles
    /// `app_deployment` rows whose `cluster_id` matches this into Kubernetes.
    /// When unset, app-deployment reconciliation is disabled.
    pub app_cluster_id: Option<u64>,

    /// Reconciliation interval in seconds (defaults to 60)
    pub reconcile_interval: Option<u64>,

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

    let db = LNVpsDbMysql::new(&settings.db).await?;
    let client = Client::try_default().await?;

    let context = Arc::new(Context {
        client: client.clone(),
        db: Arc::new(db) as Arc<dyn LNVpsDb>,
        settings: settings.clone(),
    });

    info!("LNVPS Operator is running and watching for resources...");

    // Initial reconciliation of nostr domains
    info!("Starting initial nostr domain reconciliation...");
    if let Err(e) = nostr_domains::reconcile_nostr_domains(&context).await {
        error!("Failed to reconcile nostr domains: {}", e);
    }
    if let Err(e) = app_deployments::reconcile_app_deployments(&context).await {
        error!("Failed to reconcile app deployments: {}", e);
    }

    // Set up periodic reconciliation
    let context_clone = context.clone();
    let reconcile_interval = Duration::from_secs(context.settings.reconcile_interval.unwrap_or(60));
    let mut interval = tokio::time::interval(reconcile_interval);

    let reconciliation_task = async move {
        loop {
            interval.tick().await;
            info!("Running periodic reconciliation...");
            if let Err(e) = nostr_domains::reconcile_nostr_domains(&context_clone).await {
                error!("Failed to reconcile nostr domains: {}", e);
            }
            if let Err(e) = app_deployments::reconcile_app_deployments(&context_clone).await {
                error!("Failed to reconcile app deployments: {}", e);
            }
        }
    };

    // TODO: Add back the controller logic here

    tokio::select! {
        _ = reconciliation_task => {
            warn!("Reconciliation task stopped unexpectedly");
        }
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("LNVPS Operator shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            full.encryption.unwrap().key_file,
            PathBuf::from("/etc/lnvps/encryption.key")
        );

        // Minimal config (app-deployment keys commented out) still loads.
        let minimal = load("config.minimal.yaml");
        assert!(minimal.app_cluster_id.is_none());
        assert!(minimal.encryption.is_none());
    }
}
