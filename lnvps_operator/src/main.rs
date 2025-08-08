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

mod nostr_domains;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// MYSQL connection string
    pub db: String,

    /// Kubernetes namespace to watch (defaults to "default" if not specified)
    pub namespace: Option<String>,

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

    /// Additional ingress annotations (optional)
    pub annotations: Option<HashMap<String, String>>,
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

    // Set up periodic reconciliation
    let context_clone = context.clone();
    let reconcile_interval = Duration::from_secs(context.settings.reconcile_interval.unwrap_or(60));
    let mut interval = tokio::time::interval(reconcile_interval);

    let reconciliation_task = async move {
        loop {
            interval.tick().await;
            info!("Running periodic nostr domain reconciliation...");
            if let Err(e) = nostr_domains::reconcile_nostr_domains(&context_clone).await {
                error!("Failed to reconcile nostr domains: {}", e);
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
