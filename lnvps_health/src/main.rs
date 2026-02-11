use anyhow::{Context, Result};
use clap::Parser;
use config::{Config, File};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::interval;

use lnvps_api_common::{RedisWorkCommander, WorkCommander, WorkJob};

mod checks;

use checks::dns::{DnsCheck, DnsCheckConfig};
use checks::mss::{MssCheck, MssCheckConfig};
use checks::HealthCheck;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Redis configuration for notifications
    pub redis: RedisConfig,
    /// Check interval in seconds (default: 600 = 10 minutes)
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Alert cooldown in seconds - don't re-alert for same check within this period
    #[serde(default = "default_alert_cooldown")]
    pub alert_cooldown_secs: u64,
    /// MSS check configurations
    #[serde(default)]
    pub mss_checks: Vec<MssCheckConfig>,
    /// DNS check configurations
    #[serde(default)]
    pub dns_checks: Vec<DnsCheckConfig>,
}

fn default_interval() -> u64 {
    600
}

fn default_alert_cooldown() -> u64 {
    3600 // 1 hour
}

#[derive(Parser)]
#[clap(about = "Network health monitoring service for LNVPS", version, author)]
struct Args {
    /// Path to the config file
    #[clap(short, long)]
    config: Option<PathBuf>,

    /// Run once and exit (don't loop)
    #[clap(long)]
    once: bool,
}

struct AlertState {
    /// Last alert time for each check
    last_alert: HashMap<String, std::time::Instant>,
}

impl AlertState {
    fn new() -> Self {
        Self {
            last_alert: HashMap::new(),
        }
    }

    fn should_alert(&mut self, check_id: &str, cooldown: Duration) -> bool {
        let now = std::time::Instant::now();
        if let Some(last) = self.last_alert.get(check_id)
            && now.duration_since(*last) < cooldown
        {
            return false;
        }
        self.last_alert.insert(check_id.to_string(), now);
        true
    }

    fn clear_alert(&mut self, check_id: &str) {
        self.last_alert.remove(check_id);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let settings: Settings = Config::builder()
        .add_source(File::from(
            args.config.unwrap_or(PathBuf::from("config.yaml")),
        ))
        .build()
        .context("Failed to build configuration")?
        .try_deserialize()
        .context("Failed to parse configuration")?;

    // Build all health checks from config
    let mut health_checks: Vec<Box<dyn HealthCheck>> = Vec::new();

    for config in &settings.mss_checks {
        // Creates both IPv4 and IPv6 checks for each MSS config
        health_checks.extend(MssCheck::from_config(config.clone()));
    }

    for config in &settings.dns_checks {
        // Creates checks for both IPv4 and IPv6 DNS servers if configured
        health_checks.extend(DnsCheck::from_config(config.clone()));
    }

    info!(
        "Health checker starting with {} checks ({} MSS configs, {} DNS configs), interval {}s",
        health_checks.len(),
        settings.mss_checks.len(),
        settings.dns_checks.len(),
        settings.interval_secs
    );

    if health_checks.is_empty() {
        warn!("No health checks configured - exiting");
        return Ok(());
    }

    let work_commander: Arc<dyn WorkCommander> =
        Arc::new(RedisWorkCommander::new_publisher(&settings.redis.url).await?);
    let alert_state = Arc::new(Mutex::new(AlertState::new()));

    if args.once {
        run_checks(
            &health_checks,
            &settings,
            &work_commander,
            &alert_state,
        )
        .await?;
        return Ok(());
    }

    let check_interval = Duration::from_secs(settings.interval_secs);
    let mut interval_timer = interval(check_interval);

    // Run initial check immediately
    interval_timer.tick().await;

    let check_loop = async {
        loop {
            if let Err(e) = run_checks(
                &health_checks,
                &settings,
                &work_commander,
                &alert_state,
            )
            .await
            {
                error!("Check cycle failed: {}", e);
            }
            interval_timer.tick().await;
        }
    };

    tokio::select! {
        _ = check_loop => {
            warn!("Check loop exited unexpectedly");
        }
        _ = signal::ctrl_c() => {
            info!("Shutdown signal received");
        }
    }

    Ok(())
}

async fn run_checks(
    checks: &[Box<dyn HealthCheck>],
    settings: &Settings,
    work_commander: &Arc<dyn WorkCommander>,
    alert_state: &Arc<Mutex<AlertState>>,
) -> Result<()> {
    info!("Running {} health checks", checks.len());
    let cooldown = Duration::from_secs(settings.alert_cooldown_secs);

    for check in checks {
        let check_id = check.id();

        match check.check().await {
            Ok(result) => {
                if result.passed {
                    info!("[PASS] {}: {}", result.name, result.message);
                    // Clear alert state if issue resolved
                    let mut state = alert_state.lock().await;
                    state.clear_alert(&check_id);
                } else {
                    let mut state = alert_state.lock().await;
                    if state.should_alert(&check_id, cooldown) {
                        let mut message = format!(
                            "Health check FAILED: {}\n\n{}",
                            result.name, result.message
                        );
                        if let Some(details) = &result.details {
                            message.push_str("\n\nDetails:\n");
                            message.push_str(details);
                        }

                        warn!("[FAIL] {}: {}", result.name, result.message);
                        send_admin_alert(work_commander, &result.name, &message).await;
                    } else {
                        info!(
                            "[FAIL] {}: {} (alert on cooldown)",
                            result.name, result.message
                        );
                    }
                }
            }
            Err(e) => {
                let mut state = alert_state.lock().await;
                if state.should_alert(&check_id, cooldown) {
                    let message = format!("Health check ERROR: {}\n\nError: {}", check_id, e);
                    error!("[ERROR] {}: {}", check_id, e);
                    send_admin_alert(work_commander, &check_id, &message).await;
                }
            }
        }
    }

    Ok(())
}

async fn send_admin_alert(work_commander: &Arc<dyn WorkCommander>, name: &str, message: &str) {
    let job = WorkJob::SendAdminNotification {
        message: message.to_string(),
        title: Some(format!("[Health Alert] {}", name)),
    };

    if let Err(e) = work_commander.send(job).await {
        error!("Failed to send admin notification: {}", e);
    }
}
