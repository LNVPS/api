use anyhow::{Context, Result};
use axum::routing::get;
use axum::Router;
use clap::Parser;
use config::{Config, File};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::interval;

mod checks;
mod metrics;
mod notify;

use checks::dns::{DnsCheck, DnsCheckConfig};
use checks::mss::{MssCheck, MssCheckConfig};
use checks::HealthCheck;
use metrics::{metrics_handler, HealthMetrics};
use notify::{EmailNotifier, NoopNotifier, Notifier, SmtpConfig};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetricsConfig {
    /// Enable Prometheus metrics endpoint
    #[serde(default)]
    pub enabled: bool,
    /// Metrics server bind address (default: 127.0.0.1:9090)
    #[serde(default = "default_metrics_bind")]
    pub bind: String,
}

fn default_metrics_bind() -> String {
    "127.0.0.1:9090".to_string()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_metrics_bind(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// SMTP configuration for email notifications (optional)
    pub smtp: Option<SmtpConfig>,
    /// Prometheus metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Check interval in seconds (default: 600 = 10 minutes)
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Alert cooldown in seconds - don't re-alert for same check within this period
    #[serde(default = "default_alert_cooldown")]
    pub alert_cooldown_secs: u64,
    /// MSS check configurations (also reports PMTU)
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
#[clap(about = "Standalone network health monitoring service", version, author)]
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
        "Health checker starting with {} checks ({} MSS, {} DNS configs), interval {}s",
        health_checks.len(),
        settings.mss_checks.len(),
        settings.dns_checks.len(),
        settings.interval_secs
    );

    if health_checks.is_empty() {
        warn!("No health checks configured - exiting");
        return Ok(());
    }

    // Initialize metrics
    let health_metrics = Arc::new(HealthMetrics::new());

    // Start metrics server if enabled
    if settings.metrics.enabled {
        let metrics_bind: SocketAddr = settings
            .metrics
            .bind
            .parse()
            .context("Invalid metrics bind address")?;

        let metrics_clone = health_metrics.clone();
        tokio::spawn(async move {
            let app = Router::new()
                .route("/metrics", get(metrics_handler))
                .with_state(metrics_clone);

            info!("Starting metrics server on {}", metrics_bind);
            match TcpListener::bind(metrics_bind).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app).await {
                        error!("Metrics server error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to bind metrics server to {}: {}", metrics_bind, e);
                }
            }
        });
    }

    // Initialize notifier
    let notifier: Arc<dyn Notifier> = match &settings.smtp {
        Some(smtp_config) => {
            info!("Email notifications enabled via {}", smtp_config.host);
            Arc::new(EmailNotifier::new(smtp_config.clone())?)
        }
        None => {
            warn!("No SMTP configured - notifications disabled");
            Arc::new(NoopNotifier)
        }
    };

    let alert_state = Arc::new(Mutex::new(AlertState::new()));

    if args.once {
        run_checks(
            &health_checks,
            &settings,
            &notifier,
            &alert_state,
            &health_metrics,
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
                &notifier,
                &alert_state,
                &health_metrics,
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
    notifier: &Arc<dyn Notifier>,
    alert_state: &Arc<Mutex<AlertState>>,
    metrics: &Arc<HealthMetrics>,
) -> Result<()> {
    info!("Running {} health checks", checks.len());
    let cooldown = Duration::from_secs(settings.alert_cooldown_secs);

    for check in checks {
        let check_id = check.id();

        match check.check().await {
            Ok(result) => {
                // Record metrics
                metrics.record_status(&check_id, &result.name, result.passed);
                record_check_metric(metrics, &check_id, &result);

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
                        let title = format!("[Health Alert] {}", result.name);
                        if let Err(e) = notifier.send(&title, &message).await {
                            error!("Failed to send notification: {}", e);
                        }
                    } else {
                        info!(
                            "[FAIL] {}: {} (alert on cooldown)",
                            result.name, result.message
                        );
                    }
                }
            }
            Err(e) => {
                // Record error status
                metrics.record_status(&check_id, &check_id, false);

                let mut state = alert_state.lock().await;
                if state.should_alert(&check_id, cooldown) {
                    let title = format!("[Health Alert] {}", check_id);
                    let message = format!("Health check ERROR: {}\n\nError: {}", check_id, e);
                    error!("[ERROR] {}: {}", check_id, e);
                    if let Err(e) = notifier.send(&title, &message).await {
                        error!("Failed to send notification: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Record type-specific metrics based on check ID pattern
fn record_check_metric(metrics: &HealthMetrics, check_id: &str, result: &checks::CheckResult) {
    let Some(value) = result.metric_value else {
        return;
    };

    let parts: Vec<&str> = check_id.split(':').collect();
    if parts.is_empty() {
        return;
    }

    match parts[0] {
        "mss" if parts.len() >= 4 => {
            // mss:host:port:family
            let host = parts[1];
            let port = parts[2];
            let family = parts[3];
            metrics
                .mss_gauge
                .with_label_values(&[host, port, family])
                .set(value);
        }
        "dns" if parts.len() >= 4 => {
            // dns:server:query:family
            let server = parts[1];
            let query = parts[2];
            let family = parts[3];
            metrics
                .dns_latency_gauge
                .with_label_values(&[server, query, family])
                .set(value);
        }
        _ => {}
    }
}
