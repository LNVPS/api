use anyhow::Result;
use async_trait::async_trait;

pub mod dns;
pub mod mss;

/// Result of a health check
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Name/identifier for this check
    pub name: String,
    /// Whether the check passed
    pub passed: bool,
    /// Human-readable message describing the result
    pub message: String,
    /// Optional details for debugging
    pub details: Option<String>,
    /// Optional numeric metric value (e.g., MSS bytes, latency ms)
    pub metric_value: Option<f64>,
    /// Optional PMTU value (for MSS checks)
    pub pmtu_value: Option<f64>,
}

impl CheckResult {
    pub fn ok(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            message: message.into(),
            details: None,
            metric_value: None,
            pmtu_value: None,
        }
    }

    pub fn fail(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: false,
            message: message.into(),
            details: None,
            metric_value: None,
            pmtu_value: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn with_metric(mut self, value: f64) -> Self {
        self.metric_value = Some(value);
        self
    }

    pub fn with_pmtu(mut self, value: f64) -> Self {
        self.pmtu_value = Some(value);
        self
    }
}

/// Trait for health checks
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Run the health check and return the result
    async fn check(&self) -> Result<CheckResult>;

    /// Get a unique identifier for this check (used for alert cooldown tracking)
    fn id(&self) -> String;
}
