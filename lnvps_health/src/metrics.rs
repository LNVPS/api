use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use std::sync::Arc;

/// Prometheus metrics for health checks
#[derive(Clone)]
pub struct HealthMetrics {
    registry: Registry,
    /// MSS value by target (host, port, address_family)
    pub mss_gauge: GaugeVec,
    /// DNS check latency (server, query, address_family)
    pub dns_latency_gauge: GaugeVec,
    /// Check status (1 = pass, 0 = fail) by check_id
    pub check_status: GaugeVec,
}

impl HealthMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let mss_gauge = GaugeVec::new(
            Opts::new("health_tcp_mss_bytes", "TCP Maximum Segment Size in bytes"),
            &["host", "port", "family"],
        )
        .expect("Failed to create mss_gauge");

        let dns_latency_gauge = GaugeVec::new(
            Opts::new(
                "health_dns_latency_seconds",
                "DNS query latency in seconds",
            ),
            &["server", "query", "family"],
        )
        .expect("Failed to create dns_latency_gauge");

        let check_status = GaugeVec::new(
            Opts::new(
                "health_check_status",
                "Health check status (1 = pass, 0 = fail)",
            ),
            &["check_id", "name"],
        )
        .expect("Failed to create check_status");

        registry
            .register(Box::new(mss_gauge.clone()))
            .expect("Failed to register mss_gauge");
        registry
            .register(Box::new(dns_latency_gauge.clone()))
            .expect("Failed to register dns_latency_gauge");
        registry
            .register(Box::new(check_status.clone()))
            .expect("Failed to register check_status");

        Self {
            registry,
            mss_gauge,
            dns_latency_gauge,
            check_status,
        }
    }

    /// Record check status (pass/fail)
    pub fn record_status(&self, check_id: &str, name: &str, passed: bool) {
        self.check_status
            .with_label_values(&[check_id, name])
            .set(if passed { 1.0 } else { 0.0 });
    }

    /// Export metrics in Prometheus text format
    pub fn export(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for HealthMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum handler for /metrics endpoint
pub async fn metrics_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<HealthMetrics>>,
) -> String {
    metrics.export()
}
