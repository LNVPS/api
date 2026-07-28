//! Read a deployment's resource consumption out of Prometheus (issue #278).
//!
//! Prometheus rather than `metrics.k8s.io`: the kubelet's volume statistics —
//! the only source of PVC used-bytes — are not served by the Kubernetes API at
//! all, so metrics-server can answer CPU and memory but never storage, and a
//! deployment's quota includes storage.
//!
//! One instant query per resource covers the whole cluster, aggregated by
//! namespace, because a query per deployment would multiply request count by
//! the customer count on every reconcile pass.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use serde::Deserialize;

use crate::app_deployments::namespace_name;

/// The namespaces this operator owns, as a PromQL matcher. Anchored so a
/// namespace merely starting with `app-` (or one belonging to something else
/// entirely) cannot contribute another tenant's numbers to a customer's row.
const NAMESPACE_MATCHER: &str = r#"namespace=~"app-[0-9]+""#;

/// Container-level series only. Dropping the empty name excludes cAdvisor's
/// pod-level rollup, and dropping `POD` excludes the pause container, which
/// older cadvisor builds still label that way — either would be counted a
/// second time into every deployment's reading.
const CONTAINER_MATCHER: &str = r#"container!="POD", container!="""#;

/// Range the CPU rate is averaged over. Wide enough that a 60s scrape gives the
/// rate several samples to work from.
const CPU_WINDOW: &str = "5m";

/// One deployment's last observed consumption. Same units as the quota fields
/// on the deployment row, so the two divide directly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeploymentUsage {
    pub cpu_milli: u32,
    pub memory_bytes: u64,
    /// Volume usage summed over the deployment's PVCs. `None` when the cluster
    /// has no `kubelet_volume_stats_used_bytes` series for it — a deployment
    /// with no volumes, or a Prometheus not scraping the kubelets — which is
    /// not the same as an observed zero.
    pub storage_bytes: Option<u64>,
}

/// Prometheus HTTP API client, scoped to the instant queries this needs.
pub struct PrometheusClient {
    url: String,
    client: reqwest::Client,
}

impl PrometheusClient {
    pub fn new(url: &str, timeout: Duration) -> Result<Self> {
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder().timeout(timeout).build()?,
        })
    }

    /// Current usage for every app namespace the cluster reports, keyed by
    /// deployment id.
    ///
    /// CPU and memory are required; a failure of either fails the call, because
    /// writing half a reading would date the untouched half as fresh. Volume
    /// statistics are optional: they come from a different exporter (the
    /// kubelet) than the container metrics, and a Prometheus without them
    /// should still yield CPU and memory rather than nothing.
    pub async fn deployment_usage(&self) -> Result<HashMap<u64, DeploymentUsage>> {
        let cpu = self
            .query(&format!(
                "sum by (namespace) (rate(container_cpu_usage_seconds_total{{{NAMESPACE_MATCHER}, {CONTAINER_MATCHER}}}[{CPU_WINDOW}]))"
            ))
            .await
            .context("cpu query failed")?;
        let memory = self
            .query(&format!(
                "sum by (namespace) (container_memory_working_set_bytes{{{NAMESPACE_MATCHER}, {CONTAINER_MATCHER}}})"
            ))
            .await
            .context("memory query failed")?;
        let storage = match self
            .query(&format!(
                "sum by (namespace) (kubelet_volume_stats_used_bytes{{{NAMESPACE_MATCHER}}})"
            ))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                log::warn!("volume usage unavailable, reporting cpu and memory only: {e}");
                vec![]
            }
        };
        Ok(collect_usage(&cpu, &memory, &storage))
    }

    /// Run one instant query and return its `(namespace, value)` samples.
    async fn query(&self, query: &str) -> Result<Vec<Sample>> {
        let body = self
            .client
            .get(format!("{}/api/v1/query", self.url))
            .query(&[("query", query)])
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        parse_instant_vector(&body)
    }
}

/// One `(namespace, value)` pair from an instant vector.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub namespace: String,
    pub value: f64,
}

#[derive(Deserialize)]
struct PromResponse {
    status: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    data: Option<PromData>,
}

#[derive(Deserialize)]
struct PromData {
    #[serde(default)]
    result: Vec<PromResult>,
}

#[derive(Deserialize)]
struct PromResult {
    #[serde(default)]
    metric: HashMap<String, String>,
    /// `[unix_seconds, "value"]` — the value is a string, and may be `NaN`.
    value: (f64, String),
}

/// Parse an instant-vector query response.
///
/// Samples without a `namespace` label, or whose value is not a finite number,
/// are dropped rather than failing the batch: one unparseable series should not
/// cost every other deployment its reading.
pub fn parse_instant_vector(body: &str) -> Result<Vec<Sample>> {
    let resp: PromResponse = serde_json::from_str(body)?;
    if resp.status != "success" {
        return Err(anyhow!(
            "prometheus returned {}: {}",
            resp.status,
            resp.error.unwrap_or_default()
        ));
    }
    let data = resp
        .data
        .ok_or_else(|| anyhow!("prometheus response had no data"))?;
    Ok(data
        .result
        .into_iter()
        .filter_map(|r| {
            let namespace = r.metric.get("namespace")?.clone();
            let value: f64 = r.value.1.parse().ok()?;
            if !value.is_finite() {
                return None;
            }
            Some(Sample { namespace, value })
        })
        .collect())
}

/// The deployment id a namespace belongs to, if it is one of ours.
pub fn deployment_id_from_namespace(ns: &str) -> Option<u64> {
    let id: u64 = ns.strip_prefix("app-")?.parse().ok()?;
    // Round-trip so only the canonical spelling matches: `app-007` parses as 7
    // but is not a namespace this operator ever created.
    (namespace_name(id) == ns).then_some(id)
}

/// Join the three query results into one reading per deployment.
///
/// CPU and memory are only reported together: a deployment that appears in one
/// vector but not the other is mid-scrape or mid-teardown, and half a reading
/// shown against a quota reads as an idle workload rather than as an unknown
/// one. Storage joins in where present.
pub fn collect_usage(
    cpu: &[Sample],
    memory: &[Sample],
    storage: &[Sample],
) -> HashMap<u64, DeploymentUsage> {
    let by_id = |samples: &[Sample]| -> HashMap<u64, f64> {
        samples
            .iter()
            .filter_map(|s| Some((deployment_id_from_namespace(&s.namespace)?, s.value)))
            .collect()
    };
    let cpu = by_id(cpu);
    let memory = by_id(memory);
    let storage = by_id(storage);

    cpu.iter()
        .filter_map(|(id, cores)| {
            let memory_bytes = *memory.get(id)?;
            Some((
                *id,
                DeploymentUsage {
                    // Cores to millicores, matching the quota's unit. Rounded up
                    // so a workload that is measurably busy never reports 0.
                    cpu_milli: (cores * 1000.0).ceil().max(0.0) as u32,
                    memory_bytes: memory_bytes.max(0.0) as u64,
                    storage_bytes: storage.get(id).map(|b| b.max(0.0) as u64),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ns: &str, value: f64) -> Sample {
        Sample {
            namespace: ns.to_string(),
            value,
        }
    }

    const CPU_BODY: &str = r#"{
        "status":"success",
        "data":{"resultType":"vector","result":[
            {"metric":{"namespace":"app-1"},"value":[1690000000,"0.2503"]},
            {"metric":{"namespace":"app-2"},"value":[1690000000,"0"]}
        ]}
    }"#;

    #[test]
    fn parses_an_instant_vector() {
        let s = parse_instant_vector(CPU_BODY).unwrap();
        assert_eq!(s, vec![sample("app-1", 0.2503), sample("app-2", 0.0)]);
    }

    #[test]
    fn parse_rejects_an_error_response() {
        let body = r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#;
        let e = parse_instant_vector(body).unwrap_err().to_string();
        assert!(e.contains("parse error"), "{e}");
    }

    #[test]
    fn parse_drops_unusable_series_but_keeps_the_rest() {
        let body = r#"{
            "status":"success",
            "data":{"resultType":"vector","result":[
                {"metric":{"pod":"x"},"value":[1690000000,"1"]},
                {"metric":{"namespace":"app-1"},"value":[1690000000,"NaN"]},
                {"metric":{"namespace":"app-2"},"value":[1690000000,"5"]}
            ]}
        }"#;
        assert_eq!(
            parse_instant_vector(body).unwrap(),
            vec![sample("app-2", 5.0)]
        );
    }

    #[test]
    fn only_canonical_app_namespaces_map_to_a_deployment() {
        assert_eq!(deployment_id_from_namespace("app-12"), Some(12));
        assert_eq!(deployment_id_from_namespace("app-007"), None);
        assert_eq!(deployment_id_from_namespace("app-"), None);
        assert_eq!(deployment_id_from_namespace("kube-system"), None);
        assert_eq!(deployment_id_from_namespace("myapp-1"), None);
    }

    #[test]
    fn cpu_converts_to_millicores_and_storage_is_optional() {
        let usage = collect_usage(
            &[sample("app-1", 0.2503), sample("app-2", 1.0)],
            &[sample("app-1", 1048576.0), sample("app-2", 2048.0)],
            &[sample("app-1", 4096.0)],
        );
        assert_eq!(
            usage[&1],
            DeploymentUsage {
                cpu_milli: 251,
                memory_bytes: 1048576,
                storage_bytes: Some(4096),
            }
        );
        assert_eq!(usage[&2].storage_bytes, None);
    }

    #[test]
    fn a_busy_workload_never_rounds_down_to_idle() {
        let usage = collect_usage(&[sample("app-1", 0.0004)], &[sample("app-1", 1.0)], &[]);
        assert_eq!(usage[&1].cpu_milli, 1);
    }

    #[test]
    fn a_deployment_missing_from_either_vector_is_not_reported() {
        let usage = collect_usage(
            &[sample("app-1", 1.0), sample("app-2", 1.0)],
            &[sample("app-1", 1.0)],
            &[sample("app-2", 1.0)],
        );
        assert!(usage.contains_key(&1));
        assert!(!usage.contains_key(&2), "half a reading must not be stored");
    }

    /// Serve `body` for a query matching `needle`, so each assertion pins which
    /// PromQL the client actually sent.
    async fn mock_query(server: &wiremock::MockServer, needle: &str, body: String) {
        use wiremock::matchers::{method, path, query_param_contains};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/api/v1/query"))
            .and(query_param_contains("query", needle))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(server)
            .await;
    }

    fn vector(ns: &str, value: &str) -> String {
        format!(
            r#"{{"status":"success","data":{{"resultType":"vector","result":[{{"metric":{{"namespace":"{ns}"}},"value":[1690000000,"{value}"]}}]}}}}"#
        )
    }

    #[tokio::test]
    async fn queries_prometheus_and_joins_the_three_vectors() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "container_cpu_usage_seconds_total",
            vector("app-3", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "container_memory_working_set_bytes",
            vector("app-3", "2097152"),
        )
        .await;
        mock_query(
            &server,
            "kubelet_volume_stats_used_bytes",
            vector("app-3", "8192"),
        )
        .await;

        let client =
            PrometheusClient::new(&format!("{}/", server.uri()), Duration::from_secs(5)).unwrap();
        let usage = client.deployment_usage().await.unwrap();
        assert_eq!(
            usage[&3],
            DeploymentUsage {
                cpu_milli: 500,
                memory_bytes: 2097152,
                storage_bytes: Some(8192),
            }
        );
    }

    #[tokio::test]
    async fn cpu_and_memory_survive_a_prometheus_without_volume_metrics() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "container_cpu_usage_seconds_total",
            vector("app-3", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "container_memory_working_set_bytes",
            vector("app-3", "2097152"),
        )
        .await;
        // No mock for the volume query: wiremock answers 404, which is what a
        // Prometheus behind a proxy that blocks it looks like.

        let client = PrometheusClient::new(&server.uri(), Duration::from_secs(5)).unwrap();
        let usage = client.deployment_usage().await.unwrap();
        assert_eq!(usage[&3].cpu_milli, 500);
        assert_eq!(usage[&3].storage_bytes, None);
    }

    #[tokio::test]
    async fn a_failed_cpu_query_reports_nothing_rather_than_a_partial_reading() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "container_memory_working_set_bytes",
            vector("app-3", "2097152"),
        )
        .await;

        let client = PrometheusClient::new(&server.uri(), Duration::from_secs(5)).unwrap();
        let e = client.deployment_usage().await.unwrap_err().to_string();
        assert!(e.contains("cpu query failed"), "{e}");
    }

    /// The pause container must not be summed into a deployment's memory: some
    /// cadvisor builds still expose it as `container="POD"`, and it is present
    /// in every pod.
    #[tokio::test]
    async fn the_pause_container_is_excluded_from_both_queries() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "rate(container_cpu_usage_seconds_total{namespace=~\"app-[0-9]+\", container!=\"POD\", container!=\"\"}[5m])",
            vector("app-3", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "container_memory_working_set_bytes{namespace=~\"app-[0-9]+\", container!=\"POD\", container!=\"\"}",
            vector("app-3", "1"),
        )
        .await;

        let client = PrometheusClient::new(&server.uri(), Duration::from_secs(5)).unwrap();
        assert!(client.deployment_usage().await.unwrap().contains_key(&3));
    }

    #[test]
    fn foreign_namespaces_are_ignored() {
        let usage = collect_usage(
            &[sample("kube-system", 4.0)],
            &[sample("kube-system", 4.0)],
            &[],
        );
        assert!(usage.is_empty());
    }
}
