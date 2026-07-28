//! Read a deployment's resource consumption out of Prometheus (issue #278).
//!
//! Prometheus rather than `metrics.k8s.io`: the kubelet's volume statistics —
//! the only source of PVC used-bytes — are not served by the Kubernetes API at
//! all, so metrics-server can answer CPU and memory but never storage, and a
//! deployment's quota includes storage.
//!
//! One instant query per resource covers the whole cluster, because a query per
//! deployment would multiply request count by the customer count on every
//! reconcile pass. Each is aggregated by the key its limit is enforced on —
//! container for CPU and memory, PVC for storage — and the namespace total is
//! summed from those series rather than queried separately: a namespace total
//! cannot say which container is at its limit or which volume is full, and
//! those are the failures that take an app down.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use serde::Deserialize;

pub use lnvps_api_common::k8s_names::deployment_id_from_namespace;

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
#[derive(Debug, Clone, PartialEq)]
pub struct DeploymentUsage {
    pub cpu_milli: u32,
    pub memory_bytes: u64,
    /// Volume usage summed over the deployment's PVCs. `None` when the cluster
    /// has no `kubelet_volume_stats_used_bytes` series for it — a deployment
    /// with no volumes, or a Prometheus not scraping the kubelets — which is
    /// not the same as an observed zero.
    pub storage_bytes: Option<u64>,
    /// The per-container readings the totals were summed from. A container name
    /// is the compose service name.
    pub containers: Vec<ContainerUsage>,
    /// The per-claim readings `storage_bytes` was summed from; empty when it is
    /// `None`.
    pub claims: Vec<ClaimUsage>,
}

/// One container's CPU and memory, the granularity those limits are enforced at.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerUsage {
    pub container: String,
    pub cpu_milli: u32,
    pub memory_bytes: u64,
}

/// One persistent volume claim's used bytes, the granularity the size limit is
/// enforced at.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimUsage {
    pub claim: String,
    pub storage_bytes: u64,
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
                "sum by (namespace, container) (rate(container_cpu_usage_seconds_total{{{NAMESPACE_MATCHER}, {CONTAINER_MATCHER}}}[{CPU_WINDOW}]))"
            ), CONTAINER_LABEL)
            .await
            .context("cpu query failed")?;
        let memory = self
            .query(&format!(
                "sum by (namespace, container) (container_memory_working_set_bytes{{{NAMESPACE_MATCHER}, {CONTAINER_MATCHER}}})"
            ), CONTAINER_LABEL)
            .await
            .context("memory query failed")?;
        let storage = match self
            .query(&format!(
                "sum by (namespace, persistentvolumeclaim) (kubelet_volume_stats_used_bytes{{{NAMESPACE_MATCHER}}})"
            ), CLAIM_LABEL)
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

    /// Run one instant query and return its `(namespace, key, value)` samples.
    async fn query(&self, query: &str, key_label: &str) -> Result<Vec<Sample>> {
        let body = self
            .client
            .get(format!("{}/api/v1/query", self.url))
            .query(&[("query", query)])
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        parse_instant_vector(&body, key_label)
    }
}

/// Label carrying the container name, which is the compose service name.
const CONTAINER_LABEL: &str = "container";

/// Label carrying the PVC name, which is `"{service}-{volume}"`.
const CLAIM_LABEL: &str = "persistentvolumeclaim";

/// One `(namespace, key, value)` triple from an instant vector, where the key is
/// the container or claim the series was grouped by.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub namespace: String,
    pub key: String,
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

/// Parse an instant-vector query response, keyed by `namespace` and `key_label`.
///
/// Samples missing either label, or whose value is not a finite number, are
/// dropped rather than failing the batch: one unparseable series should not cost
/// every other deployment its reading.
pub fn parse_instant_vector(body: &str, key_label: &str) -> Result<Vec<Sample>> {
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
            let key = r.metric.get(key_label)?.clone();
            let value: f64 = r.value.1.parse().ok()?;
            if !value.is_finite() {
                return None;
            }
            Some(Sample {
                namespace,
                key,
                value,
            })
        })
        .collect())
}

/// Cores to millicores, matching the quota's unit. Rounded up so a workload that
/// is measurably busy never reports 0.
fn cores_to_milli(cores: f64) -> u32 {
    (cores.max(0.0) * 1000.0).ceil() as u32
}

/// One container's cores and working-set bytes as they arrive, either half of
/// which may be missing until both vectors have been walked.
type ContainerSample = (Option<f64>, Option<f64>);

/// Join the three query results into one reading per deployment, keeping the
/// per-container and per-claim series the totals were summed from.
///
/// CPU and memory are only reported together: a deployment that appears in one
/// vector but not the other is mid-scrape or mid-teardown, and half a reading
/// shown against a quota reads as an idle workload rather than as an unknown
/// one. That holds per container as well as per deployment — a container with
/// only one of the two is left out of the breakdown, since a service listed at
/// zero memory is a wrong answer where an absent one is an honest gap. Its
/// contribution still lands in the totals, which are summed from the raw
/// vectors. Storage joins in where present.
pub fn collect_usage(
    cpu: &[Sample],
    memory: &[Sample],
    storage: &[Sample],
) -> HashMap<u64, DeploymentUsage> {
    // Rounding is applied to each total after summing, not to the parts, so the
    // breakdown never adds up to more than the total it is shown against.
    let mut totals: HashMap<u64, (f64, f64)> = HashMap::new();
    let mut by_container: HashMap<u64, HashMap<String, ContainerSample>> = HashMap::new();
    for (samples, is_cpu) in [(cpu, true), (memory, false)] {
        for s in samples {
            let Some(id) = deployment_id_from_namespace(&s.namespace) else {
                continue;
            };
            let value = s.value.max(0.0);
            let total = totals.entry(id).or_default();
            let entry = by_container
                .entry(id)
                .or_default()
                .entry(s.key.clone())
                .or_default();
            if is_cpu {
                total.0 += value;
                entry.0 = Some(value);
            } else {
                total.1 += value;
                entry.1 = Some(value);
            }
        }
    }

    let mut claims: HashMap<u64, Vec<ClaimUsage>> = HashMap::new();
    let mut storage_totals: HashMap<u64, f64> = HashMap::new();
    for s in storage {
        let Some(id) = deployment_id_from_namespace(&s.namespace) else {
            continue;
        };
        let bytes = s.value.max(0.0);
        *storage_totals.entry(id).or_default() += bytes;
        claims.entry(id).or_default().push(ClaimUsage {
            claim: s.key.clone(),
            storage_bytes: bytes as u64,
        });
    }

    let cpu_seen: HashSet<u64> = cpu
        .iter()
        .filter_map(|s| deployment_id_from_namespace(&s.namespace))
        .collect();
    let memory_seen: HashSet<u64> = memory
        .iter()
        .filter_map(|s| deployment_id_from_namespace(&s.namespace))
        .collect();

    totals
        .into_iter()
        .filter(|(id, _)| cpu_seen.contains(id) && memory_seen.contains(id))
        .map(|(id, (cores, memory_bytes))| {
            let mut containers: Vec<ContainerUsage> = by_container
                .remove(&id)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(container, (cores, memory_bytes))| {
                    Some(ContainerUsage {
                        container,
                        cpu_milli: cores_to_milli(cores?),
                        memory_bytes: memory_bytes? as u64,
                    })
                })
                .collect();
            containers.sort_by(|a, b| a.container.cmp(&b.container));
            let mut claims = claims.remove(&id).unwrap_or_default();
            claims.sort_by(|a, b| a.claim.cmp(&b.claim));
            (
                id,
                DeploymentUsage {
                    cpu_milli: cores_to_milli(cores),
                    memory_bytes: memory_bytes as u64,
                    storage_bytes: storage_totals.get(&id).map(|b| *b as u64),
                    containers,
                    claims,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ns: &str, key: &str, value: f64) -> Sample {
        Sample {
            namespace: ns.to_string(),
            key: key.to_string(),
            value,
        }
    }

    const CPU_BODY: &str = r#"{
        "status":"success",
        "data":{"resultType":"vector","result":[
            {"metric":{"namespace":"app-1","container":"web"},"value":[1690000000,"0.2503"]},
            {"metric":{"namespace":"app-2","container":"db"},"value":[1690000000,"0"]}
        ]}
    }"#;

    #[test]
    fn parses_an_instant_vector() {
        let s = parse_instant_vector(CPU_BODY, CONTAINER_LABEL).unwrap();
        assert_eq!(
            s,
            vec![sample("app-1", "web", 0.2503), sample("app-2", "db", 0.0)]
        );
    }

    #[test]
    fn parse_rejects_an_error_response() {
        let body = r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#;
        let e = parse_instant_vector(body, CONTAINER_LABEL)
            .unwrap_err()
            .to_string();
        assert!(e.contains("parse error"), "{e}");
    }

    #[test]
    fn parse_drops_unusable_series_but_keeps_the_rest() {
        let body = r#"{
            "status":"success",
            "data":{"resultType":"vector","result":[
                {"metric":{"pod":"x","container":"web"},"value":[1690000000,"1"]},
                {"metric":{"namespace":"app-1","container":"web"},"value":[1690000000,"NaN"]},
                {"metric":{"namespace":"app-1"},"value":[1690000000,"3"]},
                {"metric":{"namespace":"app-2","container":"web"},"value":[1690000000,"5"]}
            ]}
        }"#;
        assert_eq!(
            parse_instant_vector(body, CONTAINER_LABEL).unwrap(),
            vec![sample("app-2", "web", 5.0)]
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
            &[sample("app-1", "web", 0.2503), sample("app-2", "web", 1.0)],
            &[
                sample("app-1", "web", 1048576.0),
                sample("app-2", "web", 2048.0),
            ],
            &[sample("app-1", "web-data", 4096.0)],
        );
        assert_eq!(
            usage[&1],
            DeploymentUsage {
                cpu_milli: 251,
                memory_bytes: 1048576,
                storage_bytes: Some(4096),
                containers: vec![ContainerUsage {
                    container: "web".to_string(),
                    cpu_milli: 251,
                    memory_bytes: 1048576,
                }],
                claims: vec![ClaimUsage {
                    claim: "web-data".to_string(),
                    storage_bytes: 4096,
                }],
            }
        );
        assert_eq!(usage[&2].storage_bytes, None);
        assert!(usage[&2].claims.is_empty());
    }

    /// The totals are the namespace sums the quota is measured against, and the
    /// breakdown is what says which container or volume is responsible.
    #[test]
    fn totals_sum_the_containers_and_claims_they_are_broken_down_into() {
        let usage = collect_usage(
            &[sample("app-1", "web", 0.25), sample("app-1", "db", 0.5)],
            &[
                sample("app-1", "web", 1000.0),
                sample("app-1", "db", 2000.0),
            ],
            &[
                sample("app-1", "db-data", 4096.0),
                sample("app-1", "web-cache", 1024.0),
            ],
        );
        let u = &usage[&1];
        assert_eq!(u.cpu_milli, 750);
        assert_eq!(u.memory_bytes, 3000);
        assert_eq!(u.storage_bytes, Some(5120));
        assert_eq!(
            u.containers
                .iter()
                .map(|c| &c.container)
                .collect::<Vec<_>>(),
            vec!["db", "web"]
        );
        assert_eq!(
            u.claims.iter().map(|c| &c.claim).collect::<Vec<_>>(),
            vec!["db-data", "web-cache"]
        );
    }

    /// Rounding the total after summing, rather than summing rounded parts,
    /// keeps a breakdown from exceeding the figure it is shown beside.
    #[test]
    fn the_breakdown_never_adds_up_to_more_than_the_total() {
        let usage = collect_usage(
            &[
                sample("app-1", "web", 0.0004),
                sample("app-1", "db", 0.0004),
            ],
            &[sample("app-1", "web", 1.0), sample("app-1", "db", 1.0)],
            &[],
        );
        let u = &usage[&1];
        assert_eq!(u.cpu_milli, 1);
        assert_eq!(u.containers.iter().map(|c| c.cpu_milli).sum::<u32>(), 2);
    }

    /// A container present in one vector but not the other is left out of the
    /// breakdown rather than reported at zero, but still counts in the total.
    #[test]
    fn a_container_missing_from_either_vector_is_left_out_of_the_breakdown() {
        let usage = collect_usage(
            &[sample("app-1", "web", 1.0), sample("app-1", "db", 1.0)],
            &[sample("app-1", "web", 1000.0)],
            &[],
        );
        let u = &usage[&1];
        assert_eq!(u.cpu_milli, 2000);
        assert_eq!(
            u.containers,
            vec![ContainerUsage {
                container: "web".to_string(),
                cpu_milli: 1000,
                memory_bytes: 1000,
            }]
        );
    }

    #[test]
    fn a_busy_workload_never_rounds_down_to_idle() {
        let usage = collect_usage(
            &[sample("app-1", "web", 0.0004)],
            &[sample("app-1", "web", 1.0)],
            &[],
        );
        assert_eq!(usage[&1].cpu_milli, 1);
    }

    #[test]
    fn a_deployment_missing_from_either_vector_is_not_reported() {
        let usage = collect_usage(
            &[sample("app-1", "web", 1.0), sample("app-2", "web", 1.0)],
            &[sample("app-1", "web", 1.0)],
            &[sample("app-2", "web-data", 1.0)],
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

    /// An instant vector of one series, labelled with `key_label=key` alongside
    /// the namespace.
    fn vector(ns: &str, key_label: &str, key: &str, value: &str) -> String {
        format!(
            r#"{{"status":"success","data":{{"resultType":"vector","result":[{{"metric":{{"namespace":"{ns}","{key_label}":"{key}"}},"value":[1690000000,"{value}"]}}]}}}}"#
        )
    }

    fn container_vector(ns: &str, container: &str, value: &str) -> String {
        vector(ns, CONTAINER_LABEL, container, value)
    }

    fn claim_vector(ns: &str, claim: &str, value: &str) -> String {
        vector(ns, CLAIM_LABEL, claim, value)
    }

    #[tokio::test]
    async fn queries_prometheus_and_joins_the_three_vectors() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "container_cpu_usage_seconds_total",
            container_vector("app-3", "web", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "container_memory_working_set_bytes",
            container_vector("app-3", "web", "2097152"),
        )
        .await;
        mock_query(
            &server,
            "kubelet_volume_stats_used_bytes",
            claim_vector("app-3", "web-data", "8192"),
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
                containers: vec![ContainerUsage {
                    container: "web".to_string(),
                    cpu_milli: 500,
                    memory_bytes: 2097152,
                }],
                claims: vec![ClaimUsage {
                    claim: "web-data".to_string(),
                    storage_bytes: 8192,
                }],
            }
        );
    }

    #[tokio::test]
    async fn cpu_and_memory_survive_a_prometheus_without_volume_metrics() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "container_cpu_usage_seconds_total",
            container_vector("app-3", "web", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "container_memory_working_set_bytes",
            container_vector("app-3", "web", "2097152"),
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
            container_vector("app-3", "web", "2097152"),
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
            container_vector("app-3", "web", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "container_memory_working_set_bytes{namespace=~\"app-[0-9]+\", container!=\"POD\", container!=\"\"}",
            container_vector("app-3", "web", "1"),
        )
        .await;

        let client = PrometheusClient::new(&server.uri(), Duration::from_secs(5)).unwrap();
        assert!(client.deployment_usage().await.unwrap().contains_key(&3));
    }

    #[test]
    fn foreign_namespaces_are_ignored() {
        let usage = collect_usage(
            &[sample("kube-system", "web", 4.0)],
            &[sample("kube-system", "web", 4.0)],
            &[],
        );
        assert!(usage.is_empty());
    }

    /// The breakdown is grouped per container and per claim, not per namespace:
    /// a namespace sum cannot name what is at its limit.
    #[tokio::test]
    async fn the_queries_group_by_the_key_each_limit_is_enforced_on() {
        let server = wiremock::MockServer::start().await;
        mock_query(
            &server,
            "sum by (namespace, container) (rate(container_cpu_usage_seconds_total",
            container_vector("app-3", "web", "0.5"),
        )
        .await;
        mock_query(
            &server,
            "sum by (namespace, container) (container_memory_working_set_bytes",
            container_vector("app-3", "web", "1"),
        )
        .await;
        mock_query(
            &server,
            "sum by (namespace, persistentvolumeclaim) (kubelet_volume_stats_used_bytes",
            claim_vector("app-3", "web-data", "1"),
        )
        .await;

        let client = PrometheusClient::new(&server.uri(), Duration::from_secs(5)).unwrap();
        let usage = client.deployment_usage().await.unwrap();
        assert_eq!(usage[&3].containers.len(), 1);
        assert_eq!(usage[&3].claims.len(), 1);
    }
}
