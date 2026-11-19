use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, ResourceExt};
use lnvps_api_common::k8s_names::{deployment_id_from_namespace, deployment_namespace};
use lnvps_compose::L4Protocol;
use lnvps_db::{AppDeployment, LNVpsDb};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT_RANGE_START: u16 = 25565;
pub const DEFAULT_PORT_RANGE_END: u16 = 25584;
pub const DEFAULT_INGRESS_NGINX_NAMESPACE: &str = "ingress-nginx";
pub const DEFAULT_TCP_CONFIGMAP: &str = "tcp-services";
pub const DEFAULT_UDP_CONFIGMAP: &str = "udp-services";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForwarderKind {
    #[default]
    IngressNginx,
    Nodeport,
    Loadbalancer,
}

impl fmt::Display for ForwarderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ForwarderKind::IngressNginx => "ingress-nginx",
            ForwarderKind::Nodeport => "nodeport",
            ForwarderKind::Loadbalancer => "loadbalancer",
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            start: DEFAULT_PORT_RANGE_START,
            end: DEFAULT_PORT_RANGE_END,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct IngressNginxConfig {
    #[serde(default = "default_ingress_namespace")]
    pub namespace: String,
    #[serde(default = "default_tcp_configmap")]
    pub tcp_configmap: String,
    #[serde(default = "default_udp_configmap")]
    pub udp_configmap: String,
}

fn default_ingress_namespace() -> String {
    DEFAULT_INGRESS_NGINX_NAMESPACE.to_string()
}

fn default_tcp_configmap() -> String {
    DEFAULT_TCP_CONFIGMAP.to_string()
}

fn default_udp_configmap() -> String {
    DEFAULT_UDP_CONFIGMAP.to_string()
}

impl Default for IngressNginxConfig {
    fn default() -> Self {
        Self {
            namespace: default_ingress_namespace(),
            tcp_configmap: default_tcp_configmap(),
            udp_configmap: default_udp_configmap(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct L4Config {
    #[serde(default)]
    pub forwarder: ForwarderKind,
    #[serde(default)]
    pub port_range: PortRange,
    #[serde(default)]
    pub ingress_nginx: IngressNginxConfig,
}

impl L4Config {
    pub fn validate(&self) -> Result<()> {
        ensure_supported(self.forwarder)?;
        if self.port_range.start == 0 || self.port_range.start > self.port_range.end {
            bail!(
                "l4.port-range {}-{} is not a valid range",
                self.port_range.start,
                self.port_range.end
            );
        }
        Ok(())
    }
}

pub fn ensure_supported(kind: ForwarderKind) -> Result<()> {
    match kind {
        ForwarderKind::IngressNginx => Ok(()),
        other => bail!("l4 forwarder '{other}' is not supported yet; use 'ingress-nginx'"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeExhausted {
    pub start: u16,
    pub end: u16,
}

impl fmt::Display for RangeExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no public port available: all of {}-{} are in use",
            self.start, self.end
        )
    }
}

impl std::error::Error for RangeExhausted {}

pub fn allocate_port(range: &PortRange, used: &BTreeSet<u16>) -> Result<u16, RangeExhausted> {
    (range.start..=range.end)
        .find(|p| !used.contains(p))
        .ok_or(RangeExhausted {
            start: range.start,
            end: range.end,
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Target {
    pub service: String,
    pub container_port: u16,
    pub protocol: L4Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Entry {
    pub public_port: u16,
    pub deployment_id: u64,
    pub target: L4Target,
}

impl L4Entry {
    fn value(&self) -> String {
        format!(
            "{}/{}:{}",
            deployment_namespace(self.deployment_id),
            self.target.service,
            self.target.container_port
        )
    }
}

pub fn is_operator_owned(value: &str) -> bool {
    value
        .split_once('/')
        .and_then(|(ns, _)| deployment_id_from_namespace(ns))
        .is_some()
}

pub fn plan_changes(
    current: &BTreeMap<String, String>,
    wanted: &BTreeMap<u16, String>,
) -> Result<BTreeMap<String, Option<String>>> {
    let mut changes = BTreeMap::new();
    for (port, value) in wanted {
        let key = port.to_string();
        match current.get(&key) {
            Some(existing) if existing == value => {}
            Some(existing) if is_operator_owned(existing) => {
                changes.insert(key, Some(value.clone()));
            }
            Some(existing) => {
                bail!("public port {port} is already forwarded to '{existing}' by something else")
            }
            None => {
                changes.insert(key, Some(value.clone()));
            }
        }
    }
    for (key, value) in current {
        let wanted_here = key.parse::<u16>().is_ok_and(|p| wanted.contains_key(&p));
        if is_operator_owned(value) && !wanted_here {
            changes.insert(key.clone(), None);
        }
    }
    Ok(changes)
}

#[async_trait]
pub trait ConfigMapStore: Send + Sync {
    async fn get(&self, namespace: &str, name: &str) -> Result<Option<BTreeMap<String, String>>>;
    async fn patch(
        &self,
        namespace: &str,
        name: &str,
        changes: &BTreeMap<String, Option<String>>,
    ) -> Result<()>;
}

pub struct KubeConfigMaps(pub Client);

#[async_trait]
impl ConfigMapStore for KubeConfigMaps {
    async fn get(&self, namespace: &str, name: &str) -> Result<Option<BTreeMap<String, String>>> {
        let api: Api<ConfigMap> = Api::namespaced(self.0.clone(), namespace);
        Ok(api
            .get_opt(name)
            .await?
            .map(|cm| cm.data.unwrap_or_default()))
    }

    async fn patch(
        &self,
        namespace: &str,
        name: &str,
        changes: &BTreeMap<String, Option<String>>,
    ) -> Result<()> {
        let api: Api<ConfigMap> = Api::namespaced(self.0.clone(), namespace);
        let body = serde_json::json!({ "data": changes });
        let cm = api
            .patch(name, &PatchParams::default(), &Patch::Merge(&body))
            .await?;
        log::debug!("patched configmap {}/{}", namespace, cm.name_any());
        Ok(())
    }
}

#[async_trait]
pub trait L4Forwarder: Send + Sync {
    fn kind(&self) -> ForwarderKind;
    async fn foreign_ports(&self) -> Result<BTreeSet<u16>>;
    async fn sync(&self, entries: &[L4Entry]) -> Result<()>;
}

pub struct IngressNginxForwarder {
    config: IngressNginxConfig,
    store: Arc<dyn ConfigMapStore>,
}

impl IngressNginxForwarder {
    fn configmap(&self, protocol: L4Protocol) -> &str {
        match protocol {
            L4Protocol::Tcp => &self.config.tcp_configmap,
            L4Protocol::Udp => &self.config.udp_configmap,
        }
    }
}

#[async_trait]
impl L4Forwarder for IngressNginxForwarder {
    fn kind(&self) -> ForwarderKind {
        ForwarderKind::IngressNginx
    }

    async fn foreign_ports(&self) -> Result<BTreeSet<u16>> {
        let mut ports = BTreeSet::new();
        for protocol in [L4Protocol::Tcp, L4Protocol::Udp] {
            let name = self.configmap(protocol);
            if let Some(data) = self.store.get(&self.config.namespace, name).await? {
                ports.extend(
                    data.iter()
                        .filter(|(_, v)| !is_operator_owned(v))
                        .filter_map(|(k, _)| k.parse::<u16>().ok()),
                );
            }
        }
        Ok(ports)
    }

    async fn sync(&self, entries: &[L4Entry]) -> Result<()> {
        for protocol in [L4Protocol::Tcp, L4Protocol::Udp] {
            let wanted: BTreeMap<u16, String> = entries
                .iter()
                .filter(|e| e.target.protocol == protocol)
                .map(|e| (e.public_port, e.value()))
                .collect();
            let name = self.configmap(protocol);
            let namespace = &self.config.namespace;
            let Some(current) = self.store.get(namespace, name).await? else {
                if wanted.is_empty() {
                    continue;
                }
                return Err(anyhow!(
                    "ConfigMap {namespace}/{name} does not exist; create it and pass it to the ingress-nginx controller with --{}-services-configmap",
                    protocol.as_str()
                ));
            };
            let changes = plan_changes(&current, &wanted)?;
            if !changes.is_empty() {
                self.store.patch(namespace, name, &changes).await?;
            }
        }
        Ok(())
    }
}

pub fn build_forwarder(
    config: &L4Config,
    store: Arc<dyn ConfigMapStore>,
) -> Result<Arc<dyn L4Forwarder>> {
    ensure_supported(config.forwarder)?;
    Ok(Arc::new(IngressNginxForwarder {
        config: config.ingress_nginx.clone(),
        store,
    }))
}

pub struct L4Runtime {
    pub forwarder: Arc<dyn L4Forwarder>,
    pub port_range: PortRange,
}

impl L4Runtime {
    pub fn new(config: &L4Config, store: Arc<dyn ConfigMapStore>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            forwarder: build_forwarder(config, store)?,
            port_range: config.port_range.clone(),
        })
    }
}

pub struct L4Want {
    pub deployment: AppDeployment,
    pub target: L4Target,
}

pub struct L4Outcome {
    pub deployment_id: u64,
    pub result: Result<u16, String>,
}

pub async fn sync_l4(
    db: &dyn LNVpsDb,
    runtime: &L4Runtime,
    cluster_deployments: &[AppDeployment],
    wants: Vec<L4Want>,
) -> Result<Vec<L4Outcome>> {
    let mut used = runtime.forwarder.foreign_ports().await?;
    used.extend(cluster_deployments.iter().filter_map(|d| d.public_port));

    let mut outcomes = Vec::new();
    let mut entries = Vec::new();
    for want in wants {
        let id = want.deployment.id;
        let port = match want.deployment.public_port {
            Some(p) => p,
            None => match allocate_port(&runtime.port_range, &used) {
                Ok(p) => {
                    db.set_app_deployment_public_port(id, Some(p)).await?;
                    used.insert(p);
                    p
                }
                Err(e) => {
                    outcomes.push(L4Outcome {
                        deployment_id: id,
                        result: Err(e.to_string()),
                    });
                    continue;
                }
            },
        };
        entries.push(L4Entry {
            public_port: port,
            deployment_id: id,
            target: want.target,
        });
        outcomes.push(L4Outcome {
            deployment_id: id,
            result: Ok(port),
        });
    }
    runtime.forwarder.sync(&entries).await?;
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDbBase;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeStore {
        maps: Mutex<BTreeMap<(String, String), BTreeMap<String, String>>>,
        patches: Mutex<Vec<(String, String)>>,
    }

    impl FakeStore {
        fn with(ns: &str, name: &str, data: &[(&str, &str)]) -> Arc<Self> {
            let s = Arc::new(Self::default());
            s.add(ns, name, data);
            s
        }

        fn add(&self, ns: &str, name: &str, data: &[(&str, &str)]) {
            self.maps.lock().unwrap().insert(
                (ns.to_string(), name.to_string()),
                data.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            );
        }

        fn data(&self, ns: &str, name: &str) -> BTreeMap<String, String> {
            self.maps
                .lock()
                .unwrap()
                .get(&(ns.to_string(), name.to_string()))
                .cloned()
                .unwrap()
        }
    }

    #[async_trait]
    impl ConfigMapStore for FakeStore {
        async fn get(&self, ns: &str, name: &str) -> Result<Option<BTreeMap<String, String>>> {
            Ok(self
                .maps
                .lock()
                .unwrap()
                .get(&(ns.to_string(), name.to_string()))
                .cloned())
        }

        async fn patch(
            &self,
            ns: &str,
            name: &str,
            changes: &BTreeMap<String, Option<String>>,
        ) -> Result<()> {
            self.patches
                .lock()
                .unwrap()
                .push((ns.to_string(), name.to_string()));
            let mut maps = self.maps.lock().unwrap();
            let data = maps.get_mut(&(ns.to_string(), name.to_string())).unwrap();
            for (k, v) in changes {
                match v {
                    Some(v) => data.insert(k.clone(), v.clone()),
                    None => data.remove(k),
                };
            }
            Ok(())
        }
    }

    fn entry(port: u16, id: u64, protocol: L4Protocol) -> L4Entry {
        L4Entry {
            public_port: port,
            deployment_id: id,
            target: L4Target {
                service: "mc".to_string(),
                container_port: 25565,
                protocol,
            },
        }
    }

    fn forwarder(store: Arc<FakeStore>) -> Arc<dyn L4Forwarder> {
        build_forwarder(&L4Config::default(), store).unwrap()
    }

    #[test]
    fn allocation_returns_the_lowest_free_port_and_never_collides() {
        let range = PortRange {
            start: 100,
            end: 102,
        };
        let mut used = BTreeSet::new();
        let mut got = Vec::new();
        for _ in 0..3 {
            let p = allocate_port(&range, &used).unwrap();
            assert!(used.insert(p), "port {p} handed out twice");
            got.push(p);
        }
        assert_eq!(got, vec![100, 101, 102]);
    }

    #[test]
    fn a_freed_port_is_reused() {
        let range = PortRange {
            start: 100,
            end: 102,
        };
        let mut used: BTreeSet<u16> = [100, 101, 102].into();
        used.remove(&101);
        assert_eq!(allocate_port(&range, &used).unwrap(), 101);
    }

    #[test]
    fn an_exhausted_range_gives_a_clear_error() {
        let range = PortRange {
            start: 100,
            end: 101,
        };
        let used: BTreeSet<u16> = [100, 101].into();
        let err = allocate_port(&range, &used).unwrap_err();
        assert_eq!(
            err.to_string(),
            "no public port available: all of 100-101 are in use"
        );
    }

    #[test]
    fn merge_leaves_foreign_entries_alone_and_prunes_only_owned_ones() {
        let current: BTreeMap<String, String> = [
            ("22", "git/gitea-ssh:22"),
            ("25565", "app-4/mc:25565"),
            ("25566", "app-5/mc:25565"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let wanted: BTreeMap<u16, String> = [(25566, "app-5/mc:25565".to_string())].into();
        let changes = plan_changes(&current, &wanted).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes["25565"], None);
        assert!(!changes.contains_key("22"));
    }

    #[test]
    fn merge_refuses_to_overwrite_a_foreign_entry() {
        let current: BTreeMap<String, String> =
            [("22".to_string(), "git/gitea-ssh:22".to_string())].into();
        let wanted: BTreeMap<u16, String> = [(22, "app-1/mc:25565".to_string())].into();
        let err = plan_changes(&current, &wanted).unwrap_err();
        assert!(err.to_string().contains("git/gitea-ssh:22"));
    }

    #[test]
    fn a_namespace_that_only_looks_like_ours_is_not_owned() {
        assert!(is_operator_owned("app-12/mc:25565"));
        assert!(!is_operator_owned("app-012/mc:25565"));
        assert!(!is_operator_owned("app-x/mc:25565"));
        assert!(!is_operator_owned("git/gitea-ssh:22"));
        assert!(!is_operator_owned("noslash"));
    }

    #[tokio::test]
    async fn ingress_nginx_writes_tcp_and_udp_to_their_own_configmaps() {
        let store = FakeStore::with(
            "ingress-nginx",
            "tcp-services",
            &[("22", "git/gitea-ssh:22")],
        );
        store.add("ingress-nginx", "udp-services", &[]);
        let f = forwarder(store.clone());
        assert_eq!(f.kind(), ForwarderKind::IngressNginx);
        f.sync(&[
            entry(25565, 7, L4Protocol::Tcp),
            entry(25566, 8, L4Protocol::Udp),
        ])
        .await
        .unwrap();
        let tcp = store.data("ingress-nginx", "tcp-services");
        assert_eq!(tcp["22"], "git/gitea-ssh:22");
        assert_eq!(tcp["25565"], "app-7/mc:25565");
        assert!(!tcp.contains_key("25566"));
        let udp = store.data("ingress-nginx", "udp-services");
        assert_eq!(udp["25566"], "app-8/mc:25565");
    }

    #[tokio::test]
    async fn configured_names_and_namespace_are_used() {
        let store = FakeStore::with("edge", "my-tcp", &[]);
        let config = L4Config {
            ingress_nginx: IngressNginxConfig {
                namespace: "edge".into(),
                tcp_configmap: "my-tcp".into(),
                udp_configmap: "my-udp".into(),
            },
            ..Default::default()
        };
        let f = build_forwarder(&config, store.clone()).unwrap();
        f.sync(&[entry(25565, 1, L4Protocol::Tcp)]).await.unwrap();
        assert_eq!(store.data("edge", "my-tcp")["25565"], "app-1/mc:25565");
    }

    #[tokio::test]
    async fn sync_removes_a_deleted_deployments_entry_and_keeps_the_static_one() {
        let store = FakeStore::with(
            "ingress-nginx",
            "tcp-services",
            &[("22", "git/gitea-ssh:22"), ("25565", "app-7/mc:25565")],
        );
        let f = forwarder(store.clone());
        f.sync(&[]).await.unwrap();
        let tcp = store.data("ingress-nginx", "tcp-services");
        assert_eq!(tcp.len(), 1);
        assert_eq!(tcp["22"], "git/gitea-ssh:22");
    }

    #[tokio::test]
    async fn an_unchanged_sync_writes_nothing() {
        let store = FakeStore::with(
            "ingress-nginx",
            "tcp-services",
            &[("25565", "app-7/mc:25565")],
        );
        let f = forwarder(store.clone());
        f.sync(&[entry(25565, 7, L4Protocol::Tcp)]).await.unwrap();
        assert!(store.patches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_missing_udp_configmap_only_matters_when_udp_is_wanted() {
        let store = FakeStore::with("ingress-nginx", "tcp-services", &[]);
        let f = forwarder(store.clone());
        f.sync(&[entry(25565, 1, L4Protocol::Tcp)]).await.unwrap();
        let err = f
            .sync(&[entry(25566, 2, L4Protocol::Udp)])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--udp-services-configmap"));
    }

    #[tokio::test]
    async fn foreign_ports_excludes_ours() {
        let store = FakeStore::with(
            "ingress-nginx",
            "tcp-services",
            &[("22", "git/gitea-ssh:22"), ("25565", "app-7/mc:25565")],
        );
        let ports = forwarder(store).foreign_ports().await.unwrap();
        assert_eq!(ports, BTreeSet::from([22]));
    }

    #[test]
    fn unsupported_forwarders_are_refused_with_a_clear_error() {
        for kind in [ForwarderKind::Nodeport, ForwarderKind::Loadbalancer] {
            let config = L4Config {
                forwarder: kind,
                ..Default::default()
            };
            let store = FakeStore::with("ingress-nginx", "tcp-services", &[]);
            let err = build_forwarder(&config, store.clone()).err().unwrap();
            assert_eq!(
                err.to_string(),
                format!("l4 forwarder '{kind}' is not supported yet; use 'ingress-nginx'")
            );
            assert!(config.validate().is_err());
            assert!(store.patches.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn forwarder_kind_parses_from_config() {
        let config: L4Config = serde_json::from_str(r#"{"forwarder":"nodeport"}"#).unwrap();
        assert_eq!(config.forwarder, ForwarderKind::Nodeport);
        let default: L4Config = serde_json::from_str("{}").unwrap();
        assert_eq!(default.forwarder, ForwarderKind::IngressNginx);
        assert_eq!(default.port_range.start, DEFAULT_PORT_RANGE_START);
        assert_eq!(default.ingress_nginx.tcp_configmap, "tcp-services");
    }

    #[test]
    fn invalid_port_ranges_are_rejected() {
        for (start, end) in [(0, 10), (200, 100)] {
            let config = L4Config {
                port_range: PortRange { start, end },
                ..Default::default()
            };
            assert!(config.validate().is_err());
        }
    }

    fn deployment(id: u64, port: Option<u16>) -> AppDeployment {
        use lnvps_db::{AppDeploymentDesiredState, AppDeploymentStatus};
        AppDeployment {
            id,
            user_id: 1,
            app_id: 1,
            cluster_id: 1,
            resource_multiplier: 1,
            subscription_line_item_id: id,
            name: format!("d{id}"),
            namespace: deployment_namespace(id),
            hostname: None,
            public_port: port,
            custom_domain: None,
            custom_domain_verified: false,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Running,
            status_message: None,
            usage_cpu_milli: None,
            usage_memory_bytes: None,
            usage_storage_bytes: None,
            usage_collected: None,
            created: chrono::Utc::now(),
            deleted: false,
        }
    }

    fn want(d: AppDeployment) -> L4Want {
        L4Want {
            deployment: d,
            target: L4Target {
                service: "mc".into(),
                container_port: 25565,
                protocol: L4Protocol::Tcp,
            },
        }
    }

    async fn runtime_with(store: Arc<FakeStore>, range: PortRange) -> L4Runtime {
        let config = L4Config {
            port_range: range,
            ..Default::default()
        };
        L4Runtime::new(&config, store).unwrap()
    }

    #[tokio::test]
    async fn sync_allocates_distinct_ports_stores_them_and_skips_foreign_ones() {
        let store = FakeStore::with("ingress-nginx", "tcp-services", &[("100", "git/ssh:22")]);
        let rt = runtime_with(
            store.clone(),
            PortRange {
                start: 100,
                end: 110,
            },
        )
        .await;
        let db = MockDb::empty();
        let a = deployment(1, None);
        let b = deployment(2, None);
        db.app_deployments.lock().await.insert(1, a.clone());
        db.app_deployments.lock().await.insert(2, b.clone());
        let out = sync_l4(&db, &rt, &[a.clone(), b.clone()], vec![want(a), want(b)])
            .await
            .unwrap();
        let ports: Vec<u16> = out.iter().map(|o| *o.result.as_ref().unwrap()).collect();
        assert_eq!(ports, vec![101, 102]);
        assert_eq!(
            db.get_app_deployment(1).await.unwrap().public_port,
            Some(101)
        );
        let tcp = store.data("ingress-nginx", "tcp-services");
        assert_eq!(tcp["101"], "app-1/mc:25565");
        assert_eq!(tcp["102"], "app-2/mc:25565");
        assert_eq!(tcp["100"], "git/ssh:22");
    }

    #[tokio::test]
    async fn sync_reports_exhaustion_per_deployment_and_keeps_the_others() {
        let store = FakeStore::with("ingress-nginx", "tcp-services", &[]);
        let rt = runtime_with(
            store.clone(),
            PortRange {
                start: 100,
                end: 100,
            },
        )
        .await;
        let db = MockDb::empty();
        let a = deployment(1, None);
        let b = deployment(2, None);
        db.app_deployments.lock().await.insert(1, a.clone());
        db.app_deployments.lock().await.insert(2, b.clone());
        let out = sync_l4(&db, &rt, &[a.clone(), b.clone()], vec![want(a), want(b)])
            .await
            .unwrap();
        assert_eq!(out[0].result, Ok(100));
        assert!(out[1].result.as_ref().unwrap_err().contains("100-100"));
        assert_eq!(db.get_app_deployment(2).await.unwrap().public_port, None);
    }

    #[tokio::test]
    async fn a_deleted_deployments_port_is_freed_and_reused() {
        let store = FakeStore::with("ingress-nginx", "tcp-services", &[]);
        let rt = runtime_with(
            store.clone(),
            PortRange {
                start: 100,
                end: 100,
            },
        )
        .await;
        let db = MockDb::empty();
        let a = deployment(1, None);
        db.app_deployments.lock().await.insert(1, a.clone());
        sync_l4(&db, &rt, &[a.clone()], vec![want(a)])
            .await
            .unwrap();
        assert_eq!(
            db.get_app_deployment(1).await.unwrap().public_port,
            Some(100)
        );

        db.delete_app_deployment(1).await.unwrap();
        let after = db.get_app_deployment(1).await.unwrap();
        assert_eq!(after.public_port, None);
        sync_l4(&db, &rt, &[], vec![]).await.unwrap();
        assert!(store.data("ingress-nginx", "tcp-services").is_empty());

        let b = deployment(2, None);
        db.app_deployments.lock().await.insert(2, b.clone());
        let out = sync_l4(&db, &rt, &[b.clone()], vec![want(b)])
            .await
            .unwrap();
        assert_eq!(out[0].result, Ok(100));
    }

    #[tokio::test]
    async fn an_existing_allocation_is_kept() {
        let store = FakeStore::with("ingress-nginx", "tcp-services", &[]);
        let rt = runtime_with(
            store.clone(),
            PortRange {
                start: 100,
                end: 110,
            },
        )
        .await;
        let db = MockDb::empty();
        let a = deployment(1, Some(105));
        db.app_deployments.lock().await.insert(1, a.clone());
        let out = sync_l4(&db, &rt, &[a.clone()], vec![want(a)])
            .await
            .unwrap();
        assert_eq!(out[0].result, Ok(105));
        assert_eq!(
            store.data("ingress-nginx", "tcp-services")["105"],
            "app-1/mc:25565"
        );
    }
}
