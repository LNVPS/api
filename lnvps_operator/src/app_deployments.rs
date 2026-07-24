//! Reconcile managed **app deployments** into Kubernetes.
//!
//! Each `app_deployment` row (for this operator's cluster) is rendered from its
//! app's `lnvps_compose` document into a set of namespaced Kubernetes objects:
//! a locked-down Namespace (one per deployment) with a default-deny
//! NetworkPolicy and a ResourceQuota, a Deployment + Service per compose
//! service, an Ingress for each `expose: ingress` port, PVCs for `volumes:`, and
//! ConfigMap/Secret-backed `files:` mounted read-only via `subPath`.
//!
//! The object **builders** are pure functions (unit-tested without a cluster);
//! [`reconcile_app_deployments`] resolves config/secrets and applies them.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;

use anyhow::{Result, anyhow};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::{Client, Resource, ResourceExt};
use log::{error, info, warn};
use serde::Serialize;
use serde::de::DeserializeOwned;

use k8s_openapi::NamespaceResourceScope;
use lnvps_db::{AppDeployment, AppDeploymentStatus, EncryptedString};

use crate::Context;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, Namespace, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, PodSecurityContext, PodSpec, PodTemplateSpec, ResourceQuota,
    ResourceQuotaSpec, ResourceRequirements, SeccompProfile, SecurityContext, Service, ServicePort,
    ServiceSpec, Volume as K8sVolume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, IngressTLS, NetworkPolicy, NetworkPolicySpec,
    ServiceBackendPort,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use lnvps_compose::{Compose, Expose, ResolvedFile, Service as ComposeService};

/// Label value marking objects this operator owns.
pub const MANAGED_BY: &str = "lnvps-operator";

/// The Kubernetes namespace for a deployment.
pub fn namespace_name(deployment_id: u64) -> String {
    format!("app-{deployment_id}")
}

/// Common labels applied to every object of a deployment.
fn labels(deployment_id: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("managed-by".to_string(), MANAGED_BY.to_string()),
        (
            "app.kubernetes.io/instance".to_string(),
            format!("app-{deployment_id}"),
        ),
    ])
}

/// Per-service selector/labels (adds the compose service name).
fn service_labels(deployment_id: u64, service: &str) -> BTreeMap<String, String> {
    let mut l = labels(deployment_id);
    l.insert(
        "app.kubernetes.io/component".to_string(),
        service.to_string(),
    );
    l
}

/// A namespace for a deployment, labelled for the **restricted** Pod Security
/// Standard so the admission controller rejects privileged pods.
pub fn build_namespace(deployment_id: u64) -> Namespace {
    let mut l = labels(deployment_id);
    l.insert(
        "pod-security.kubernetes.io/enforce".to_string(),
        "restricted".to_string(),
    );
    l.insert(
        "pod-security.kubernetes.io/enforce-version".to_string(),
        "latest".to_string(),
    );
    Namespace {
        metadata: ObjectMeta {
            name: Some(namespace_name(deployment_id)),
            labels: Some(l),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A default-deny NetworkPolicy (blocks all ingress/egress) leaving only DNS —
/// so services can resolve each other but the deployment can't reach the rest of
/// the cluster. Egress to the internet is added by the ingress/service path.
pub fn build_network_policy(deployment_id: u64) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some("default-deny".to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            // Empty selector = all pods; no ingress/egress rules = deny all
            // (except intra-namespace is still governed by CNI defaults).
            pod_selector: LabelSelector::default(),
            policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
            ..Default::default()
        }),
    }
}

/// A ResourceQuota capping what the whole deployment namespace may consume.
///
/// Not applied yet: a `limits.*` quota requires every container to declare
/// resource limits, which only lands with the capacity increment (per-service
/// `resources:` → container requests/limits). Wired there.
#[allow(dead_code)]
pub fn build_resource_quota(
    deployment_id: u64,
    cpu: &str,
    memory: &str,
    pvc: &str,
) -> ResourceQuota {
    let hard = BTreeMap::from([
        ("limits.cpu".to_string(), Quantity(cpu.to_string())),
        ("limits.memory".to_string(), Quantity(memory.to_string())),
        ("requests.storage".to_string(), Quantity(pvc.to_string())),
    ]);
    ResourceQuota {
        metadata: ObjectMeta {
            name: Some("quota".to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            ..Default::default()
        },
        spec: Some(ResourceQuotaSpec {
            hard: Some(hard),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A locked-down pod security context (non-root, seccomp RuntimeDefault).
fn pod_security_context() -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: Some(true),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A locked-down container security context: no privilege escalation, all
/// capabilities dropped, read-only root filesystem.
fn container_security_context() -> SecurityContext {
    use k8s_openapi::api::core::v1::Capabilities;
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A PVC for a compose `volume`.
pub fn build_pvc(
    deployment_id: u64,
    service: &str,
    name: &str,
    size: &str,
) -> PersistentVolumeClaim {
    let requests = BTreeMap::from([("storage".to_string(), Quantity(size.to_string()))]);
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(format!("{service}-{name}")),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(service_labels(deployment_id, service)),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Sanitize a file path into a config-map/secret data key (`/etc/x.conf` →
/// `etc-x.conf`).
fn file_key(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "-")
}

/// ConfigMap holding a service's non-sensitive files (keyed by [`file_key`]).
pub fn build_files_configmap(
    deployment_id: u64,
    service: &str,
    files: &[ResolvedFile],
) -> Option<ConfigMap> {
    let data: BTreeMap<String, String> = files
        .iter()
        .filter(|f| !f.sensitive)
        .map(|f| (file_key(&f.path), f.content.clone()))
        .collect();
    if data.is_empty() {
        return None;
    }
    Some(ConfigMap {
        metadata: ObjectMeta {
            name: Some(format!("{service}-files")),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(service_labels(deployment_id, service)),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

/// Secret holding a service's generated secret values and any `sensitive` files.
pub fn build_secret(
    deployment_id: u64,
    service: &str,
    generated: &BTreeMap<String, String>,
    files: &[ResolvedFile],
) -> Option<k8s_openapi::api::core::v1::Secret> {
    use k8s_openapi::ByteString;
    let mut data: BTreeMap<String, ByteString> = generated
        .iter()
        .map(|(k, v)| (k.clone(), ByteString(v.clone().into_bytes())))
        .collect();
    for f in files.iter().filter(|f| f.sensitive) {
        data.insert(
            file_key(&f.path),
            ByteString(f.content.clone().into_bytes()),
        );
    }
    if data.is_empty() {
        return None;
    }
    Some(k8s_openapi::api::core::v1::Secret {
        metadata: ObjectMeta {
            name: Some(format!("{service}-secret")),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(service_labels(deployment_id, service)),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

/// A ClusterIP Service exposing a compose service's declared ports. `None` when
/// the service declares no ports (purely internal, no addressable endpoint).
pub fn build_service(
    deployment_id: u64,
    service_name: &str,
    svc: &ComposeService,
) -> Option<Service> {
    if svc.ports.is_empty() {
        return None;
    }
    let ports = svc
        .ports
        .iter()
        .map(|p| ServicePort {
            name: Some(p.name.clone()),
            port: p.container as i32,
            target_port: Some(
                k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(p.container as i32),
            ),
            ..Default::default()
        })
        .collect();
    Some(Service {
        metadata: ObjectMeta {
            // Service name == compose service name so intra-namespace DNS
            // matches the compose reference (e.g. `mariadb:3306`).
            name: Some(service_name.to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(service_labels(deployment_id, service_name)),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(service_labels(deployment_id, service_name)),
            ports: Some(ports),
            cluster_ip: None,
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// A Deployment for a compose service. `replicas` is 0 when the deployment is
/// stopped. Mounts PVCs (read-write) and file ConfigMap/Secret (read-only via
/// `subPath`). Uses the `Recreate` strategy so a single RWO PVC is released
/// before a new pod starts.
pub fn build_deployment(
    deployment_id: u64,
    service_name: &str,
    svc: &ComposeService,
    env: &BTreeMap<String, String>,
    files: &[ResolvedFile],
    replicas: i32,
) -> Deployment {
    let sel = service_labels(deployment_id, service_name);

    let mut volumes: Vec<K8sVolume> = Vec::new();
    let mut mounts: Vec<VolumeMount> = Vec::new();

    // Data volumes (PVC).
    for v in &svc.volumes {
        let vol_name = format!("{service_name}-{}", v.name);
        volumes.push(K8sVolume {
            name: vol_name.clone(),
            persistent_volume_claim: Some(
                k8s_openapi::api::core::v1::PersistentVolumeClaimVolumeSource {
                    claim_name: vol_name.clone(),
                    ..Default::default()
                },
            ),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: vol_name,
            mount_path: v.path.clone(),
            ..Default::default()
        });
    }

    // Config files: non-sensitive via ConfigMap, sensitive via Secret, each
    // mounted read-only at its path with subPath so it doesn't shadow the dir.
    let has_cm = files.iter().any(|f| !f.sensitive);
    let has_secret_files = files.iter().any(|f| f.sensitive);
    if has_cm {
        volumes.push(K8sVolume {
            name: "files-cm".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{service_name}-files"),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    if has_secret_files {
        volumes.push(K8sVolume {
            name: "files-secret".to_string(),
            secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                secret_name: Some(format!("{service_name}-secret")),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    for f in files {
        mounts.push(VolumeMount {
            name: if f.sensitive {
                "files-secret".to_string()
            } else {
                "files-cm".to_string()
            },
            mount_path: f.path.clone(),
            sub_path: Some(file_key(&f.path)),
            read_only: Some(true),
            ..Default::default()
        });
    }

    let container = Container {
        name: service_name.to_string(),
        image: Some(svc.image.clone()),
        env: Some(
            env.iter()
                .map(|(k, v)| EnvVar {
                    name: k.clone(),
                    value: Some(v.clone()),
                    ..Default::default()
                })
                .collect(),
        ),
        ports: Some(
            svc.ports
                .iter()
                .map(|p| ContainerPort {
                    name: Some(p.name.clone()),
                    container_port: p.container as i32,
                    ..Default::default()
                })
                .collect(),
        ),
        volume_mounts: if mounts.is_empty() {
            None
        } else {
            Some(mounts)
        },
        security_context: Some(container_security_context()),
        resources: Some(ResourceRequirements::default()),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta {
            name: Some(service_name.to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(sel.clone()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(replicas),
            selector: LabelSelector {
                match_labels: Some(sel.clone()),
                ..Default::default()
            },
            strategy: Some(DeploymentStrategy {
                type_: Some("Recreate".to_string()),
                ..Default::default()
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(sel),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: if volumes.is_empty() {
                        None
                    } else {
                        Some(volumes)
                    },
                    security_context: Some(pod_security_context()),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// An Ingress routing `hostname` to the first `expose: ingress` port found
/// across the app's services, with cert-manager TLS. Returns `None` when no
/// service exposes an ingress port. `issuer`/`class` come from operator config.
pub fn build_ingress(
    deployment_id: u64,
    compose: &Compose,
    hostname: &str,
    issuer: &str,
    class: &str,
) -> Option<Ingress> {
    // Find the service + port marked expose: ingress.
    let (service_name, port) = compose.services.iter().find_map(|(name, svc)| {
        svc.ports
            .iter()
            .find(|p| p.expose == Expose::Ingress)
            .map(|p| (name.clone(), p.clone()))
    })?;

    let annotations = BTreeMap::from([
        (
            "cert-manager.io/cluster-issuer".to_string(),
            issuer.to_string(),
        ),
        ("kubernetes.io/ingress.class".to_string(), class.to_string()),
    ]);

    let rule = IngressRule {
        host: Some(hostname.to_string()),
        http: Some(HTTPIngressRuleValue {
            paths: vec![HTTPIngressPath {
                path: Some(port.path.clone().unwrap_or_else(|| "/".to_string())),
                path_type: "Prefix".to_string(),
                backend: IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: service_name,
                        port: Some(ServiceBackendPort {
                            number: Some(port.container as i32),
                            ..Default::default()
                        }),
                    }),
                    ..Default::default()
                },
            }],
        }),
    };

    Some(Ingress {
        metadata: ObjectMeta {
            name: Some("app".to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            tls: Some(vec![IngressTLS {
                hosts: Some(vec![hostname.to_string()]),
                secret_name: Some("app-tls".to_string()),
            }]),
            rules: Some(vec![rule]),
            ..Default::default()
        }),
        status: None,
    })
}

/// Generate a random URL-safe secret value of `len` bytes (hex-encoded).
pub fn generate_secret_value(len: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Compute the effective hostname for a deployment on a cluster.
pub fn deployment_hostname(name: &str, ingress_domain: &str) -> String {
    format!("{name}.{ingress_domain}")
}

/// Build the merged `${…}` substitution map from generated secrets + config
/// values + operator context (currently `HOSTNAME`).
pub fn build_vars(
    generated: &BTreeMap<String, String>,
    config: &BTreeMap<String, String>,
    hostname: &str,
) -> std::collections::HashMap<String, String> {
    let mut vars = std::collections::HashMap::new();
    for (k, v) in generated {
        vars.insert(k.clone(), v.clone());
    }
    for (k, v) in config {
        vars.insert(k.clone(), v.clone());
    }
    vars.insert("HOSTNAME".to_string(), hostname.to_string());
    vars
}

/// Ensure every declared secret has a value, generating any that are missing
/// (preserving existing ones so values are stable across reconciles).
pub fn ensure_secrets(
    compose: &Compose,
    existing: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut out = existing.clone();
    for s in &compose.secrets {
        out.entry(s.name.clone())
            .or_insert_with(|| generate_secret_value(24));
    }
    // Sanity: every declared secret is now present.
    for s in &compose.secrets {
        if !out.contains_key(&s.name) {
            return Err(anyhow!("secret '{}' missing after generation", s.name));
        }
    }
    Ok(out)
}

/// Server-side apply a namespaced Kubernetes object, creating or updating it
/// idempotently.
async fn apply<K>(client: &Client, obj: &K) -> Result<()>
where
    K: Resource<Scope = NamespaceResourceScope> + Serialize + DeserializeOwned + Clone + Debug,
    K::DynamicType: Default,
{
    let ns = obj.namespace().unwrap_or_default();
    let api: Api<K> = Api::namespaced(client.clone(), &ns);
    api.patch(
        &obj.name_any(),
        &PatchParams::apply(MANAGED_BY).force(),
        &Patch::Apply(obj),
    )
    .await?;
    Ok(())
}

/// Server-side apply the (cluster-scoped) Namespace.
async fn apply_namespace(client: &Client, obj: &Namespace) -> Result<()> {
    let api: Api<Namespace> = Api::all(client.clone());
    api.patch(
        &obj.name_any(),
        &PatchParams::apply(MANAGED_BY).force(),
        &Patch::Apply(obj),
    )
    .await?;
    Ok(())
}

/// The namespace-level Secret storing a deployment's generated secret values so
/// they stay stable across reconciles.
fn build_generated_secret(
    deployment_id: u64,
    generated: &BTreeMap<String, String>,
) -> k8s_openapi::api::core::v1::Secret {
    use k8s_openapi::ByteString;
    let data = generated
        .iter()
        .map(|(k, v)| (k.clone(), ByteString(v.clone().into_bytes())))
        .collect();
    k8s_openapi::api::core::v1::Secret {
        metadata: ObjectMeta {
            name: Some("generated".to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Read a deployment's existing generated secret values (empty on first run).
async fn read_generated(client: &Client, deployment_id: u64) -> BTreeMap<String, String> {
    let api: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), &namespace_name(deployment_id));
    match api.get("generated").await {
        Ok(s) => s
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8_lossy(&v.0).to_string()))
            .collect(),
        Err(_) => BTreeMap::new(),
    }
}

/// Decode a deployment's stored (decrypted) config JSON into a flat map.
fn parse_config(cfg: &Option<EncryptedString>) -> BTreeMap<String, String> {
    let Some(c) = cfg else {
        return BTreeMap::new();
    };
    let s = c.as_str();
    if s.trim().is_empty() {
        return BTreeMap::new();
    }
    match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s) {
        Ok(m) => m
            .into_iter()
            .map(|(k, v)| {
                let val = match v {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                (k, val)
            })
            .collect(),
        Err(_) => BTreeMap::new(),
    }
}

/// Reconcile every app deployment assigned to this operator's cluster into
/// Kubernetes. No-op when the operator isn't configured with an `app_cluster_id`.
pub async fn reconcile_app_deployments(ctx: &Context) -> Result<()> {
    let Some(cluster_id) = ctx.settings.app_cluster_id else {
        return Ok(());
    };
    let cluster = ctx.db.get_app_cluster(cluster_id).await?;
    let deployments: Vec<AppDeployment> = ctx
        .db
        .list_all_app_deployments()
        .await?
        .into_iter()
        .filter(|d| d.cluster_id == cluster_id)
        .collect();

    let mut active: HashSet<u64> = HashSet::new();
    for d in &deployments {
        active.insert(d.id);
        if let Err(e) = reconcile_one(ctx, d, &cluster.ingress_domain).await {
            error!("app deployment {} reconcile failed: {}", d.id, e);
            let mut errd = d.clone();
            errd.status = AppDeploymentStatus::Error;
            errd.status_message = Some(e.to_string());
            let _ = ctx.db.update_app_deployment(&errd).await;
        }
    }

    // Garbage-collect namespaces for deployments that no longer exist (deleted
    // rows are excluded from the active set above).
    gc_namespaces(&ctx.client, &active).await?;
    Ok(())
}

/// Render and apply a single deployment's Kubernetes objects.
async fn reconcile_one(
    ctx: &Context,
    deployment: &AppDeployment,
    ingress_domain: &str,
) -> Result<()> {
    let client = &ctx.client;
    let id = deployment.id;
    let app = ctx.db.get_app(deployment.app_id).await?;
    let compose = lnvps_compose::Compose::parse(&app.compose)?;
    let hostname = deployment_hostname(&deployment.name, ingress_domain);

    // 1. Namespace (restricted PSS) + default-deny NetworkPolicy.
    apply_namespace(client, &build_namespace(id)).await?;
    apply(client, &build_network_policy(id)).await?;

    // 2. Generated secrets: preserve existing values, generate any new ones.
    let existing = read_generated(client, id).await;
    let generated = ensure_secrets(&compose, &existing)?;
    apply(client, &build_generated_secret(id, &generated)).await?;

    // 3. Resolve env + files against generated secrets + customer config.
    let config = parse_config(&deployment.config);
    let vars = build_vars(&generated, &config, &hostname);
    let env = compose.resolve_env(&vars)?;
    let files = compose.resolve_files(&vars)?;

    let replicas = if deployment.desired_state == lnvps_db::AppDeploymentDesiredState::Running
        && !deployment.deleted
    {
        1
    } else {
        0
    };

    // 4. Per service: PVCs, file ConfigMap/Secret, Service, Deployment.
    for (sname, svc) in &compose.services {
        for v in &svc.volumes {
            apply(client, &build_pvc(id, sname, &v.name, &v.size)).await?;
        }
        let sfiles = files.get(sname).cloned().unwrap_or_default();
        if let Some(cm) = build_files_configmap(id, sname, &sfiles) {
            apply(client, &cm).await?;
        }
        if let Some(sec) = build_secret(id, sname, &BTreeMap::new(), &sfiles) {
            apply(client, &sec).await?;
        }
        if let Some(svc_obj) = build_service(id, sname, svc) {
            apply(client, &svc_obj).await?;
        }
        let svc_env: BTreeMap<String, String> = env
            .get(sname)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        apply(
            client,
            &build_deployment(id, sname, svc, &svc_env, &sfiles, replicas),
        )
        .await?;
    }

    // 5. Ingress for the exposed port (if any).
    if let Some(ing) = build_ingress(
        id,
        &compose,
        &hostname,
        ctx.settings
            .cluster_issuer
            .as_deref()
            .unwrap_or("letsencrypt-prod"),
        ctx.settings.ingress_class.as_deref().unwrap_or("nginx"),
    ) {
        apply(client, &ing).await?;
    }

    // 6. Status write-back: record the hostname and running state.
    let mut updated = deployment.clone();
    updated.hostname = Some(hostname);
    updated.status = if replicas == 0 {
        AppDeploymentStatus::Stopped
    } else {
        AppDeploymentStatus::Running
    };
    updated.status_message = None;
    ctx.db.update_app_deployment(&updated).await?;
    info!("reconciled app deployment {id}");
    Ok(())
}

/// Delete namespaces owned by this operator whose deployment id is not in
/// `active` (deployment deleted or removed).
async fn gc_namespaces(client: &Client, active: &HashSet<u64>) -> Result<()> {
    let api: Api<Namespace> = Api::all(client.clone());
    let lp = ListParams::default().labels(&format!("managed-by={MANAGED_BY}"));
    for ns in api.list(&lp).await?.items {
        let name = ns.name_any();
        if let Some(id) = name
            .strip_prefix("app-")
            .and_then(|s| s.parse::<u64>().ok())
            && !active.contains(&id)
        {
            info!("tearing down namespace {name} (deployment gone)");
            if let Err(e) = api.delete(&name, &Default::default()).await {
                warn!("failed to delete namespace {name}: {e}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = r#"
services:
  mariadb:
    image: mariadb:11
    env:
      MARIADB_PASSWORD: ${DB_PASSWORD}
    volumes:
      - { name: db, path: /var/lib/mysql, size: 5Gi }
  web:
    image: example/web:latest
    ports:
      - { name: http, container: 8000, protocol: http, expose: ingress }
    env:
      DATABASE_URL: "mysql://web:${DB_PASSWORD}@mariadb:3306/web"
      PUBLIC_URL: "https://${HOSTNAME}"
    files:
      - path: /etc/web.conf
        content: "name=${HOSTNAME}"
      - path: /etc/api.key
        content: "${DB_PASSWORD}"
        sensitive: true
secrets:
  - { name: DB_PASSWORD, generate: password }
config:
  - { name: unused, type: string }
"#;

    fn compose() -> Compose {
        Compose::parse(APP).unwrap()
    }

    #[test]
    fn namespace_is_restricted() {
        let ns = build_namespace(7);
        assert_eq!(ns.metadata.name.as_deref(), Some("app-7"));
        let l = ns.metadata.labels.unwrap();
        assert_eq!(
            l.get("pod-security.kubernetes.io/enforce")
                .map(String::as_str),
            Some("restricted")
        );
        assert_eq!(l.get("managed-by").map(String::as_str), Some(MANAGED_BY));
    }

    #[test]
    fn netpol_denies_all() {
        let np = build_network_policy(7);
        let spec = np.spec.unwrap();
        assert_eq!(
            spec.policy_types,
            Some(vec!["Ingress".to_string(), "Egress".to_string()])
        );
        // no ingress/egress allow rules => deny
        assert!(spec.ingress.is_none());
        assert!(spec.egress.is_none());
    }

    #[test]
    fn quota_sets_hard_limits() {
        let q = build_resource_quota(7, "2", "2Gi", "30Gi");
        let hard = q.spec.unwrap().hard.unwrap();
        assert_eq!(hard.get("limits.cpu").unwrap().0, "2");
        assert_eq!(hard.get("requests.storage").unwrap().0, "30Gi");
    }

    #[test]
    fn pvc_is_rwo_with_size() {
        let pvc = build_pvc(7, "mariadb", "db", "5Gi");
        assert_eq!(pvc.metadata.name.as_deref(), Some("mariadb-db"));
        let spec = pvc.spec.unwrap();
        assert_eq!(spec.access_modes, Some(vec!["ReadWriteOnce".to_string()]));
        assert_eq!(
            spec.resources
                .unwrap()
                .requests
                .unwrap()
                .get("storage")
                .unwrap()
                .0,
            "5Gi"
        );
    }

    #[test]
    fn service_only_when_ports() {
        let c = compose();
        // mariadb has no ports -> no Service
        assert!(build_service(7, "mariadb", &c.services["mariadb"]).is_none());
        // web has a port -> Service named after the service
        let svc = build_service(7, "web", &c.services["web"]).unwrap();
        assert_eq!(svc.metadata.name.as_deref(), Some("web"));
        assert_eq!(svc.spec.unwrap().ports.unwrap()[0].port, 8000);
    }

    #[test]
    fn deployment_mounts_pvc_and_files_locked_down() {
        let c = compose();
        let files = vec![
            ResolvedFile {
                path: "/etc/web.conf".to_string(),
                content: "name=x".to_string(),
                sensitive: false,
            },
            ResolvedFile {
                path: "/etc/api.key".to_string(),
                content: "secret".to_string(),
                sensitive: true,
            },
        ];
        let env = BTreeMap::from([("PUBLIC_URL".to_string(), "https://h".to_string())]);
        let d = build_deployment(7, "web", &c.services["web"], &env, &files, 1);
        let spec = d.spec.unwrap();
        assert_eq!(spec.replicas, Some(1));
        assert_eq!(spec.strategy.unwrap().type_.as_deref(), Some("Recreate"));

        let pod = spec.template.spec.unwrap();
        assert_eq!(pod.security_context.unwrap().run_as_non_root, Some(true));
        let ctr = &pod.containers[0];
        let sc = ctr.security_context.as_ref().unwrap();
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(
            sc.capabilities.as_ref().unwrap().drop,
            Some(vec!["ALL".to_string()])
        );

        // A read-only subPath mount for each file.
        let m = ctr.volume_mounts.as_ref().unwrap();
        let conf = m.iter().find(|x| x.mount_path == "/etc/web.conf").unwrap();
        assert_eq!(conf.sub_path.as_deref(), Some("etc-web.conf"));
        assert_eq!(conf.read_only, Some(true));
        assert_eq!(conf.name, "files-cm");
        let key = m.iter().find(|x| x.mount_path == "/etc/api.key").unwrap();
        assert_eq!(key.name, "files-secret");
    }

    #[test]
    fn stopped_deployment_has_zero_replicas() {
        let c = compose();
        let d = build_deployment(7, "web", &c.services["web"], &BTreeMap::new(), &[], 0);
        assert_eq!(d.spec.unwrap().replicas, Some(0));
    }

    #[test]
    fn files_split_configmap_vs_secret() {
        let files = vec![
            ResolvedFile {
                path: "/etc/web.conf".to_string(),
                content: "a".to_string(),
                sensitive: false,
            },
            ResolvedFile {
                path: "/etc/api.key".to_string(),
                content: "b".to_string(),
                sensitive: true,
            },
        ];
        let cm = build_files_configmap(7, "web", &files).unwrap();
        assert!(cm.data.as_ref().unwrap().contains_key("etc-web.conf"));
        assert!(!cm.data.unwrap().contains_key("etc-api.key"));

        let generated = BTreeMap::from([("DB_PASSWORD".to_string(), "pw".to_string())]);
        let sec = build_secret(7, "web", &generated, &files).unwrap();
        let data = sec.data.unwrap();
        assert!(data.contains_key("DB_PASSWORD"));
        assert!(data.contains_key("etc-api.key"));
        assert!(!data.contains_key("etc-web.conf"));

        // No generated + no sensitive files -> no Secret.
        assert!(build_secret(7, "web", &BTreeMap::new(), &files[..1]).is_none());
        assert!(build_files_configmap(7, "mariadb", &[]).is_none());
    }

    #[test]
    fn ingress_targets_exposed_port_with_tls() {
        let c = compose();
        let ing =
            build_ingress(7, &c, "relay.apps.example.com", "letsencrypt-prod", "nginx").unwrap();
        let spec = ing.spec.unwrap();
        assert_eq!(
            spec.tls.unwrap()[0].hosts.as_ref().unwrap()[0],
            "relay.apps.example.com"
        );
        let rule = &spec.rules.unwrap()[0];
        assert_eq!(rule.host.as_deref(), Some("relay.apps.example.com"));
        let backend = rule.http.as_ref().unwrap().paths[0]
            .backend
            .service
            .as_ref()
            .unwrap();
        assert_eq!(backend.name, "web");
        assert_eq!(backend.port.as_ref().unwrap().number, Some(8000));
    }

    #[test]
    fn ingress_none_without_exposed_port() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 5, protocol: tcp }\n",
        )
        .unwrap();
        assert!(build_ingress(7, &c, "h", "i", "nginx").is_none());
    }

    #[test]
    fn ensure_secrets_generates_and_preserves() {
        let c = compose();
        let first = ensure_secrets(&c, &BTreeMap::new()).unwrap();
        assert!(first.contains_key("DB_PASSWORD"));
        assert!(!first["DB_PASSWORD"].is_empty());
        // Re-running preserves the existing value.
        let second = ensure_secrets(&c, &first).unwrap();
        assert_eq!(first["DB_PASSWORD"], second["DB_PASSWORD"]);
    }

    #[test]
    fn vars_merge_and_resolve_full_app() {
        let c = compose();
        let generated = ensure_secrets(&c, &BTreeMap::new()).unwrap();
        let config = BTreeMap::new();
        let host = deployment_hostname("my-relay", "apps.example.com");
        let vars = build_vars(&generated, &config, &host);

        // env + files resolve end-to-end against the generated secret.
        let env = c.resolve_env(&vars).unwrap();
        assert_eq!(
            env["web"]["PUBLIC_URL"],
            "https://my-relay.apps.example.com"
        );
        assert!(env["web"]["DATABASE_URL"].contains(&generated["DB_PASSWORD"]));
        let files = c.resolve_files(&vars).unwrap();
        let web_files = &files["web"];
        assert!(
            web_files
                .iter()
                .any(|f| f.path == "/etc/api.key" && f.sensitive)
        );
    }

    #[test]
    fn generate_secret_value_is_random_hex() {
        let a = generate_secret_value(24);
        let b = generate_secret_value(24);
        assert_eq!(a.len(), 48);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
