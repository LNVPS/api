//! Reconcile managed **app deployments** into Kubernetes.
//!
//! Each `app_deployment` row (for this operator's cluster) is rendered from its
//! app's `lnvps_compose` document into a set of namespaced Kubernetes objects:
//! a locked-down Namespace (one per deployment) with an isolation
//! NetworkPolicy and a ResourceQuota, a Deployment + Service per compose
//! service, an Ingress for each `expose: ingress` port, PVCs for `volumes:`, and
//! ConfigMap/Secret-backed `files:` mounted read-only via `subPath`.
//!
//! The object **builders** are pure functions (unit-tested without a cluster);
//! [`reconcile_app_deployments`] resolves config/secrets and applies them.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;

use anyhow::{Result, anyhow};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use kube::{Client, Resource, ResourceExt};
use log::{error, info, warn};
use serde::Serialize;
use serde::de::DeserializeOwned;

use k8s_openapi::NamespaceResourceScope;
use lnvps_db::{
    AppDeployment, AppDeploymentStatus, EncryptedString, Subscription,
};

use crate::Context;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, Namespace, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, PodSecurityContext, PodSpec, PodTemplateSpec, ResourceQuota,
    ResourceRequirements, SeccompProfile, SecurityContext, Service, ServicePort, ServiceSpec,
    Volume as K8sVolume, VolumeMount, VolumeResourceRequirements,
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

/// A namespace for a deployment, labelled for a Pod Security Standard
/// enforcement `level` (`restricted` or `baseline`) so the admission
/// controller rejects pods that violate it.
pub fn build_namespace_with_level(deployment_id: u64, level: &str) -> Namespace {
    let mut l = labels(deployment_id);
    l.insert(
        "pod-security.kubernetes.io/enforce".to_string(),
        level.to_string(),
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

/// A namespace for a deployment, labelled for the **restricted** Pod Security
/// Standard so the admission controller rejects privileged pods.
pub fn build_namespace(deployment_id: u64) -> Namespace {
    build_namespace_with_level(deployment_id, "restricted")
}

/// A namespace for a deployment containing a root-entrypoint service (mariadb,
/// postgres, redis, …). The **baseline** standard still blocks genuinely
/// dangerous pods (privileged, host namespaces/ports/PID/IPC, hostPath) but
/// does not force `runAsNonRoot`, so a curated image that starts as root and
/// drops privileges itself can be admitted. The per-container SecurityContext
/// (no privilege escalation, drop ALL caps, read-only root fs) still applies.
pub fn build_namespace_baseline(deployment_id: u64) -> Namespace {
    build_namespace_with_level(deployment_id, "baseline")
}

/// The isolation NetworkPolicy for a deployment namespace.
///
/// Tenant isolation without cutting the deployment off from the outside world:
///
/// * **Ingress** — accept traffic only from the ingress-controller namespace
///   (the inbound HTTP path) and from pods in the deployment's own namespace
///   (multi-service apps). Other tenants' namespaces are denied.
/// * **Egress** — allow DNS (so services resolve each other and the internet),
///   same-namespace traffic (e.g. `app` → its `db`), and the **public
///   internet** — minus RFC1918 / CGNAT / link-local ranges. Excluding those
///   private ranges keeps a deployment from reaching other tenants' pods,
///   in-cluster services, the Kubernetes API, or the cloud metadata endpoint
///   (`169.254.169.254`), while still permitting normal outbound internet
///   access (relay sync, blastr, webhooks, API calls, …).
pub fn build_network_policy(deployment_id: u64, ingress_namespace: &str) -> NetworkPolicy {
    use k8s_openapi::api::networking::v1::{
        IPBlock, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPeer,
        NetworkPolicyPort,
    };
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    // All pods in this deployment's own namespace.
    let same_ns = NetworkPolicyPeer {
        pod_selector: Some(LabelSelector::default()),
        ..Default::default()
    };
    // The public internet, minus internal ranges a tenant must not reach
    // directly (other pods/services, kube API, cloud metadata, CGNAT).
    let internet = NetworkPolicyPeer {
        ip_block: Some(IPBlock {
            cidr: "0.0.0.0/0".to_string(),
            except: Some(vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                // link-local incl. the cloud metadata endpoint 169.254.169.254
                "169.254.0.0/16".to_string(),
                "100.64.0.0/10".to_string(), // CGNAT
            ]),
        }),
        ..Default::default()
    };
    // `..Default::default()` covers the optional `end_port` field, which only
    // exists under some k8s_openapi feature sets; harmless where it doesn't.
    #[allow(clippy::needless_update)]
    let dns_ports = vec![
        NetworkPolicyPort {
            protocol: Some("UDP".to_string()),
            port: Some(IntOrString::Int(53)),
            ..Default::default()
        },
        NetworkPolicyPort {
            protocol: Some("TCP".to_string()),
            port: Some(IntOrString::Int(53)),
            ..Default::default()
        },
    ];
    let ingress_controller = NetworkPolicyPeer {
        namespace_selector: Some(LabelSelector {
            match_labels: Some(BTreeMap::from([(
                "kubernetes.io/metadata.name".to_string(),
                ingress_namespace.to_string(),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    };

    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some("default-isolation".to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector::default(),
            policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![same_ns.clone(), ingress_controller]),
                ports: None,
            }]),
            egress: Some(vec![
                // DNS to the cluster resolver (any destination, port 53 only).
                NetworkPolicyEgressRule {
                    to: None,
                    ports: Some(dns_ports),
                },
                // Same-namespace service-to-service (e.g. app -> its DB).
                NetworkPolicyEgressRule {
                    to: Some(vec![same_ns]),
                    ports: None,
                },
                // The public internet (private/cluster/metadata ranges excluded).
                NetworkPolicyEgressRule {
                    to: Some(vec![internet]),
                    ports: None,
                },
            ]),
        }),
    }
}

/// Container requests == limits (Guaranteed QoS, 1:1 — no overcommit) from a
/// compose service's `resources`.
fn build_resource_requirements(r: &lnvps_compose::Resources) -> ResourceRequirements {
    let map = BTreeMap::from([
        ("cpu".to_string(), Quantity(r.cpu.clone())),
        ("memory".to_string(), Quantity(r.memory.clone())),
    ]);
    ResourceRequirements {
        requests: Some(map.clone()),
        limits: Some(map),
        ..Default::default()
    }
}

/// Remove the per-namespace `ResourceQuota` if one is still present.
///
/// Deployment namespaces no longer carry a quota at all, because it enforced
/// nothing that isn't already enforced while breaking legitimate operations:
///
/// - Every container is created with `requests == limits` from the compose
///   (see [`build_resource_requirements`], Guaranteed QoS) and `replicas` is
///   fixed at 0 or 1; PVC sizes come from the compose too. Customers have no
///   Kubernetes API access — this operator is the only writer in the namespace
///   — so the workload cannot exceed its provisioned footprint with or without
///   a quota. Cluster-level capacity is enforced at order/upgrade time by
///   `AppClusterCapacityService`, not here.
/// - Sized to *exactly* the footprint, it left zero headroom, so anything
///   needing transient extra capacity was rejected: cert-manager's ephemeral
///   ACME HTTP-01 solver pod (`limits.cpu=100m,limits.memory=64Mi`), which
///   blocked all TLS issuance, and later PVC growth/replacement
///   (`requests.storage=5Gi, used: 5Gi, limited: 5Gi`), which blocked volume
///   expansion because the outgoing PVC still counts toward usage while the
///   incoming one is admitted.
///
/// Deleting is idempotent — a `404` means it is already gone. This runs on
/// every reconcile so namespaces created before the quota was retired heal
/// themselves; server-side apply cannot prune an object we simply stop
/// applying.
async fn delete_resource_quota(client: &Client, deployment_id: u64) -> Result<()> {
    let api: Api<ResourceQuota> = Api::namespaced(client.clone(), &namespace_name(deployment_id));
    match api.delete("quota", &DeleteParams::default()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
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
///
/// `run_as_non_root` is normally `true` (default-deny). It is set to `false`
/// only when the catalog compose service opts in via `user: root` — for images
/// whose entrypoint must *start* as root and drop privileges itself (mariadb,
/// postgres, redis). The other restrictions stay in force either way.
fn container_security_context_for(run_as_non_root: bool) -> SecurityContext {
    use k8s_openapi::api::core::v1::Capabilities;
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(run_as_non_root),
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
        security_context: Some(container_security_context_for(!svc.runs_as_root())),
        resources: Some(build_resource_requirements(&svc.resources)),
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
                    // Don't mount the ServiceAccount token: a managed app never
                    // talks to the Kubernetes API, and withholding the token
                    // blocks API access even on CNIs that don't enforce the
                    // isolation NetworkPolicy (e.g. Flannel). Enforced by the
                    // kubelet, independent of the CNI.
                    automount_service_account_token: Some(false),
                    // Don't inject `*_SERVICE_HOST/PORT` env vars for every
                    // service in the namespace (avoids leaking topology).
                    enable_service_links: Some(false),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// An Ingress routing `hostname` (and an optional customer `custom_domain`) to
/// the first `expose: ingress` port found across the app's services, with
/// cert-manager TLS. Returns `None` when no service exposes an ingress port.
/// `issuer`/`class` come from operator config.
///
/// Both hosts serve the same backend. Each gets its own TLS secret
/// (`app-tls` for the default host, `app-tls-custom` for the custom domain) so
/// cert-manager issues a separate certificate per host via HTTP-01 — the custom
/// domain's cert is only solvable once the customer's CNAME points at us.
pub fn build_ingress(
    deployment_id: u64,
    compose: &Compose,
    hostname: &str,
    custom_domain: Option<&str>,
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

    // cert-manager cluster-issuer drives TLS issuance. The ingress class is set
    // via the modern `spec.ingressClassName` (below) rather than the deprecated
    // `kubernetes.io/ingress.class` annotation, which recent ingress-nginx
    // ignores (and warns about if both are present).
    let annotations = BTreeMap::from([(
        "cert-manager.io/cluster-issuer".to_string(),
        issuer.to_string(),
    )]);

    let rule_for = |host: &str| IngressRule {
        host: Some(host.to_string()),
        http: Some(HTTPIngressRuleValue {
            paths: vec![HTTPIngressPath {
                path: Some(port.path.clone().unwrap_or_else(|| "/".to_string())),
                path_type: "Prefix".to_string(),
                backend: IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: service_name.clone(),
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

    let mut rules = vec![rule_for(hostname)];
    let mut tls = vec![IngressTLS {
        hosts: Some(vec![hostname.to_string()]),
        secret_name: Some("app-tls".to_string()),
    }];
    // Custom domain (dedup against the default host in case they're identical).
    if let Some(cd) = custom_domain
        && !cd.eq_ignore_ascii_case(hostname)
    {
        rules.push(rule_for(cd));
        tls.push(IngressTLS {
            hosts: Some(vec![cd.to_string()]),
            secret_name: Some("app-tls-custom".to_string()),
        });
    }

    Some(Ingress {
        metadata: ObjectMeta {
            name: Some("app".to_string()),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            ingress_class_name: Some(class.to_string()),
            tls: Some(tls),
            rules: Some(rules),
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

/// Why a deployment's workload is not running (drives the reconcile billing
/// gate). Each variant maps to a customer-visible reason so a deployment that
/// *should* be running never silently sits at 0 replicas with no explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateReason {
    /// Running: subscription set up (paid), not expired, desired running.
    Running,
    /// Customer (or admin) set the deployment's desired state to stopped.
    StoppedByUser,
    /// The subscription could not be read (DB error, or decryption of an
    /// encrypted column failed because the operator's encryption key is
    /// missing/mismatched). Distinct from [`GateReason::Unpaid`]: this is an
    /// operational fault, not a billing state, and must be loud.
    SubscriptionLookupFailed(String),
    /// The subscription's initial purchase payment has not been confirmed
    /// (`is_setup = 0`) — a freshly-ordered, unpaid deployment.
    Unpaid,
    /// The subscription was paid but has since expired (and is within the
    /// grace period, so data is retained at 0 replicas).
    Expired,
}

impl std::fmt::Display for GateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateReason::Running => write!(f, "running"),
            GateReason::StoppedByUser => write!(f, "deployment stopped by user"),
            GateReason::SubscriptionLookupFailed(e) => {
                write!(f, "subscription lookup failed: {e}")
            }
            GateReason::Unpaid => write!(f, "subscription not yet paid"),
            GateReason::Expired => write!(f, "subscription expired (data retained)"),
        }
    }
}

/// The pure billing/lifecycle gate: given the deployment's desired state and
/// its subscription (or the lookup error), decide whether the workload runs.
///
/// Returns [`GateReason::Running`] (1 replica) or the reason it stays at 0.
/// Extracted as a pure function so the gate logic is unit-testable without a
/// cluster or DB.
pub fn gate_running(
    desired_running: bool,
    deleted: bool,
    sub: Option<&Subscription>,
    sub_lookup_err: Option<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> GateReason {
    if deleted || !desired_running {
        return GateReason::StoppedByUser;
    }
    if let Some(e) = sub_lookup_err {
        return GateReason::SubscriptionLookupFailed(e);
    }
    let Some(sub) = sub else {
        // Lookup succeeded but found nothing — treat as unpaid (no billing
        // record yet) rather than an operational fault.
        return GateReason::Unpaid;
    };
    if !sub.is_setup {
        return GateReason::Unpaid;
    }
    if sub.expires.map(|e| e < now).unwrap_or(false) {
        return GateReason::Expired;
    }
    GateReason::Running
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

    // 1. Namespace (Pod Security Standard) + isolation NetworkPolicy.
    // Default to the restricted PSS; drop to baseline only when a catalog
    // service opts into running as root (e.g. mariadb), whose entrypoint
    // starts as root and drops privileges itself. Baseline still blocks
    // privileged pods / host namespaces, ports, PID/IPC and hostPath.
    let namespace = if compose.services.values().any(|s| s.runs_as_root()) {
        build_namespace_baseline(id)
    } else {
        build_namespace(id)
    };
    apply_namespace(client, &namespace).await?;
    let ingress_ns = ctx
        .settings
        .ingress_namespace
        .as_deref()
        .unwrap_or("ingress-nginx");
    apply(client, &build_network_policy(id, ingress_ns)).await?;

    // 2. Generated secrets: preserve existing values, generate any new ones.
    let existing = read_generated(client, id).await;
    let generated = ensure_secrets(&compose, &existing)?;
    apply(client, &build_generated_secret(id, &generated)).await?;

    // 3. Resolve env + files against generated secrets + customer config.
    let config = parse_config(&deployment.config);
    let vars = build_vars(&generated, &config, &hostname);
    let env = compose.resolve_env(&vars)?;
    let files = compose.resolve_files(&vars)?;

    // Billing gate + retention. The workload only runs when the subscription is
    // set up (paid at least once) and not expired. A freshly-ordered, unpaid
    // deployment (not set up) stays at 0 replicas; an expired one scales to 0
    // but keeps its PVCs (customer data) — only real deletion tears it down.
    //
    // The lookup error is NOT swallowed: a DB/decryption fault here must be
    // surfaced (and the gate fails closed) rather than silently reading as
    // "unpaid", which is how a paid deployment previously sat at 0 replicas
    // with an empty status message.
    let (sub, sub_err) = match ctx
        .db
        .get_subscription_by_line_item_id(deployment.subscription_line_item_id)
        .await
    {
        Ok(s) => (Some(s), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let desired_running =
        deployment.desired_state == lnvps_db::AppDeploymentDesiredState::Running;
    let gate = gate_running(
        desired_running,
        deployment.deleted,
        sub.as_ref(),
        sub_err,
        chrono::Utc::now(),
    );
    // Log the gate's actual inputs so a surprising conclusion (e.g. "not yet
    // paid" on a subscription that looks paid in the DB) can be diagnosed
    // against the exact is_setup/expires the operator decoded.
    if gate != GateReason::Running {
        info!(
            "app deployment {id} gate={gate}: desired_running={desired_running} deleted={} sub={:?}",
            deployment.deleted,
            sub.as_ref().map(|s| (s.id, s.is_setup, s.expires))
        );
    }
    let replicas = if gate == GateReason::Running { 1 } else { 0 };

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

    // 5. Ingress for the exposed port (if any), serving both the default
    // hostname and any customer custom domain.
    if let Some(ing) = build_ingress(
        id,
        &compose,
        &hostname,
        deployment.custom_domain.as_deref(),
        ctx.settings
            .cluster_issuer
            .as_deref()
            .unwrap_or("letsencrypt-prod"),
        ctx.settings.ingress_class.as_deref().unwrap_or("nginx"),
    ) {
        apply(client, &ing).await?;
    }

    // 6. Remove any leftover ResourceQuota. Namespaces are deliberately not
    // quota'd - see delete_resource_quota for why - but ones provisioned
    // before that change still have the object, which blocks PVC growth.
    delete_resource_quota(client, id).await?;

    // 7. Status write-back: record the hostname and running state. When the
    // workload isn't running, surface *why* so a paid-intended deployment never
    // sits at 0 replicas with no explanation (previously a silent `stopped`).
    let mut updated = deployment.clone();
    updated.hostname = Some(hostname);
    match &gate {
        GateReason::Running => {
            updated.status = AppDeploymentStatus::Running;
            updated.status_message = None;
        }
        // A lookup fault is an operational error, not a lifecycle state — mark
        // it Error so it's visibly wrong and alerted on, not a calm `stopped`.
        GateReason::SubscriptionLookupFailed(e) => {
            updated.status = AppDeploymentStatus::Error;
            updated.status_message = Some(format!("subscription lookup failed: {e}"));
            error!("app deployment {id} not running: subscription lookup failed: {e}");
        }
        reason => {
            updated.status = AppDeploymentStatus::Stopped;
            updated.status_message = Some(reason.to_string());
            info!("app deployment {id} not running: {reason}");
        }
    }
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

    /// A deployment with a root-entrypoint service gets the baseline PSS (which
    /// permits starting as root) instead of restricted; restricted stays the
    /// default otherwise.
    #[test]
    fn namespace_baseline_for_root_services() {
        let base = build_namespace_baseline(7);
        let l = base.metadata.labels.unwrap();
        assert_eq!(
            l.get("pod-security.kubernetes.io/enforce")
                .map(String::as_str),
            Some("baseline")
        );
        assert_eq!(
            l.get("pod-security.kubernetes.io/enforce-version")
                .map(String::as_str),
            Some("latest")
        );

        // The parameterized builder produces identical output for both levels.
        let r = build_namespace_with_level(7, "restricted");
        assert_eq!(
            r.metadata.labels.as_ref().unwrap()
                .get("pod-security.kubernetes.io/enforce")
                .map(String::as_str),
            Some("restricted")
        );
    }

    /// A `user: root` service omits runAsNonRoot on its container; a normal
    /// service keeps it (default-deny hardening).
    #[test]
    fn root_service_omits_run_as_non_root() {
        let root = Compose::parse("services:\n  db:\n    image: mariadb:11\n    user: root\n")
            .unwrap();
        let d = build_deployment(7, "db", &root.services["db"], &BTreeMap::new(), &[], 1);
        let ctr = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let sc = ctr.security_context.as_ref().unwrap();
        assert_eq!(sc.run_as_non_root, Some(false));
        // The rest of the lockdown still applies.
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(
            sc.capabilities.as_ref().unwrap().drop,
            Some(vec!["ALL".to_string()])
        );

        // Default (no user:) stays runAsNonRoot.
        let plain = Compose::parse("services:\n  app:\n    image: x\n").unwrap();
        let d = build_deployment(7, "app", &plain.services["app"], &BTreeMap::new(), &[], 1);
        let ctr = &d.spec.unwrap().template.spec.unwrap().containers[0];
        assert_eq!(
            ctr.security_context.as_ref().unwrap().run_as_non_root,
            Some(true)
        );
    }

    #[test]
    fn netpol_isolates_but_allows_internet_egress() {
        let np = build_network_policy(7, "ingress-nginx");
        let spec = np.spec.unwrap();
        assert_eq!(
            spec.policy_types,
            Some(vec!["Ingress".to_string(), "Egress".to_string()])
        );

        // Ingress: only same-namespace + the ingress controller namespace.
        let ingress = spec.ingress.expect("ingress rules");
        let from = ingress[0].from.as_ref().unwrap();
        assert!(from.iter().any(|p| p.pod_selector.is_some()));
        assert!(from.iter().any(|p| {
            p.namespace_selector
                .as_ref()
                .and_then(|s| s.match_labels.as_ref())
                .and_then(|l| l.get("kubernetes.io/metadata.name"))
                .map(|v| v == "ingress-nginx")
                .unwrap_or(false)
        }));

        // Egress: DNS (port 53), same-namespace, and internet with private
        // ranges excluded.
        let egress = spec.egress.expect("egress rules");
        assert!(egress.iter().any(|r| {
            r.ports
                .as_ref()
                .map(|ps| ps.iter().any(|p| p.protocol.as_deref() == Some("UDP")))
                .unwrap_or(false)
        }));
        let internet = egress
            .iter()
            .find_map(|r| r.to.as_ref()?.iter().find_map(|p| p.ip_block.as_ref()))
            .expect("internet ipBlock");
        assert_eq!(internet.cidr, "0.0.0.0/0");
        let except = internet.except.as_ref().unwrap();
        assert!(except.contains(&"10.0.0.0/8".to_string()));
        // cloud metadata endpoint is inside the excluded link-local range
        assert!(except.contains(&"169.254.0.0/16".to_string()));
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

        let pod = spec.template.spec.clone().unwrap();
        assert_eq!(
            pod.security_context.as_ref().unwrap().run_as_non_root,
            Some(true)
        );
        // ServiceAccount token withheld (blocks kube-API even without a
        // policy-enforcing CNI) and service-link env injection disabled.
        assert_eq!(pod.automount_service_account_token, Some(false));
        assert_eq!(pod.enable_service_links, Some(false));
        let ctr = &pod.containers[0];
        // Container carries requests == limits from the compose resources
        // (defaults 250m / 256Mi here).
        let res = ctr.resources.as_ref().unwrap();
        assert_eq!(res.requests.as_ref().unwrap().get("cpu").unwrap().0, "250m");
        assert_eq!(
            res.limits.as_ref().unwrap().get("memory").unwrap().0,
            "256Mi"
        );
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
        let ing = build_ingress(
            7,
            &c,
            "relay.apps.example.com",
            None,
            "letsencrypt-prod",
            "nginx",
        )
        .unwrap();
        // cert-manager issuer via annotation; ingress class via the modern
        // spec.ingressClassName (not the deprecated annotation).
        let ann = ing.metadata.annotations.as_ref().unwrap();
        assert_eq!(
            ann.get("cert-manager.io/cluster-issuer")
                .map(|s| s.as_str()),
            Some("letsencrypt-prod")
        );
        assert!(!ann.contains_key("kubernetes.io/ingress.class"));
        let spec = ing.spec.unwrap();
        assert_eq!(spec.ingress_class_name.as_deref(), Some("nginx"));
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
        assert!(build_ingress(7, &c, "h", None, "i", "nginx").is_none());
    }

    /// A custom domain adds a second rule + a separate TLS secret
    /// (`app-tls-custom`), while the default host keeps its own (`app-tls`).
    #[test]
    fn ingress_adds_custom_domain_rule_and_tls() {
        let c = compose();
        let ing = build_ingress(
            7,
            &c,
            "relay.apps.example.com",
            Some("blog.example.com"),
            "letsencrypt-prod",
            "nginx",
        )
        .unwrap();
        let spec = ing.spec.unwrap();

        // Two rules: default host + custom domain, same backend.
        let rules = spec.rules.unwrap();
        let hosts: Vec<&str> = rules
            .iter()
            .filter_map(|r| r.host.as_deref())
            .collect();
        assert_eq!(hosts, vec!["relay.apps.example.com", "blog.example.com"]);
        let backend = rules[1].http.as_ref().unwrap().paths[0]
            .backend
            .service
            .as_ref()
            .unwrap();
        assert_eq!(backend.name, "web");

        // Two TLS blocks with distinct secrets/hosts.
        let tls = spec.tls.unwrap();
        assert_eq!(tls.len(), 2);
        assert_eq!(tls[0].secret_name.as_deref(), Some("app-tls"));
        assert_eq!(
            tls[0].hosts.as_ref().unwrap(),
            &vec!["relay.apps.example.com".to_string()]
        );
        assert_eq!(tls[1].secret_name.as_deref(), Some("app-tls-custom"));
        assert_eq!(
            tls[1].hosts.as_ref().unwrap(),
            &vec!["blog.example.com".to_string()]
        );

        // Custom domain identical to the default host is deduped (no dup rule).
        let ing = build_ingress(
            7,
            &c,
            "relay.apps.example.com",
            Some("relay.apps.example.com"),
            "letsencrypt-prod",
            "nginx",
        )
        .unwrap();
        let spec = ing.spec.unwrap();
        assert_eq!(spec.rules.unwrap().len(), 1);
        assert_eq!(spec.tls.unwrap().len(), 1);
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

    /// Full compose → Kubernetes mapping, mirroring `reconcile_one`: generate
    /// secrets, resolve env/files against them, then assert the resolved values
    /// actually land in the rendered Deployment / ConfigMap / Secret / Service /
    /// Ingress / PVC objects for every service.
    #[test]
    fn compose_maps_to_k8s_end_to_end() {
        let c = compose();
        let id = 42u64;
        let host = deployment_hostname("my-relay", "apps.example.com");

        // 1. Generate secrets and resolve env/files exactly like the reconciler.
        let generated = ensure_secrets(&c, &BTreeMap::new()).unwrap();
        let pw = generated["DB_PASSWORD"].clone();
        let vars = build_vars(&generated, &BTreeMap::new(), &host);
        let env = c.resolve_env(&vars).unwrap();
        let files = c.resolve_files(&vars).unwrap();
        let to_bt = |m: &std::collections::HashMap<String, String>| -> BTreeMap<String, String> {
            m.clone().into_iter().collect()
        };

        // ── web service (ingress, files: ConfigMap + Secret, env with vars) ──
        let web_env = to_bt(&env["web"]);
        let web_files = files["web"].clone();
        let web = build_deployment(id, "web", &c.services["web"], &web_env, &web_files, 1);
        let pod = web.spec.unwrap().template.spec.unwrap();
        let ctr = &pod.containers[0];
        assert_eq!(ctr.image.as_deref(), Some("example/web:latest"));

        // Env is inlined with fully-resolved values (no `${…}` left).
        let cenv: BTreeMap<String, String> = ctr
            .env
            .as_ref()
            .unwrap()
            .iter()
            .map(|e| (e.name.clone(), e.value.clone().unwrap_or_default()))
            .collect();
        assert_eq!(
            cenv["DATABASE_URL"],
            format!("mysql://web:{pw}@mariadb:3306/web")
        );
        assert_eq!(cenv["PUBLIC_URL"], "https://my-relay.apps.example.com");
        assert!(cenv.values().all(|v| !v.contains("${")));

        // File mounts: non-sensitive via ConfigMap volume, sensitive via Secret
        // volume — both read-only + subPath so they don't shadow the dir.
        let mounts = ctr.volume_mounts.as_ref().unwrap();
        let conf = mounts
            .iter()
            .find(|m| m.mount_path == "/etc/web.conf")
            .unwrap();
        assert_eq!(conf.name, "files-cm");
        assert_eq!(conf.read_only, Some(true));
        assert!(conf.sub_path.is_some());
        let key = mounts
            .iter()
            .find(|m| m.mount_path == "/etc/api.key")
            .unwrap();
        assert_eq!(key.name, "files-secret");
        assert_eq!(key.read_only, Some(true));

        // ConfigMap carries only the non-sensitive file, rendered with ${HOSTNAME}.
        let cm = build_files_configmap(id, "web", &web_files).unwrap();
        let cm_data = cm.data.unwrap();
        assert_eq!(cm_data.len(), 1);
        assert!(
            cm_data
                .values()
                .any(|v| v == "name=my-relay.apps.example.com")
        );

        // Secret carries only the sensitive file, rendered to the generated pw.
        let sec = build_secret(id, "web", &BTreeMap::new(), &web_files).unwrap();
        let sec_data = sec.data.unwrap();
        assert_eq!(sec_data.len(), 1);
        assert!(sec_data.values().any(|b| b.0 == pw.clone().into_bytes()));

        // Service + Ingress target web's exposed port 8000.
        let svc = build_service(id, "web", &c.services["web"]).unwrap();
        assert_eq!(svc.spec.unwrap().ports.unwrap()[0].port, 8000);
        let ing = build_ingress(id, &c, &host, None, "letsencrypt-prod", "nginx").unwrap();
        let backend = ing.spec.unwrap().rules.unwrap()[0]
            .http
            .as_ref()
            .unwrap()
            .paths[0]
            .backend
            .service
            .clone()
            .unwrap();
        assert_eq!(backend.name, "web");
        assert_eq!(backend.port.unwrap().number, Some(8000));

        // ── mariadb service (no ports, PVC, secret injected into env) ──
        let db_env = to_bt(&env["mariadb"]);
        assert_eq!(db_env["MARIADB_PASSWORD"], pw);
        let db = build_deployment(id, "mariadb", &c.services["mariadb"], &db_env, &[], 1);
        let db_pod = db.spec.unwrap().template.spec.unwrap();
        let vm = db_pod.containers[0]
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.mount_path == "/var/lib/mysql")
            .unwrap();
        assert_eq!(vm.name, "mariadb-db");
        // No declared ports ⇒ no Service.
        assert!(build_service(id, "mariadb", &c.services["mariadb"]).is_none());
        // PVC uses the declared size.
        let vol = &c.services["mariadb"].volumes[0];
        let pvc = build_pvc(id, "mariadb", &vol.name, &vol.size);
        assert_eq!(
            pvc.spec.unwrap().resources.unwrap().requests.unwrap()["storage"].0,
            "5Gi"
        );

        // ── lifecycle: stopped ⇒ 0 replicas (data-preserving) ──
        let stopped = build_deployment(id, "web", &c.services["web"], &web_env, &web_files, 0);
        assert_eq!(stopped.spec.unwrap().replicas, Some(0));
    }

    /// Extract every ```yaml fenced block from a markdown doc, tagged with the
    /// nearest preceding `## ` heading (used to name the fixture in failures).
    fn extract_yaml_blocks(md: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut heading = String::new();
        let mut lines = md.lines();
        while let Some(line) = lines.next() {
            if let Some(h) = line.strip_prefix("## ") {
                heading = h.trim().to_string();
            } else if line.trim_start() == "```yaml" {
                let mut body = String::new();
                for l in lines.by_ref() {
                    if l.trim_start() == "```" {
                        break;
                    }
                    body.push_str(l);
                    body.push('\n');
                }
                out.push((heading.clone(), body));
            }
        }
        out
    }

    /// Every app compose published in `docs/managed-app-examples.md` must run
    /// through the full compose → Kubernetes pipeline: parse, validate, compute
    /// a footprint, resolve secrets/config/files, and render each service's
    /// Deployment / Service / PVC / ConfigMap / Secret plus the shared Ingress /
    /// NetworkPolicy / ResourceQuota — without panicking and with the key
    /// invariants intact. This keeps the documented fixtures from drifting out
    /// of the grammar the operator actually implements.
    #[test]
    fn documented_examples_map_to_k8s() {
        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/managed-app-examples.md"
        ))
        .expect("read docs/managed-app-examples.md");

        let examples = extract_yaml_blocks(&doc);
        assert!(
            examples.len() >= 6,
            "expected at least the 6 documented app composes, found {}",
            examples.len()
        );

        for (name, yaml) in examples {
            let c = Compose::parse(&yaml).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
            c.validate()
                .unwrap_or_else(|e| panic!("{name}: validate: {e}"));
            let fp = c
                .footprint()
                .unwrap_or_else(|e| panic!("{name}: footprint: {e}"));
            assert!(
                fp.cpu_milli > 0 && fp.memory_bytes > 0,
                "{name}: empty footprint"
            );

            // Resolve every referenced var: generated secrets + config (its
            // default, or a placeholder for required fields) + HOSTNAME.
            let id = 1u64;
            let generated = ensure_secrets(&c, &BTreeMap::new()).unwrap();
            let config: BTreeMap<String, String> = c
                .config
                .iter()
                .map(|f| {
                    (
                        f.name.clone(),
                        f.default.clone().unwrap_or_else(|| "test".to_string()),
                    )
                })
                .collect();
            let host = deployment_hostname("inst", "apps.example.com");
            let vars = build_vars(&generated, &config, &host);
            let env = c
                .resolve_env(&vars)
                .unwrap_or_else(|e| panic!("{name}: resolve_env: {e}"));
            let files = c
                .resolve_files(&vars)
                .unwrap_or_else(|e| panic!("{name}: resolve_files: {e}"));

            // Every service renders a Deployment with its image; ported services
            // render a Service; declared volumes render PVCs; resolved files stay
            // free of unresolved `${…}`.
            for (sname, svc) in &c.services {
                let senv: BTreeMap<String, String> = env[sname].clone().into_iter().collect();
                let sfiles = files[sname].clone();
                for f in &sfiles {
                    assert!(
                        !f.content.contains("${"),
                        "{name}/{sname}: unresolved var in {}",
                        f.path
                    );
                }
                let dep = build_deployment(id, sname, svc, &senv, &sfiles, 1);
                let image = dep.spec.unwrap().template.spec.unwrap().containers[0]
                    .image
                    .clone();
                assert_eq!(image.as_deref(), Some(svc.image.as_str()));
                assert_eq!(
                    build_service(id, sname, svc).is_some(),
                    !svc.ports.is_empty(),
                    "{name}/{sname}: service presence tracks declared ports"
                );
                for v in &svc.volumes {
                    assert!(build_pvc(id, sname, &v.name, &v.size).spec.is_some());
                }
                let _ = build_files_configmap(id, sname, &sfiles);
                let _ = build_secret(id, sname, &BTreeMap::new(), &sfiles);
            }

            // Each documented app exposes an ingress endpoint.
            assert!(
                build_ingress(id, &c, &host, None, "letsencrypt-prod", "nginx").is_some(),
                "{name}: expected an ingress endpoint"
            );
            // Shared namespace objects render from the footprint.
            let _ = build_network_policy(id, "ingress-nginx");
        }
    }

    // ── billing gate (reconcile_one) ────────────────────────────────────────

    use lnvps_db::{IntervalType, Subscription};

    fn sub(is_setup: bool, expires: Option<chrono::DateTime<chrono::Utc>>) -> Subscription {
        Subscription {
            id: 1,
            user_id: 1,
            company_id: 1,
            name: "s".to_string(),
            description: None,
            created: chrono::Utc::now(),
            expires,
            is_active: true,
            is_setup,
            currency: "USD".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: true,
            external_id: None,
        }
    }

    /// A paid, unexpired, desired-running deployment runs.
    #[test]
    fn gate_paid_and_running() {
        let s = sub(true, Some(chrono::Utc::now() + chrono::Duration::days(30)));
        assert_eq!(
            gate_running(true, false, Some(&s), None, chrono::Utc::now()),
            GateReason::Running
        );
    }

    /// Regression: a *lookup fault* (DB error / decryption failure) must NOT be
    /// silently treated as "unpaid". It surfaces as a distinct, loud reason so
    /// a paid deployment doesn't sit at 0 replicas with an empty status message.
    #[test]
    fn gate_lookup_error_is_not_unpaid() {
        let now = chrono::Utc::now();
        let err = Some("Encryption context not initialized".to_string());
        assert_eq!(
            gate_running(true, false, None, err, now),
            GateReason::SubscriptionLookupFailed(
                "Encryption context not initialized".to_string()
            )
        );
        // ...and it is NOT the calm Unpaid reason.
        assert_ne!(
            gate_running(true, false, None, Some("x".to_string()), now),
            GateReason::Unpaid
        );
    }

    /// A freshly-ordered deployment whose subscription isn't set up yet stays
    /// at 0 replicas with the Unpaid reason.
    #[test]
    fn gate_unpaid_when_not_setup() {
        let s = sub(false, None);
        assert_eq!(
            gate_running(true, false, Some(&s), None, chrono::Utc::now()),
            GateReason::Unpaid
        );
        // No subscription row at all (lookup succeeded, nothing found) → Unpaid.
        assert_eq!(
            gate_running(true, false, None, None, chrono::Utc::now()),
            GateReason::Unpaid
        );
    }

    /// A paid but expired subscription scales to 0 (data retained).
    #[test]
    fn gate_expired_when_past_expiry() {
        let s = sub(true, Some(chrono::Utc::now() - chrono::Duration::hours(1)));
        assert_eq!(
            gate_running(true, false, Some(&s), None, chrono::Utc::now()),
            GateReason::Expired
        );
    }

    /// Desired-stopped (or deleted) always wins, regardless of billing.
    #[test]
    fn gate_stopped_by_user() {
        let s = sub(true, Some(chrono::Utc::now() + chrono::Duration::days(30)));
        assert_eq!(
            gate_running(false, false, Some(&s), None, chrono::Utc::now()),
            GateReason::StoppedByUser
        );
        assert_eq!(
            gate_running(true, true, Some(&s), None, chrono::Utc::now()),
            GateReason::StoppedByUser
        );
    }

    /// The customer-facing messages for each gate reason (also exercises the
    /// Display impl that status write-back relies on).
    #[test]
    fn gate_reason_messages() {
        assert_eq!(GateReason::Running.to_string(), "running");
        assert_eq!(
            GateReason::StoppedByUser.to_string(),
            "deployment stopped by user"
        );
        assert_eq!(
            GateReason::Unpaid.to_string(),
            "subscription not yet paid"
        );
        assert_eq!(
            GateReason::Expired.to_string(),
            "subscription expired (data retained)"
        );
        assert_eq!(
            GateReason::SubscriptionLookupFailed("boom".to_string()).to_string(),
            "subscription lookup failed: boom"
        );
    }
}
