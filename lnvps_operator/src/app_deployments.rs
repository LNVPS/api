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
use lnvps_db::{AppDeployment, AppDeploymentStatus, BillingState, EncryptedString, Subscription};

use crate::Context;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, Namespace, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, Pod, PodSecurityContext, PodSpec, PodTemplateSpec, ResourceQuota,
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
use lnvps_compose::{
    Compose, Expose, ROOT_ENTRYPOINT_CAPABILITIES, ResolvedFile, ResolvedInit,
    Service as ComposeService,
};

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
/// (no privilege escalation, read-only root fs, `drop: ALL` plus only
/// [`ROOT_ENTRYPOINT_CAPABILITIES`]) still applies.
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

/// Scale a Kubernetes CPU quantity by a deployment's resource multiplier,
/// e.g. `("500m", 2) -> "1000m"`.
///
/// A multiplier of 1 returns the value untouched so base-size deployments keep
/// rendering byte-identical specs. An unparseable value is also returned as-is:
/// compose resources are validated when the catalog app is admitted, so this is
/// unreachable in practice, and silently keeping the base size is safer than
/// failing a reconcile.
fn scale_cpu(cpu: &str, multiplier: u32) -> String {
    if multiplier <= 1 {
        return cpu.to_string();
    }
    match lnvps_compose::parse_cpu_milli(cpu) {
        Ok(m) => format!("{}m", m * multiplier as u64),
        Err(_) => cpu.to_string(),
    }
}

/// Scale a Kubernetes byte quantity (memory or storage) by a deployment's
/// resource multiplier, e.g. `("1Gi", 2) -> "2147483648"`. Same passthrough
/// rules as [`scale_cpu`].
fn scale_bytes(value: &str, multiplier: u32) -> String {
    if multiplier <= 1 {
        return value.to_string();
    }
    match lnvps_compose::parse_bytes(value) {
        Ok(b) => (b * multiplier as u64).to_string(),
        Err(_) => value.to_string(),
    }
}

/// Container requests == limits (Guaranteed QoS, 1:1 — no overcommit) from a
/// compose service's `resources`, scaled by the deployment's resource
/// multiplier (1 = the catalog app's base size).
fn build_resource_requirements(
    r: &lnvps_compose::Resources,
    multiplier: u32,
) -> ResourceRequirements {
    let map = BTreeMap::from([
        ("cpu".to_string(), Quantity(scale_cpu(&r.cpu, multiplier))),
        (
            "memory".to_string(),
            Quantity(scale_bytes(&r.memory, multiplier)),
        ),
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
///
/// `fs_group` is set when the service declares a numeric `user:`, so the
/// kubelet chowns mounted volumes to that group. Without it a freshly
/// provisioned PVC is root-owned `0755` and a non-root process cannot write to
/// it — the app starts and then fails on its first write.
fn pod_security_context_for(fs_group: Option<i64>) -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: Some(true),
        fs_group,
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
///
/// A root service additionally gets [`ROOT_ENTRYPOINT_CAPABILITIES`] added back
/// on top of `drop: ALL`. Without them `user: root` is a trap: the container
/// starts as uid 0 with an empty capability set, so the entrypoint's first
/// privileged step — dropping to its own service account, then chowning the
/// data directory — fails with `EPERM` and the platform bug reads as an app
/// bug. Non-root services keep `drop: ALL` with nothing added, which is what
/// the restricted PSS requires.
///
/// This is necessary but not sufficient for a database service: the read-only
/// root filesystem then denies it a writable `/tmp` and runtime directory
/// (#264).
///
/// `run_as_user` is set from a numeric compose `user:`. It is required for
/// images whose Dockerfile `USER` is a name (e.g. `USER nonroot`): the kubelet
/// verifies `runAsNonRoot` against the image config and cannot resolve a name,
/// so without an explicit UID the container is refused with "image has
/// non-numeric user ... cannot verify user is non-root".
fn container_security_context_for(
    run_as_non_root: bool,
    run_as_user: Option<i64>,
) -> SecurityContext {
    use k8s_openapi::api::core::v1::Capabilities;
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(run_as_non_root),
        run_as_user,
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            add: if run_as_non_root {
                None
            } else {
                Some(
                    ROOT_ENTRYPOINT_CAPABILITIES
                        .iter()
                        .map(|c| c.to_string())
                        .collect(),
                )
            },
        }),
        ..Default::default()
    }
}

/// Writable scratch space every init step gets, since the root filesystem is
/// read-only like every other container's. Tools that insist on a config or
/// cache dir (`mc`, `psql`, `git`) work by pointing `HOME` at it.
const INIT_TMP_DIR: &str = "/tmp";
const INIT_TMP_VOLUME: &str = "init-tmp";

/// Pod-local name for a `scratch:` path's `emptyDir` (#264).
///
/// The declaration index makes it unique — slugging the path alone does not,
/// since `/run/mysqld` and `/run-mysqld` are different paths compose accepts
/// and would slug the same, and two volumes sharing a name is an invalid pod
/// spec. The slug is carried anyway so `kubectl describe` reads as
/// `scratch-0-run-mysqld` rather than `scratch-0`, truncated to keep the whole
/// name inside the 63-character DNS-1123 label limit.
fn scratch_volume_name(index: usize, path: &str) -> String {
    let slug: String = path
        .trim_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    // A DNS-1123 label must start and end alphanumeric, so a path that slugs to
    // nothing usable (`/-`) falls back to the index alone.
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        format!("scratch-{index}")
    } else {
        format!("scratch-{index}-{slug}")
    }
}

/// A compose `init:` step as a Kubernetes init container (#244).
///
/// The kubelet runs these to completion, in declaration order, before the
/// service's own container starts, and restarts a failed one — which is the
/// gate: a service whose setup step has not succeeded never runs. It sees
/// exactly what the service container sees (`mounts`: the service's volumes,
/// scratch paths and config files), plus a writable [`INIT_TMP_DIR`], and is
/// hardened the same way.
///
/// A service that declares `scratch:` at `/tmp` already supplies that mount, so
/// the step's own is skipped: two volumeMounts at one path is an invalid pod
/// spec, and the service's declaration is the one the author asked for.
///
/// Resources are taken as declared, unscaled by the deployment's size
/// multiplier: a setup step does fixed work, and a pod reserves
/// `max(largest init container, sum of containers)`, so an unscaled step can
/// only ever cost less than the scaled service it precedes.
pub fn build_init_container(init: &ResolvedInit, mounts: &[VolumeMount]) -> Container {
    let mut mounts = mounts.to_vec();
    if !mounts.iter().any(|m| m.mount_path == INIT_TMP_DIR) {
        mounts.push(VolumeMount {
            name: INIT_TMP_VOLUME.to_string(),
            mount_path: INIT_TMP_DIR.to_string(),
            ..Default::default()
        });
    }

    Container {
        name: init.name.clone(),
        image: Some(init.image.clone()),
        command: init.command.clone(),
        args: init.args.clone(),
        env: Some(
            init.env
                .iter()
                .map(|(k, v)| EnvVar {
                    name: k.clone(),
                    value: Some(v.clone()),
                    ..Default::default()
                })
                .collect(),
        ),
        volume_mounts: Some(mounts),
        security_context: Some(container_security_context_for(
            !init.runs_as_root(),
            init.run_as_user(),
        )),
        resources: Some(build_resource_requirements(&init.resources, 1)),
        ..Default::default()
    }
}

/// A PVC for a compose `volume`.
pub fn build_pvc(
    deployment_id: u64,
    service: &str,
    name: &str,
    size: &str,
    multiplier: u32,
) -> PersistentVolumeClaim {
    let requests = BTreeMap::from([(
        "storage".to_string(),
        Quantity(scale_bytes(size, multiplier)),
    )]);
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
///
/// `multiplier` scales the container's CPU/memory limits (1 = base app size).
// Eight positional arguments, all of them the caller's own state: bundling them
// into a struct would only move the same list one line up, so the lint is
// suppressed rather than worked around.
#[allow(clippy::too_many_arguments)]
pub fn build_deployment(
    deployment_id: u64,
    service_name: &str,
    svc: &ComposeService,
    env: &BTreeMap<String, String>,
    files: &[ResolvedFile],
    replicas: i32,
    multiplier: u32,
    init: &[ResolvedInit],
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

    // Scratch paths (#264): writable, node-local, discarded with the pod. The
    // root filesystem is read-only, so an image that needs a runtime directory
    // it does not persist — mariadb's `/run/mysqld`, postgres' socket dir,
    // InnoDB's `/tmp` — has nowhere to write without one of these, and exits on
    // startup. `sizeLimit` is what stops one tenant's scratch filling the node
    // it shares: the kubelet evicts the pod that exceeds it.
    for (i, s) in svc.scratch.iter().enumerate() {
        let vol_name = scratch_volume_name(i, &s.path);
        volumes.push(K8sVolume {
            name: vol_name.clone(),
            empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource {
                size_limit: Some(Quantity(s.size_or_default().to_string())),
                ..Default::default()
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: vol_name,
            mount_path: s.path.clone(),
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

    // Setup steps run before this service's container, seeing the same mounts
    // plus a writable scratch dir — every root filesystem here is read-only.
    let init_containers: Vec<Container> = init
        .iter()
        .map(|i| build_init_container(i, &mounts))
        .collect();
    // ...unless the service declares its own `scratch:` at that path, in which
    // case the steps mount that instead and this volume would go unreferenced.
    let init_tmp_referenced = init_containers.iter().any(|c| {
        c.volume_mounts
            .as_ref()
            .is_some_and(|m| m.iter().any(|m| m.name == INIT_TMP_VOLUME))
    });
    if init_tmp_referenced {
        volumes.push(K8sVolume {
            name: INIT_TMP_VOLUME.to_string(),
            empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource::default()),
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
        security_context: Some(container_security_context_for(
            !svc.runs_as_root(),
            svc.run_as_user(),
        )),
        resources: Some(build_resource_requirements(&svc.resources, multiplier)),
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
                    init_containers: if init_containers.is_empty() {
                        None
                    } else {
                        Some(init_containers)
                    },
                    volumes: if volumes.is_empty() {
                        None
                    } else {
                        Some(volumes)
                    },
                    security_context: Some(pod_security_context_for(svc.run_as_user())),
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
    compose: &Compose,
    generated: &BTreeMap<String, String>,
    config: &BTreeMap<String, String>,
    hostname: &str,
) -> std::collections::HashMap<String, String> {
    let mut vars = std::collections::HashMap::new();
    // Declared defaults first, so a config field added to the catalog app after
    // this deployment was created resolves to its default instead of an empty
    // string. The deployment's stored config then overrides them.
    for (k, v) in compose.config_defaults() {
        vars.insert(k, v);
    }
    for (k, v) in generated {
        vars.insert(k.clone(), v.clone());
    }
    for (k, v) in config {
        vars.insert(k.clone(), v.clone());
    }
    vars.insert("HOSTNAME".to_string(), hostname.to_string());

    // Anything still unset substitutes empty (see lnvps_compose::substitute).
    // That keeps a running deployment running, but is worth surfacing: it means
    // a required field has no value and no default.
    let missing: Vec<String> = compose
        .referenced_vars()
        .into_iter()
        .filter(|n| !vars.contains_key(n))
        .collect();
    if !missing.is_empty() {
        warn!(
            "compose references {} with no value or default; substituting empty",
            missing.join(", ")
        );
    }
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
        // Only missing secrets are generated, so an existing deployment keeps
        // its stored value even if the declaration's length changes later.
        out.entry(s.name.clone())
            .or_insert_with(|| generate_secret_value(s.byte_len()));
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
    // The billing verdict itself comes from the shared derivation on the model,
    // which the customer API also reports as `billing_state` (#253). One rule,
    // so a deployment cannot be told it is unpaid while the operator runs it.
    match sub.billing_state(now) {
        BillingState::Unpaid => GateReason::Unpaid,
        BillingState::Expired => GateReason::Expired,
        BillingState::Active => GateReason::Running,
    }
}

/// Whether a deployment in this gate state gets Kubernetes objects at all
/// (issue #252).
///
/// Everything except a never-paid deployment does. In particular:
///
/// - [`GateReason::Expired`] **must** keep its objects. It was paid for once,
///   so its PVCs hold customer data that is deliberately retained at 0 replicas
///   until real deletion.
/// - [`GateReason::StoppedByUser`] likewise — the customer asked for it to
///   stop, not to be destroyed.
/// - [`GateReason::SubscriptionLookupFailed`] is an operational fault, not a
///   billing verdict. Tearing down (or refusing to maintain) a deployment
///   because the database blinked would turn a transient error into data loss.
///
/// Only [`GateReason::Unpaid`] — `is_setup = 0`, never paid — gets nothing.
/// Extracted as a pure function so the rule is unit-testable without a cluster.
pub fn provisions_cluster_objects(gate: &GateReason) -> bool {
    !matches!(gate, GateReason::Unpaid)
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

    // Billing gate + retention, decided *before* anything is created in the
    // cluster. The workload only runs when the subscription is set up (paid at
    // least once) and not expired.
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
    let desired_running = deployment.desired_state == lnvps_db::AppDeploymentDesiredState::Running;
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

    // A deployment that has never been paid for gets *nothing* in the cluster
    // (issue #252). Payment used to gate the replica count alone, so an unpaid
    // order still created its namespace, its generated secrets, its PVCs at
    // full size × multiplier, and — worst — an Ingress with a real
    // `letsencrypt-prod` issuer. Certificates are rate-limited per registered
    // domain, so free orders could exhaust the quota for the apps domain and
    // deny certificates to customers who had paid.
    //
    // Only the never-paid case returns here. `Expired` must keep falling
    // through: it was paid once, so its PVCs hold customer data and are
    // deliberately retained at 0 replicas until real deletion (see the
    // retention note further down).
    if !provisions_cluster_objects(&gate) {
        info!("app deployment {id} not provisioned: {gate}");
        // Nothing was applied, so there is no workload to read.
        write_back_status(ctx, deployment, hostname, &gate, None).await?;
        return Ok(());
    }

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
    let vars = build_vars(&compose, &generated, &config, &hostname);
    let env = compose.resolve_env(&vars)?;
    let files = compose.resolve_files(&vars)?;
    let init = compose.resolve_init(&vars)?;

    // An expired deployment scales to 0 but keeps its PVCs (customer data);
    // only real deletion tears it down.
    let replicas = if gate == GateReason::Running { 1 } else { 0 };
    // Size of this deployment as a multiple of the catalog app's footprint.
    // Legacy rows (pre-multiplier) decode as 0, so clamp to the base size.
    let multiplier = deployment.resource_multiplier.max(1);

    // 4. Per service: PVCs, file ConfigMap/Secret, Service, Deployment.
    for (sname, svc) in &compose.services {
        for v in &svc.volumes {
            apply(client, &build_pvc(id, sname, &v.name, &v.size, multiplier)).await?;
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
            &build_deployment(
                id,
                sname,
                svc,
                &svc_env,
                &sfiles,
                replicas,
                multiplier,
                init.get(sname).map(Vec::as_slice).unwrap_or_default(),
            ),
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
    // Nothing here scales with `multiplier`: the deployment's size is enforced
    // by the per-container limits and PVC sizes written above, not by a
    // namespace cap.
    delete_resource_quota(client, id).await?;

    // 7. Status write-back: record the hostname and what the workload is
    // actually doing (#276).
    //
    // A failed read is not a failed reconcile: the objects are applied and
    // correct, and the API server being briefly unavailable must not undo that
    // or overwrite a true status with a guess.
    let health = match read_workload_health(client, id).await {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("app deployment {id}: could not read workload health: {e}");
            None
        }
    };
    write_back_status(ctx, deployment, hostname, &gate, health).await?;
    info!("reconciled app deployment {id}");
    Ok(())
}

/// What the cluster says about a deployment's workload (issue #276).
///
/// Collected from the Deployments and Pods in the deployment's namespace, and
/// mapped to a status by [`workload_status`]. Kept as data so the mapping is a
/// pure function, testable without a cluster — like [`gate_running`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorkloadHealth {
    /// Replicas asked for, summed across the deployment's services.
    pub desired: i32,
    /// Replicas the cluster reports as ready.
    pub ready: i32,
    /// Containers the kubelet says will not start.
    pub failures: Vec<ContainerFailure>,
}

/// One container the kubelet is refusing to run, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerFailure {
    /// Compose service the container belongs to.
    pub service: String,
    /// The kubelet's waiting reason, e.g. `CrashLoopBackOff`.
    pub reason: String,
    /// The last termination message, when the container ran and died.
    pub detail: Option<String>,
}

/// Waiting reasons that mean "this will not start on its own".
///
/// `CrashLoopBackOff` only appears after the kubelet has restarted a container
/// repeatedly, so it is a settled verdict rather than a container that is
/// merely slow — which is why a not-yet-ready workload without one of these is
/// reported as `Pending` and not as an error.
const TERMINAL_WAITING_REASONS: [&str; 5] = [
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "CreateContainerConfigError",
    "CreateContainerError",
];

/// Map observed workload health onto the status the customer sees (issue #276).
///
/// `Running` used to mean "the billing gate is open": it was written whenever
/// the subscription was paid and the customer had not stopped the deployment,
/// and nothing ever read the workload back. A database that aborted while
/// initialising its data directory reported `Running` throughout, in the admin
/// UI and on the customer's own page, for as long as it kept crashing.
///
/// So `Running` now requires every replica to be ready. A container the kubelet
/// has given up on is `Error` with the reason (and its last words) in
/// `status_message`; anything else that is not yet ready is `Pending`, which is
/// what a deployment coming up honestly is.
pub fn workload_status(health: &WorkloadHealth) -> (AppDeploymentStatus, Option<String>) {
    if !health.failures.is_empty() {
        let detail = health
            .failures
            .iter()
            .map(|f| {
                let mut line = format!("{}: {}", f.service, f.reason);
                if let Some(d) = &f.detail {
                    // The last termination message is the app's own output and
                    // can be long; it is the most useful part, so keep the head
                    // of it rather than dropping it.
                    let d = d.trim();
                    if !d.is_empty() {
                        let head: String = d.chars().take(200).collect();
                        line.push_str(&format!(" ({head})"));
                    }
                }
                line
            })
            .collect::<Vec<_>>()
            .join("; ");
        return (AppDeploymentStatus::Error, Some(detail));
    }
    if health.desired > 0 && health.ready >= health.desired {
        return (AppDeploymentStatus::Running, None);
    }
    (
        AppDeploymentStatus::Pending,
        Some(format!(
            "waiting for the workload to become ready ({}/{} replicas)",
            health.ready, health.desired
        )),
    )
}

/// Read the workload's health back out of the cluster (issue #276).
///
/// Deployments give the ready/desired counts; pods give the reason a container
/// is not starting, which is the part a customer can act on ("no such image",
/// "the database aborted") and which the replica count alone cannot say.
async fn read_workload_health(client: &Client, deployment_id: u64) -> Result<WorkloadHealth> {
    let ns = namespace_name(deployment_id);
    let mut health = WorkloadHealth::default();

    let deps: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    for d in deps.list(&ListParams::default()).await?.items {
        health.desired += d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
        health.ready += d
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), &ns);
    for p in pods.list(&ListParams::default()).await?.items {
        health.failures.extend(pod_failures(&p));
    }
    Ok(health)
}

/// The terminal container failures a single pod reports, if any.
///
/// Pure so the reason filter and the service-name fallback are testable without
/// a cluster.
fn pod_failures(pod: &Pod) -> Vec<ContainerFailure> {
    // The compose service name is on the pod as the component label, which
    // is what the customer recognises — the pod name is generated.
    let service = pod
        .labels()
        .get("app.kubernetes.io/component")
        .cloned()
        .unwrap_or_else(|| pod.name_any());
    let Some(status) = &pod.status else {
        return vec![];
    };
    let statuses = status
        .container_statuses
        .iter()
        .flatten()
        .chain(status.init_container_statuses.iter().flatten());
    let mut failures = vec![];
    for cs in statuses {
        let Some(waiting) = cs.state.as_ref().and_then(|s| s.waiting.as_ref()) else {
            continue;
        };
        let Some(reason) = waiting.reason.as_deref() else {
            continue;
        };
        if !TERMINAL_WAITING_REASONS.contains(&reason) {
            continue;
        }
        failures.push(ContainerFailure {
            service: service.clone(),
            reason: reason.to_string(),
            detail: cs
                .last_state
                .as_ref()
                .and_then(|s| s.terminated.as_ref())
                .and_then(|t| t.message.clone())
                .or_else(|| waiting.message.clone()),
        });
    }
    failures
}

/// Record the deployment's hostname and why it is (not) running.
///
/// When the workload isn't running, surface *why*, so a paid-intended
/// deployment never sits at 0 replicas with no explanation (previously a silent
/// `stopped`). Shared by the normal end-of-reconcile path and the unpaid early
/// return, so an unpaid order still gets its hostname and a reason the customer
/// can act on — it just gets no cluster objects.
async fn write_back_status(
    ctx: &Context,
    deployment: &AppDeployment,
    hostname: String,
    gate: &GateReason,
    health: Option<WorkloadHealth>,
) -> Result<()> {
    let id = deployment.id;
    let mut updated = deployment.clone();
    updated.hostname = Some(hostname);
    match gate {
        GateReason::Running => match health {
            // The gate being open only says the customer has paid and wants it
            // running. What it *is* doing comes from the cluster (#276).
            Some(h) => {
                let (status, message) = workload_status(&h);
                if status != AppDeploymentStatus::Running {
                    info!(
                        "app deployment {id} is {status}: {}",
                        message.as_deref().unwrap_or("")
                    );
                }
                updated.status = status;
                updated.status_message = message;
            }
            // Health could not be read (see the call site). Asserting anything
            // here would be a guess: leave the stored status alone rather than
            // reporting a state nobody observed.
            None => {
                warn!("app deployment {id}: workload health unknown, leaving status as-is");
            }
        },
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

    /// A `user: root` service omits runAsNonRoot on its container and gets the
    /// root-entrypoint capabilities back on top of `drop: ALL` (#263); a normal
    /// service keeps runAsNonRoot and adds nothing (default-deny hardening).
    #[test]
    fn root_service_omits_run_as_non_root() {
        let root =
            Compose::parse("services:\n  db:\n    image: mariadb:11\n    user: root\n").unwrap();
        let d = build_deployment(
            7,
            "db",
            &root.services["db"],
            &BTreeMap::new(),
            &[],
            1,
            1,
            &[],
        );
        let ctr = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let sc = ctr.security_context.as_ref().unwrap();
        assert_eq!(sc.run_as_non_root, Some(false));
        // The rest of the lockdown still applies.
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        let caps = sc.capabilities.as_ref().unwrap();
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
        // Dropped to nothing, then handed back exactly the five a
        // start-as-root-and-drop entrypoint needs — no more (#263).
        assert_eq!(
            caps.add,
            Some(
                ROOT_ENTRYPOINT_CAPABILITIES
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
            )
        );

        // Default (no user:) stays runAsNonRoot with nothing added back.
        let plain = Compose::parse("services:\n  app:\n    image: x\n").unwrap();
        let d = build_deployment(
            7,
            "app",
            &plain.services["app"],
            &BTreeMap::new(),
            &[],
            1,
            1,
            &[],
        );
        let ctr = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let sc = ctr.security_context.as_ref().unwrap();
        assert_eq!(sc.run_as_non_root, Some(true));
        let caps = sc.capabilities.as_ref().unwrap();
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
        assert_eq!(caps.add, None);
    }

    /// The same branch applies to `init:` steps, which share
    /// [`container_security_context_for`]: a root init step that chowns a
    /// volume before the service starts needs the same capabilities, and a
    /// non-root one must not get them (#263).
    #[test]
    fn root_init_step_gets_capabilities() {
        let c = Compose::parse(
            "services:\n  db:\n    image: mariadb:11\n    user: root\n    volumes:\n      - { name: data, path: /var/lib/mysql, size: 1Gi }\n    init:\n      - name: fix-perms\n        image: busybox\n        user: root\n        command: [\"chown\", \"-R\", \"999:999\", \"/var/lib/mysql\"]\n      - name: check\n        image: busybox\n        user: \"1000\"\n        command: [\"true\"]\n",
        )
        .unwrap();
        let init = c.resolve_init(&std::collections::HashMap::new()).unwrap();
        let steps = &init["db"];
        assert_eq!(steps.len(), 2);

        let root = build_init_container(&steps[0], &[]);
        let caps = root
            .security_context
            .as_ref()
            .unwrap()
            .capabilities
            .clone()
            .unwrap();
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
        for cap in ROOT_ENTRYPOINT_CAPABILITIES {
            assert!(caps.add.as_ref().unwrap().iter().any(|c| c == cap));
        }

        let nonroot = build_init_container(&steps[1], &[]);
        let caps = nonroot
            .security_context
            .as_ref()
            .unwrap()
            .capabilities
            .clone()
            .unwrap();
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
        assert_eq!(caps.add, None);
    }

    /// Regression: an image whose Dockerfile `USER` is a *name* (e.g. haven's
    /// `USER nonroot`) is refused by the kubelet under `runAsNonRoot` with
    /// "image has non-numeric user (nonroot), cannot verify user is non-root",
    /// because the kubelet reads the image config and cannot resolve a name.
    /// A numeric compose `user:` supplies `runAsUser` so the check passes, and
    /// the same value becomes `fsGroup` so mounted PVCs are writable (a fresh
    /// PVC is root-owned `0755`).
    #[test]
    fn numeric_user_sets_run_as_user_and_fs_group() {
        let c = Compose::parse(
            "services:\n  haven:\n    image: x\n    user: \"1000\"\n    volumes:\n      - { name: db, path: /app/db, size: 10Gi }\n",
        )
        .unwrap();
        let d = build_deployment(
            7,
            "haven",
            &c.services["haven"],
            &BTreeMap::new(),
            &[],
            1,
            1,
            &[],
        );
        let pod = d.spec.unwrap().template.spec.unwrap();

        let ctr = &pod.containers[0];
        let sc = ctr.security_context.as_ref().unwrap();
        assert_eq!(sc.run_as_user, Some(1000));
        assert_eq!(sc.run_as_non_root, Some(true), "still non-root hardened");

        let psc = pod.security_context.as_ref().unwrap();
        assert_eq!(
            psc.fs_group,
            Some(1000),
            "volumes must be chowned to the run-as user"
        );

        // Services without a numeric user keep the previous behaviour: no
        // runAsUser, no fsGroup (their image's USER is already numeric).
        let plain = Compose::parse("services:\n  app:\n    image: x\n").unwrap();
        let d = build_deployment(
            7,
            "app",
            &plain.services["app"],
            &BTreeMap::new(),
            &[],
            1,
            1,
            &[],
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert_eq!(
            pod.containers[0]
                .security_context
                .as_ref()
                .unwrap()
                .run_as_user,
            None
        );
        assert_eq!(pod.security_context.as_ref().unwrap().fs_group, None);
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
    fn multiplier_scales_cpu_memory_and_storage() {
        // A resource multiplier of N runs the app at N times its base size:
        // every container's CPU/memory limits and every PVC scale together.
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    resources: { cpu: \"500m\", memory: 1Gi }\n",
        )
        .unwrap();
        let d = build_deployment(7, "a", &c.services["a"], &BTreeMap::new(), &[], 1, 3, &[]);
        let ctr = &d.spec.unwrap().template.spec.unwrap().containers[0];
        let limits = ctr.resources.as_ref().unwrap().limits.as_ref().unwrap();
        assert_eq!(limits.get("cpu").unwrap().0, "1500m");
        assert_eq!(
            limits.get("memory").unwrap().0,
            (3u64 * 1024 * 1024 * 1024).to_string()
        );

        let pvc = build_pvc(7, "a", "data", "10Gi", 3);
        assert_eq!(
            pvc.spec
                .unwrap()
                .resources
                .unwrap()
                .requests
                .unwrap()
                .get("storage")
                .unwrap()
                .0,
            (30u64 * 1024 * 1024 * 1024).to_string()
        );
    }

    #[test]
    fn multiplier_of_one_leaves_quantities_untouched() {
        // Base-size deployments must render byte-identical specs, so upgrading
        // the operator does not churn every existing deployment.
        assert_eq!(scale_cpu("500m", 1), "500m");
        assert_eq!(scale_bytes("1Gi", 1), "1Gi");
        // 0 is what a pre-migration row decodes to; treat it as the base size.
        assert_eq!(scale_cpu("500m", 0), "500m");
        assert_eq!(scale_bytes("1Gi", 0), "1Gi");
        // An unparseable quantity is passed through rather than failing the
        // reconcile (compose values are validated at catalog admission).
        assert_eq!(scale_cpu("not-a-cpu", 4), "not-a-cpu");
        assert_eq!(scale_bytes("not-bytes", 4), "not-bytes");
    }

    #[test]
    fn pvc_is_rwo_with_size() {
        let pvc = build_pvc(7, "mariadb", "db", "5Gi", 1);
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
        let d = build_deployment(7, "web", &c.services["web"], &env, &files, 1, 1, &[]);
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
        let d = build_deployment(
            7,
            "web",
            &c.services["web"],
            &BTreeMap::new(),
            &[],
            0,
            1,
            &[],
        );
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
        let hosts: Vec<&str> = rules.iter().filter_map(|r| r.host.as_deref()).collect();
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
        let vars = build_vars(&c, &generated, &config, &host);

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

    /// A service's `init:` steps render as init containers in its own pod, in
    /// declaration order, seeing the same mounts as the service container plus
    /// a writable scratch dir. A service that declares none renders none (#244).
    #[test]
    fn init_steps_render_as_init_containers() {
        let c = lnvps_compose::Compose::parse(
            "services:\n  s3:\n    image: rustfs/rustfs:latest\n    ports:\n      \
             - { name: api, container: 9000 }\n  \
             app:\n    image: example/app:latest\n    depends_on: [s3]\n    \
             user: \"1000\"\n    volumes:\n      \
             - { name: data, path: /data, size: 1Gi }\n    init:\n      \
             - name: wait-s3\n        image: minio/mc:latest\n        \
               command: [\"sh\", \"-c\", \"until mc --quiet ls t; do sleep 2; done\"]\n        \
               env:\n          MC_HOST_t: http://ak:${S3_SECRET}@s3:9000\n          \
               HOME: /tmp\n      \
             - name: make-bucket\n        image: minio/mc:latest\n        \
               args: [\"mb\", \"-p\", \"t/media\"]\n        user: \"65534\"\n\
             secrets:\n  - { name: S3_SECRET, generate: password }\n",
        )
        .unwrap();
        let vars =
            std::collections::HashMap::from([("S3_SECRET".to_string(), "sk123".to_string())]);
        let resolved = c.resolve_init(&vars).unwrap();

        let render = |sname: &str| {
            build_deployment(
                7,
                sname,
                &c.services[sname],
                &BTreeMap::new(),
                &[],
                1,
                1,
                resolved.get(sname).map(Vec::as_slice).unwrap_or_default(),
            )
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
        };

        let app = render("app");
        let inits = app.init_containers.expect("app declares two steps");
        assert_eq!(
            inits.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            vec!["wait-s3", "make-bucket"]
        );

        let wait = &inits[0];
        assert_eq!(wait.image.as_deref(), Some("minio/mc:latest"));
        assert_eq!(wait.command.as_ref().unwrap()[0], "sh");
        // `${…}` in env is substituted; nothing interpolates into argv.
        let host = wait
            .env
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.name == "MC_HOST_t")
            .unwrap()
            .value
            .clone()
            .unwrap();
        assert_eq!(host, "http://ak:sk123@s3:9000");

        // Sees the service's own volume, plus scratch space it can write to
        // under a read-only root filesystem.
        let mounts = wait.volume_mounts.as_ref().unwrap();
        assert!(mounts.iter().any(|m| m.mount_path == "/data"));
        assert!(mounts.iter().any(|m| m.name == INIT_TMP_VOLUME));
        assert!(
            app.volumes
                .as_ref()
                .unwrap()
                .iter()
                .any(|v| v.name == INIT_TMP_VOLUME && v.empty_dir.is_some())
        );

        // Hardened like every other container; the step inherits the service's
        // user unless it names its own.
        let sc = wait.security_context.as_ref().unwrap();
        assert_eq!(sc.run_as_non_root, Some(true));
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        assert_eq!(sc.run_as_user, Some(1000));
        assert_eq!(
            inits[1].security_context.as_ref().unwrap().run_as_user,
            Some(65534)
        );
        assert_eq!(inits[1].args.as_ref().unwrap()[0], "mb");
        assert!(inits[1].command.is_none());

        // A service with no steps renders none.
        assert!(render("s3").init_containers.is_none());
    }

    /// A `scratch:` path renders an `emptyDir` with a `sizeLimit` and a mount
    /// at that path, alongside — not instead of — the service's PVCs (#264).
    /// Without one, a database image has nowhere to write its socket, pid file
    /// or temporary files under the read-only root filesystem, and exits on
    /// startup.
    #[test]
    fn scratch_renders_bounded_empty_dirs() {
        let c = lnvps_compose::Compose::parse(
            "services:\n  db:\n    image: mariadb:11\n    user: \"999\"\n    \
             volumes:\n      - { name: data, path: /var/lib/mysql, size: 5Gi }\n    \
             scratch:\n      - { path: /tmp, size: 512Mi }\n      - { path: /run/mysqld }\n",
        )
        .unwrap();
        let pod = build_deployment(9, "db", &c.services["db"], &BTreeMap::new(), &[], 1, 1, &[])
            .spec
            .unwrap()
            .template
            .spec
            .unwrap();

        let volumes = pod.volumes.as_ref().unwrap();
        let scratch: Vec<_> = volumes
            .iter()
            .filter(|v| v.empty_dir.is_some())
            .map(|v| {
                (
                    v.name.clone(),
                    v.empty_dir.as_ref().unwrap().size_limit.clone(),
                )
            })
            .collect();
        assert_eq!(
            scratch,
            vec![
                ("scratch-0-tmp".to_string(), Some(Quantity("512Mi".into()))),
                (
                    "scratch-1-run-mysqld".to_string(),
                    // Undeclared falls back rather than being unbounded — an
                    // emptyDir with no limit can fill the node it shares.
                    Some(Quantity(lnvps_compose::DEFAULT_SCRATCH_SIZE.into()))
                ),
            ]
        );

        // The data volume is still a PVC, and the scratch mounts sit beside it.
        assert!(
            volumes
                .iter()
                .any(|v| v.name == "db-data" && v.persistent_volume_claim.is_some())
        );
        let mounts = pod.containers[0].volume_mounts.as_ref().unwrap();
        let at = |p: &str| mounts.iter().find(|m| m.mount_path == p).map(|m| &m.name);
        assert_eq!(at("/var/lib/mysql"), Some(&"db-data".to_string()));
        assert_eq!(at("/tmp"), Some(&"scratch-0-tmp".to_string()));
        assert_eq!(at("/run/mysqld"), Some(&"scratch-1-run-mysqld".to_string()));

        // Scratch is not storage: it is node-local and discarded with the pod,
        // so it must not appear in what the customer is sold or billed for.
        let fp = c.footprint().unwrap();
        assert_eq!(fp.storage_bytes, 5 * 1024 * 1024 * 1024);
    }

    /// A service that declares `scratch:` at `/tmp` supplies the init steps'
    /// scratch too — the step must not get a second mount at the same path,
    /// which is an invalid pod spec, and the unused `init-tmp` volume drops out
    /// with it (#264).
    #[test]
    fn service_scratch_at_tmp_replaces_the_init_step_default() {
        let c = lnvps_compose::Compose::parse(
            "services:\n  db:\n    image: mariadb:11\n    user: \"999\"\n    \
             volumes:\n      - { name: data, path: /var/lib/mysql, size: 5Gi }\n    \
             scratch:\n      - { path: /tmp }\n    init:\n      \
             - name: seed\n        image: busybox\n        command: [\"true\"]\n",
        )
        .unwrap();
        let resolved = c.resolve_init(&std::collections::HashMap::new()).unwrap();
        let pod = build_deployment(
            9,
            "db",
            &c.services["db"],
            &BTreeMap::new(),
            &[],
            1,
            1,
            &resolved["db"],
        )
        .spec
        .unwrap()
        .template
        .spec
        .unwrap();

        let step = &pod.init_containers.as_ref().unwrap()[0];
        let mounts = step.volume_mounts.as_ref().unwrap();
        assert_eq!(
            mounts
                .iter()
                .filter(|m| m.mount_path == INIT_TMP_DIR)
                .count(),
            1,
            "two mounts at one path is rejected by the kubelet"
        );
        assert_eq!(
            mounts
                .iter()
                .find(|m| m.mount_path == INIT_TMP_DIR)
                .map(|m| m.name.as_str()),
            Some("scratch-0-tmp"),
            "the step writes into the scratch the service declared"
        );
        // It also sees the service's data volume, as it always did.
        assert!(mounts.iter().any(|m| m.mount_path == "/var/lib/mysql"));
        assert!(
            !pod.volumes
                .as_ref()
                .unwrap()
                .iter()
                .any(|v| v.name == INIT_TMP_VOLUME),
            "the default scratch volume is unreferenced and must not be declared"
        );
    }

    /// A secret declaring `bytes:` is generated at that width, and one that
    /// does not keeps the historical 24 bytes.
    #[test]
    fn ensure_secrets_honours_declared_byte_length() {
        let c = lnvps_compose::Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      K: ${KEY}\n      P: ${PW}\n\
             secrets:\n  - { name: PW, generate: password }\n  \
             - { name: KEY, generate: token, bytes: 32 }\n",
        )
        .unwrap();
        let generated = ensure_secrets(&c, &BTreeMap::new()).unwrap();
        assert_eq!(generated["PW"].len(), 48, "default stays 24 bytes");
        assert_eq!(generated["KEY"].len(), 64, "32 bytes hex-encoded");
        assert!(generated["KEY"].chars().all(|c| c.is_ascii_hexdigit()));

        // A stored value is preserved even if the declared length changed.
        let existing = BTreeMap::from([("KEY".to_string(), "ff".to_string())]);
        let kept = ensure_secrets(&c, &existing).unwrap();
        assert_eq!(kept["KEY"], "ff");
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
        let vars = build_vars(&c, &generated, &BTreeMap::new(), &host);
        let env = c.resolve_env(&vars).unwrap();
        let files = c.resolve_files(&vars).unwrap();
        let to_bt = |m: &std::collections::HashMap<String, String>| -> BTreeMap<String, String> {
            m.clone().into_iter().collect()
        };

        // ── web service (ingress, files: ConfigMap + Secret, env with vars) ──
        let web_env = to_bt(&env["web"]);
        let web_files = files["web"].clone();
        let web = build_deployment(
            id,
            "web",
            &c.services["web"],
            &web_env,
            &web_files,
            1,
            1,
            &[],
        );
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
        let db = build_deployment(
            id,
            "mariadb",
            &c.services["mariadb"],
            &db_env,
            &[],
            1,
            1,
            &[],
        );
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
        let pvc = build_pvc(id, "mariadb", &vol.name, &vol.size, 1);
        assert_eq!(
            pvc.spec.unwrap().resources.unwrap().requests.unwrap()["storage"].0,
            "5Gi"
        );

        // ── lifecycle: stopped ⇒ 0 replicas (data-preserving) ──
        let stopped = build_deployment(
            id,
            "web",
            &c.services["web"],
            &web_env,
            &web_files,
            0,
            1,
            &[],
        );
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
            // The documented composes are what an admin pastes into the API, so
            // they must satisfy the admission-only rule too: every `${...}`
            // declared in config:/secrets: or a builtin. Otherwise we would
            // publish examples the API now rejects.
            c.validate_declarations()
                .unwrap_or_else(|e| panic!("{name}: validate_declarations: {e}"));
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
            let vars = build_vars(&c, &generated, &config, &host);
            let env = c
                .resolve_env(&vars)
                .unwrap_or_else(|e| panic!("{name}: resolve_env: {e}"));
            let files = c
                .resolve_files(&vars)
                .unwrap_or_else(|e| panic!("{name}: resolve_files: {e}"));
            let init = c
                .resolve_init(&vars)
                .unwrap_or_else(|e| panic!("{name}: resolve_init: {e}"));

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
                let dep = build_deployment(
                    id,
                    sname,
                    svc,
                    &senv,
                    &sfiles,
                    1,
                    1,
                    init.get(sname).map(Vec::as_slice).unwrap_or_default(),
                );
                let pod = dep.spec.unwrap().template.spec.unwrap();
                let ctr = &pod.containers[0];
                assert_eq!(ctr.image.as_deref(), Some(svc.image.as_str()));

                // Every documented service must resolve to a user the kubelet
                // will accept (#256). Under the default restricted path the pod
                // asks for `runAsNonRoot` with no `runAsUser`, which leaves the
                // kubelet to read the image's own `USER` — and it refuses both
                // an image that declares none (it would run as root) and one
                // that declares a *name* it cannot resolve to a number. Neither
                // is visible to validation, so three of these examples shipped
                // enabled, priced, and incapable of starting. An example must
                // therefore either opt into root explicitly or name a numeric
                // UID.
                let sc = ctr.security_context.as_ref().expect("security context");
                assert!(
                    svc.runs_as_root() || sc.run_as_user.is_some(),
                    "{name}/{sname}: no `user:` — the kubelet cannot verify the image's \
                     USER, so this pod is refused. Set a numeric uid (check the image with \
                     `docker inspect -f '{{{{.Config.User}}}}'`), or `user: root` if the \
                     entrypoint genuinely needs it"
                );
                // ...and a service that *did* opt into root must get the
                // capabilities a root entrypoint actually needs (#263).
                // `user: root` only satisfies the kubelet; without these the
                // container starts as uid 0 with an empty capability set and
                // dies on its first `chown`, which looks like an app bug.
                if svc.runs_as_root() {
                    let add = sc
                        .capabilities
                        .as_ref()
                        .and_then(|c| c.add.as_ref())
                        .unwrap_or_else(|| {
                            panic!(
                                "{name}/{sname}: `user: root` with no added capabilities — a \
                                 root entrypoint cannot chown its data directory"
                            )
                        });
                    for cap in ROOT_ENTRYPOINT_CAPABILITIES {
                        assert!(
                            add.iter().any(|c| c == cap),
                            "{name}/{sname}: missing {cap}"
                        );
                    }
                }
                if let Some(uid) = sc.run_as_user {
                    // fsGroup follows runAsUser, otherwise a fresh PVC stays
                    // root-owned 0755 and the process cannot write its data.
                    assert_eq!(
                        pod.security_context.as_ref().and_then(|p| p.fs_group),
                        Some(uid),
                        "{name}/{sname}: fsGroup must match runAsUser"
                    );
                }
                // No container may mount two things at one path, and every
                // mount must name a volume the pod declares. The kubelet
                // rejects either, and neither is visible to compose validation
                // — `scratch:` (#264) made both reachable by a catalog edit.
                let declared: std::collections::BTreeSet<&str> = pod
                    .volumes
                    .iter()
                    .flatten()
                    .map(|v| v.name.as_str())
                    .collect();
                for c in std::iter::once(ctr).chain(pod.init_containers.iter().flatten()) {
                    let mut paths = std::collections::BTreeSet::new();
                    for m in c.volume_mounts.iter().flatten() {
                        assert!(
                            paths.insert(m.mount_path.as_str()),
                            "{name}/{sname}: container '{}' mounts '{}' twice",
                            c.name,
                            m.mount_path
                        );
                        assert!(
                            declared.contains(m.name.as_str()),
                            "{name}/{sname}: container '{}' mounts undeclared volume '{}'",
                            c.name,
                            m.name
                        );
                    }
                }
                assert_eq!(
                    build_service(id, sname, svc).is_some(),
                    !svc.ports.is_empty(),
                    "{name}/{sname}: service presence tracks declared ports"
                );
                // ...and every peer this service addresses by name must be one
                // of the services that gets one (#281). The assertion above
                // says the rendering is self-consistent; this one asks whether
                // it is *sufficient*, which is the question the Buzz entry
                // failed in production: `db:5432` in the relay's env, with a
                // `db` that declared no ports and so had no DNS name.
                for (peer, psvc) in &c.services {
                    if peer == sname || !psvc.ports.is_empty() {
                        continue;
                    }
                    for value in senv.values() {
                        assert!(
                            !value.contains(&format!("{peer}:")),
                            "{name}/{sname}: addresses '{peer}:…' but '{peer}' declares no \
                             ports, so no Service and no DNS name is created for it"
                        );
                    }
                }
                for v in &svc.volumes {
                    assert!(build_pvc(id, sname, &v.name, &v.size, 1).spec.is_some());
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

    /// `Running` now means the workload is running, not that the bill is paid
    /// (#276). A crash-looping container reads Error with the reason, a
    /// workload still coming up reads Pending, and only a fully ready one reads
    /// Running.
    #[test]
    fn workload_status_reports_what_the_cluster_says() {
        // Every replica ready: the only case that is Running.
        let (s, m) = workload_status(&WorkloadHealth {
            desired: 2,
            ready: 2,
            failures: vec![],
        });
        assert_eq!(s, AppDeploymentStatus::Running);
        assert_eq!(m, None);

        // Coming up is Pending, not Running — and says how far along it is.
        let (s, m) = workload_status(&WorkloadHealth {
            desired: 2,
            ready: 1,
            failures: vec![],
        });
        assert_eq!(s, AppDeploymentStatus::Pending);
        assert!(m.unwrap().contains("1/2"));

        // A deployment with nothing applied yet is Pending, not Running: a
        // zero/zero "everything I asked for is ready" would be the same lie in
        // a different shape.
        let (s, _) = workload_status(&WorkloadHealth::default());
        assert_eq!(s, AppDeploymentStatus::Pending);

        // The case Kieran hit: a container the kubelet has given up on. Error,
        // naming the service, the reason, and the container's last words.
        let (s, m) = workload_status(&WorkloadHealth {
            desired: 2,
            ready: 1,
            failures: vec![ContainerFailure {
                service: "db".to_string(),
                reason: "CrashLoopBackOff".to_string(),
                detail: Some("InnoDB: Unable to create temporary file\n".to_string()),
            }],
        });
        assert_eq!(s, AppDeploymentStatus::Error);
        let m = m.unwrap();
        assert!(m.contains("db: CrashLoopBackOff"), "{m}");
        assert!(m.contains("InnoDB"), "{m}");

        // A failure outranks a ready count: a two-service app with one service
        // up and one crash-looping is broken, not running.
        let (s, _) = workload_status(&WorkloadHealth {
            desired: 1,
            ready: 1,
            failures: vec![ContainerFailure {
                service: "web".to_string(),
                reason: "ImagePullBackOff".to_string(),
                detail: None,
            }],
        });
        assert_eq!(s, AppDeploymentStatus::Error);

        // A long last-termination message is truncated rather than dropped —
        // the head of it is what names the fault.
        let (_, m) = workload_status(&WorkloadHealth {
            desired: 1,
            ready: 0,
            failures: vec![ContainerFailure {
                service: "db".to_string(),
                reason: "CrashLoopBackOff".to_string(),
                detail: Some("x".repeat(5000)),
            }],
        });
        let m = m.unwrap();
        assert!(m.len() < 400, "message stays renderable: {}", m.len());
    }

    /// A pod is only a failure once the kubelet has settled on one: a container
    /// still being created is not an error the customer can act on.
    #[test]
    fn pod_failures_reports_only_terminal_reasons() {
        use k8s_openapi::api::core::v1::{
            ContainerState, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus,
            PodStatus,
        };

        let waiting = |reason: &str| ContainerState {
            waiting: Some(ContainerStateWaiting {
                reason: Some(reason.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let status = |name: &str, state: ContainerState| ContainerStatus {
            name: name.to_string(),
            state: Some(state),
            ..Default::default()
        };

        let mut crashing = status("db", waiting("CrashLoopBackOff"));
        crashing.last_state = Some(ContainerState {
            terminated: Some(ContainerStateTerminated {
                message: Some("InnoDB: Unable to create temporary file\n".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("db-7f9c8-abcde".to_string()),
                labels: Some(BTreeMap::from([(
                    "app.kubernetes.io/component".to_string(),
                    "db".to_string(),
                )])),
                ..Default::default()
            },
            status: Some(PodStatus {
                container_statuses: Some(vec![
                    status("web", waiting("ContainerCreating")),
                    crashing,
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            pod_failures(&pod),
            vec![ContainerFailure {
                // The component label, not the generated pod name.
                service: "db".to_string(),
                reason: "CrashLoopBackOff".to_string(),
                detail: Some("InnoDB: Unable to create temporary file\n".to_string()),
            }]
        );

        // Without the label there is still a name to show, so a failure is
        // never dropped for want of one.
        let mut unlabelled = pod.clone();
        unlabelled.metadata.labels = None;
        assert_eq!(unlabelled.name_any(), pod_failures(&unlabelled)[0].service);
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

    /// A never-paid deployment gets nothing in the cluster (#252). Payment used
    /// to gate the replica count alone, so an unpaid order still got its
    /// namespace, generated secrets, PVCs at full size × multiplier and an
    /// Ingress with a real `letsencrypt-prod` issuer — certificates are
    /// rate-limited per registered domain, so free orders could deny
    /// certificates to customers who had paid.
    #[test]
    fn unpaid_provisions_nothing() {
        assert!(!provisions_cluster_objects(&GateReason::Unpaid));
    }

    /// Everything that was ever paid for keeps its objects. An expired
    /// deployment's PVCs are customer data retained at 0 replicas; a stopped
    /// one was stopped, not destroyed; and a lookup fault is an operational
    /// error, so treating it as "unpaid" would turn a database blip into data
    /// loss.
    #[test]
    fn only_never_paid_is_withheld() {
        for gate in [
            GateReason::Running,
            GateReason::Expired,
            GateReason::StoppedByUser,
            GateReason::SubscriptionLookupFailed("db down".to_string()),
        ] {
            assert!(
                provisions_cluster_objects(&gate),
                "{gate} must keep its cluster objects"
            );
        }
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
            GateReason::SubscriptionLookupFailed("Encryption context not initialized".to_string())
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
        assert_eq!(GateReason::Unpaid.to_string(), "subscription not yet paid");
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
