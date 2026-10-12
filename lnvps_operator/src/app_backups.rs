//! Capture app-deployment backups as Kubernetes Jobs
//! (`work/app-deployments.md` increment 6).
//!
//! A **run** covers one deployment at one point in time; every compose service
//! that declares a `backup:` method contributes one artifact, and each artifact
//! is one Job and one uploaded object. Two services back up with different
//! images and different volumes, so they cannot share a pod.
//!
//! Scheduling lives here rather than in a Kubernetes `CronJob` because a
//! CronJob fires with nothing to write the run down in and no way to obtain an
//! upload URL that has not expired. The operator evaluates the schedule, mints
//! the row, signs a `PUT` for exactly that object, and hands the Job a URL that
//! is good for one key and one method. A long-lived storage credential in the
//! customer's namespace would be readable by the app's own containers, and a
//! compromised app could then delete the backups that exist to survive it.
//!
//! The object **builders** are pure functions, unit-tested without a cluster;
//! [`reconcile_app_backups`] is the loop that applies them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use chrono::Utc;
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::core::v1::{
    Affinity, Container, EmptyDirVolumeSource, EnvVar, EnvVarSource,
    PersistentVolumeClaimVolumeSource, PodAffinity, PodAffinityTerm, PodSpec, PodTemplateSpec,
    ResourceRequirements, Secret, SecretKeySelector, Volume as K8sVolume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use kube::api::{
    Api, AttachParams, AttachedProcess, DeleteParams, ListParams, Patch, PatchParams,
    PropagationPolicy,
};
use log::{debug, error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use lnvps_api_common::ObjectStore;
use lnvps_api_common::k8s_names::{deployment_namespace as namespace_name, deployment_volume};
use lnvps_compose::{Backup, Compose, Service as ComposeService, parse_bytes};
use lnvps_db::{AppBackupMethod, AppBackupState, AppDeployment, AppDeploymentBackup, LNVpsDb};

use crate::Context;
use crate::app_deployments::{
    GateReason, IMAGE_PULL_POLICY, apply, build_resource_requirements,
    container_security_context_for, gate_running, labels, pod_security_context_for, resolved_env,
    service_labels,
};

/// Where the artifact is staged inside the Job's pod before it is uploaded.
///
/// It is staged rather than streamed because a presigned `PUT` needs a
/// `Content-Length`: piping `tar` straight into `curl` forces chunked transfer
/// encoding, which S3 rejects.
const WORK_DIR: &str = "/work";
const WORK_VOLUME: &str = "work";
const PAYLOAD: &str = "payload";
const UPLOADER_CONTAINER: &str = "upload";
pub const PAYLOAD_READY_ANNOTATION: &str = "lnvps.io/payload-ready";
const POD_WAIT: Duration = Duration::from_secs(300);

/// Where a `volume:` backup mounts the customer's data, always read-only.
const DATA_DIR: &str = "/data";
const DATA_VOLUME: &str = "data";

/// Env var carrying the presigned upload URL into the uploader container.
///
/// It arrives as an env var from a Secret, not as a command-line argument: an
/// argument is visible in `ps` to everything else in the pod.
const UPLOAD_URL_ENV: &str = "LNVPS_UPLOAD_URL";
const UPLOAD_URL_KEY: &str = "url";

/// Image that tars, compresses and uploads. A stock `curl` image, whose busybox
/// userland already provides `tar` and `gzip`, so this increment ships without
/// building and publishing an image of our own.
pub const DEFAULT_UPLOADER_IMAGE: &str = "curlimages/curl:8.11.1";

/// How long a signed upload URL stays valid. Long enough to cover a queued Job
/// and a slow dump of a large volume, short enough that a leaked URL is not a
/// standing grant.
pub const DEFAULT_UPLOAD_URL_HOURS: u64 = 6;

/// How long a backup Job may run before Kubernetes kills it. Kept under the
/// URL's life, so a Job cannot still be running when its upload URL expires and
/// then fail with a signature error that reads as a storage fault.
pub const DEFAULT_JOB_DEADLINE_HOURS: u64 = 5;

/// How many backup Jobs may be in flight per cluster at once.
pub const DEFAULT_MAX_CONCURRENT_BACKUPS: usize = 3;

/// Staging space for a service whose dump size cannot be inferred from its
/// volumes.
const DEFAULT_WORK_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

/// What the uploader is given: `tar`, `gzip` and one HTTP `PUT`, none of which
/// scale with the size of the deployment. Requests equal limits, as every
/// customer container here does, so a backup is not the first thing evicted
/// when the node it was pinned to comes under pressure.
const UPLOADER_CPU: &str = "500m";
const UPLOADER_MEMORY: &str = "256Mi";

/// Kubernetes object name for a backup's Job.
pub fn backup_job_name(backup_id: u64) -> String {
    format!("backup-{backup_id}")
}

/// Kubernetes object name for the Secret holding a backup's upload URL.
pub fn backup_url_secret_name(backup_id: u64) -> String {
    format!("backup-{backup_id}-url")
}

/// Storage key for one artifact.
///
/// Entirely server-derived: the deployment id, the run's UUID and the artifact
/// filename the catalog declared. No part of it comes from a request, so a
/// customer cannot address another customer's object by naming one.
pub fn backup_object_key(deployment_id: u64, run_id: &str, artifact: &str) -> String {
    format!("deployments/{deployment_id}/{run_id}/{artifact}")
}

/// Which of the two capture methods a service's `backup:` selects.
pub fn backup_method(backup: &Backup) -> AppBackupMethod {
    if backup.exec.is_some() {
        AppBackupMethod::Exec
    } else if backup.volume.is_some() {
        AppBackupMethod::Volume
    } else {
        AppBackupMethod::Command
    }
}

/// The Secret carrying one backup's upload URL into its Job.
pub fn build_url_secret(deployment_id: u64, backup_id: u64, url: &str) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(backup_url_secret_name(backup_id)),
            namespace: Some(namespace_name(deployment_id)),
            labels: Some(labels(deployment_id)),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([(
            UPLOAD_URL_KEY.to_string(),
            url.to_string(),
        )])),
        ..Default::default()
    }
}

/// Everything one backup Job needs, gathered by the caller that already has it.
pub struct BackupJobSpec<'a> {
    pub deployment_id: u64,
    pub backup_id: u64,
    pub service_name: &'a str,
    pub service: &'a ComposeService,
    pub backup: &'a Backup,
    /// The service's resolved env, so a dump command can authenticate with the
    /// same generated password the running service uses.
    pub env: &'a BTreeMap<String, String>,
    pub artifact: &'a str,
    pub uploader_image: &'a str,
    /// Size multiplier of the deployment, applied to staging space the same way
    /// it is applied to the volumes being captured.
    pub multiplier: u32,
    pub deadline: Duration,
}

/// The Job that captures one artifact and uploads it.
///
/// A `volume:` backup is one container: tar the read-only mount and upload it.
/// A `command:` backup is two: the dump runs in an init container on the
/// **app's own image** (only that image has `pg_dumpall` or `mariadb-dump`),
/// writing to a shared `emptyDir`, and the uploader — which is the only image
/// here with an HTTP client — compresses and sends it.
pub fn build_backup_job(spec: &BackupJobSpec) -> Result<Job> {
    let mut sel = labels(spec.deployment_id);
    sel.insert("lnvps.io/backup".to_string(), spec.backup_id.to_string());

    let work_size = staging_size(spec.service, spec.multiplier);
    let mut volumes = vec![K8sVolume {
        name: WORK_VOLUME.to_string(),
        empty_dir: Some(EmptyDirVolumeSource {
            size_limit: Some(Quantity(format!("{work_size}"))),
            ..Default::default()
        }),
        ..Default::default()
    }];
    let work_mount = VolumeMount {
        name: WORK_VOLUME.to_string(),
        mount_path: WORK_DIR.to_string(),
        ..Default::default()
    };

    let mut init_containers: Vec<Container> = Vec::new();
    let mut upload_mounts = vec![work_mount.clone()];
    let mut affinity = None;

    let script = match (&spec.backup.command, &spec.backup.volume) {
        _ if spec.backup.exec.is_some() => format!(
            "set -e; while [ ! -e '{WORK_DIR}/{PAYLOAD}' ]; do sleep 1; done; \
             gzip -n '{WORK_DIR}/{PAYLOAD}'; mv '{WORK_DIR}/{PAYLOAD}.gz' '{WORK_DIR}/{artifact}'; \
             curl -fsS --upload-file '{WORK_DIR}/{artifact}' \"${UPLOAD_URL_ENV}\"",
            artifact = spec.artifact
        ),
        (Some(command), _) => {
            if command.is_empty() {
                return Err(anyhow!(
                    "service '{}': backup command is empty",
                    spec.service_name
                ));
            }
            // The dump's payload name is the artifact without our `.gz`.
            let payload = spec.artifact.trim_end_matches(".gz");
            init_containers.push(Container {
                name: "dump".to_string(),
                image: Some(spec.service.image.clone()),
                image_pull_policy: Some(IMAGE_PULL_POLICY.to_string()),
                // The catalog's command is an argv; it is re-quoted into a
                // shell so its stdout can be redirected to the staging file.
                command: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!("{} > {WORK_DIR}/{payload}", shell_join(command)),
                ]),
                env: Some(env_vars(spec.env)),
                volume_mounts: Some(vec![work_mount.clone()]),
                // The dump runs the app's own image, so it is sized like the
                // app, plus the staging space it writes into.
                resources: Some(with_ephemeral(
                    build_resource_requirements(&spec.service.resources, spec.multiplier),
                    work_size,
                )),
                security_context: Some(container_security_context_for(
                    !spec.service.runs_as_root(),
                    spec.service.run_as_user(),
                )),
                ..Default::default()
            });
            format!(
                "set -e; gzip -n '{WORK_DIR}/{payload}'; \
                 curl -fsS --upload-file '{WORK_DIR}/{}' \"${UPLOAD_URL_ENV}\"",
                spec.artifact
            )
        }
        (_, Some(volume)) => {
            let claim = deployment_volume(spec.service_name, volume);
            volumes.push(K8sVolume {
                name: DATA_VOLUME.to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: claim,
                    // Read-only at the volume source as well as the mount: a
                    // backup of a compromised app must not be able to write to
                    // the data it is capturing.
                    read_only: Some(true),
                }),
                ..Default::default()
            });
            upload_mounts.push(VolumeMount {
                name: DATA_VOLUME.to_string(),
                mount_path: DATA_DIR.to_string(),
                read_only: Some(true),
                ..Default::default()
            });
            // A ReadWriteOnce claim can only be mounted by pods on the node
            // that already has it attached, so the Job is pinned to the app's
            // node. Without this it schedules anywhere and sits in
            // `Multi-Attach error` until the deadline kills it.
            affinity = (!spec.backup.quiesce).then(|| Affinity {
                pod_affinity: Some(PodAffinity {
                    required_during_scheduling_ignored_during_execution: Some(vec![
                        PodAffinityTerm {
                            label_selector: Some(LabelSelector {
                                match_labels: Some(service_labels(
                                    spec.deployment_id,
                                    spec.service_name,
                                )),
                                ..Default::default()
                            }),
                            topology_key: "kubernetes.io/hostname".to_string(),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            });
            format!(
                "set -e; tar -czf '{WORK_DIR}/{artifact}' -C {DATA_DIR} .; \
                 curl -fsS --upload-file '{WORK_DIR}/{artifact}' \"${UPLOAD_URL_ENV}\"",
                artifact = spec.artifact
            )
        }
        _ => {
            return Err(anyhow!(
                "service '{}': backup declares neither command nor volume",
                spec.service_name
            ));
        }
    };

    let uploader = Container {
        name: UPLOADER_CONTAINER.to_string(),
        image: Some(spec.uploader_image.to_string()),
        image_pull_policy: Some(IMAGE_PULL_POLICY.to_string()),
        command: Some(vec!["/bin/sh".to_string(), "-c".to_string(), script]),
        env: Some(vec![EnvVar {
            name: UPLOAD_URL_ENV.to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: backup_url_secret_name(spec.backup_id),
                    key: UPLOAD_URL_KEY.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        volume_mounts: Some(upload_mounts),
        resources: Some(with_ephemeral(
            build_resource_requirements(
                &lnvps_compose::Resources {
                    cpu: UPLOADER_CPU.to_string(),
                    memory: UPLOADER_MEMORY.to_string(),
                },
                1,
            ),
            work_size,
        )),
        // Runs as whoever owns the data: the files on a PVC belong to the uid
        // the service writes them as, and a read-only mount gets no `fsGroup`
        // remap, so any other uid would tar an unreadable tree.
        security_context: Some(container_security_context_for(
            !spec.service.runs_as_root(),
            spec.service.run_as_user(),
        )),
        ..Default::default()
    };

    Ok(Job {
        metadata: ObjectMeta {
            name: Some(backup_job_name(spec.backup_id)),
            namespace: Some(namespace_name(spec.deployment_id)),
            labels: Some(sel.clone()),
            ..Default::default()
        },
        spec: Some(JobSpec {
            // One retry. A dump that failed on bad credentials fails again, and
            // the second attempt would upload to the same key.
            backoff_limit: Some(1),
            active_deadline_seconds: Some(spec.deadline.as_secs() as i64),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(sel),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![uploader],
                    init_containers: (!init_containers.is_empty()).then_some(init_containers),
                    volumes: Some(volumes),
                    affinity,
                    restart_policy: Some("Never".to_string()),
                    security_context: Some(pod_security_context_for(spec.service.run_as_user())),
                    // Same rule as the app's own pods: nothing here talks to
                    // the Kubernetes API, and withholding the token is enforced
                    // by the kubelet whatever the CNI does with NetworkPolicy.
                    automount_service_account_token: Some(false),
                    enable_service_links: Some(false),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Staging space for the artifact: the service's own volumes, scaled the way
/// they are, and doubled because a `command:` dump is written and then gzipped
/// beside itself.
fn staging_size(service: &ComposeService, multiplier: u32) -> u64 {
    let declared: u64 = service
        .volumes
        .iter()
        .filter_map(|v| parse_bytes(&v.size).ok())
        .sum();
    let base = if declared == 0 {
        DEFAULT_WORK_SIZE_BYTES
    } else {
        declared
    };
    base.saturating_mul(multiplier.max(1) as u64)
        .saturating_mul(2)
}

/// Add an `ephemeral-storage` request and limit covering the staging emptyDir.
///
/// Without it the pod is scheduled onto a node without asking for the disk it
/// is about to fill: a volume backup stages the whole volume, twice over for a
/// dump, on a node that is also running customers' apps. The effective pod
/// request is the larger of the init container's and the sum of the others', so
/// putting the same figure on both books it once rather than twice.
fn with_ephemeral(mut r: ResourceRequirements, bytes: u64) -> ResourceRequirements {
    let q = Quantity(bytes.to_string());
    r.requests
        .get_or_insert_with(Default::default)
        .insert("ephemeral-storage".to_string(), q.clone());
    r.limits
        .get_or_insert_with(Default::default)
        .insert("ephemeral-storage".to_string(), q);
    r
}

fn env_vars(env: &BTreeMap<String, String>) -> Vec<EnvVar> {
    env.iter()
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..Default::default()
        })
        .collect()
}

/// Re-quote an argv into a single shell word list, so it can be run by `sh -c`
/// with its stdout redirected. Single quotes, with the usual `'\''` escape, so
/// nothing in a catalog command is re-interpreted.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Drive every backup on this operator's cluster one step: start what is
/// pending, record what has finished, schedule what is due, prune what is past
/// retention.
///
/// No-op unless the operator has both a cluster and object storage configured.
/// Individual failures are logged and skipped rather than ending the pass: one
/// deployment's broken backup must not stop every other deployment's.
pub async fn reconcile_app_backups(ctx: &Arc<Context>) -> Result<BTreeSet<u64>> {
    let (Some(cluster_id), Some(store)) = (ctx.settings.app_cluster_id, ctx.object_store.as_ref())
    else {
        return Ok(BTreeSet::new());
    };
    let cluster = ctx.db.get_app_cluster(cluster_id).await?;

    if let Err(e) = schedule_due_backups(ctx, cluster_id).await {
        warn!("backup scheduling failed: {e}");
    }

    let active = ctx
        .db
        .list_active_app_deployment_backups(cluster_id)
        .await?;
    let to_start = startable(&active, ctx.settings.max_concurrent_backups());
    for backup in &active {
        let id = backup.id;
        let result = step_backup(ctx, store, backup, &to_start, &cluster.ingress_domain).await;
        if let Err(e) = result {
            error!("backup {id} failed: {e}");
            if let Err(e) = fail_backup(ctx, backup, &e.to_string()).await {
                warn!("backup {id}: could not record the failure: {e}");
            }
        }
    }

    if let Err(e) = prune_backups(ctx, store, cluster_id).await {
        warn!("backup retention pruning failed: {e}");
    }
    Ok(active.iter().map(|b| b.deployment_id).collect())
}

pub fn quiesced_services(compose: &Compose, backups: &[AppDeploymentBackup]) -> BTreeSet<String> {
    backups
        .iter()
        .filter(|b| b.state == AppBackupState::Running)
        .filter(|b| {
            compose
                .services
                .get(&b.service)
                .and_then(|s| s.backup.as_ref())
                .is_some_and(|m| m.quiesce)
        })
        .map(|b| b.service.clone())
        .collect()
}

async fn backup_method_of(ctx: &Context, backup: &AppDeploymentBackup) -> Result<Backup> {
    let deployment = ctx.db.get_app_deployment(backup.deployment_id).await?;
    let app = ctx.db.get_app(deployment.app_id).await?;
    let compose = Compose::parse(&app.compose)?;
    compose
        .services
        .get(&backup.service)
        .and_then(|s| s.backup.clone())
        .ok_or_else(|| anyhow!("service '{}' declares no backup method", backup.service))
}

async fn step_backup(
    ctx: &Arc<Context>,
    store: &ObjectStore,
    backup: &AppDeploymentBackup,
    to_start: &[u64],
    ingress_domain: &str,
) -> Result<()> {
    let method = backup_method_of(ctx, backup).await?;
    match backup.state {
        AppBackupState::Pending if to_start.contains(&backup.id) => {
            if method.quiesce {
                mark_running(ctx, backup).await
            } else {
                start_backup(ctx, store, backup, ingress_domain).await?;
                if let Some(argv) = method.exec {
                    spawn_pump(ctx, backup.clone(), argv);
                }
                Ok(())
            }
        }
        AppBackupState::Pending => Ok(()),
        _ if method.exec.is_some() => {
            if ctx.exec_pumps.lock().unwrap().contains(&backup.id) {
                return Ok(());
            }
            if payload_ready(ctx, backup).await? {
                record_finished(ctx, store, backup).await
            } else {
                fail_backup(
                    ctx,
                    backup,
                    "the operator restarted while it was copying this backup",
                )
                .await
            }
        }
        _ if method.quiesce && backup.object_key.is_none() => {
            if service_pods(ctx, backup).await? == 0 {
                start_backup(ctx, store, backup, ingress_domain).await
            } else if backup.started.is_some_and(|t| {
                Utc::now() - t
                    > chrono::Duration::from_std(ctx.settings.backup_job_deadline())
                        .unwrap_or(chrono::Duration::hours(1))
            }) {
                fail_backup(ctx, backup, "the app did not stop for the backup in time").await
            } else {
                debug!("backup {}: waiting for the app to stop", backup.id);
                Ok(())
            }
        }
        _ => record_finished(ctx, store, backup).await,
    }
}

async fn mark_running(ctx: &Context, backup: &AppDeploymentBackup) -> Result<()> {
    let mut row = backup.clone();
    row.state = AppBackupState::Running;
    row.started = Some(Utc::now());
    ctx.db.update_app_deployment_backup(&row).await?;
    info!(
        "backup {}: stopping deployment {} service {} for a consistent copy",
        backup.id, backup.deployment_id, backup.service
    );
    Ok(())
}

async fn service_pods(ctx: &Context, backup: &AppDeploymentBackup) -> Result<usize> {
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace_name(backup.deployment_id));
    Ok(pods
        .list(
            &ListParams::default().labels(&label_selector(&service_labels(
                backup.deployment_id,
                &backup.service,
            ))),
        )
        .await?
        .items
        .len())
}

fn label_selector(labels: &BTreeMap<String, String>) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

async fn payload_ready(ctx: &Context, backup: &AppDeploymentBackup) -> Result<bool> {
    let jobs: Api<Job> = Api::namespaced(ctx.client.clone(), &namespace_name(backup.deployment_id));
    Ok(jobs
        .get_opt(&backup_job_name(backup.id))
        .await?
        .and_then(|j| j.metadata.annotations)
        .is_some_and(|a| a.get(PAYLOAD_READY_ANNOTATION).is_some_and(|v| v == "true")))
}

fn spawn_pump(ctx: &Arc<Context>, backup: AppDeploymentBackup, argv: Vec<String>) {
    ctx.exec_pumps.lock().unwrap().insert(backup.id);
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let deadline = ctx.settings.backup_job_deadline();
        let result = match tokio::time::timeout(deadline, pump_exec(&ctx, &backup, &argv)).await {
            Ok(r) => r,
            Err(_) => Err(anyhow!(
                "the app's export did not finish within {deadline:?}"
            )),
        };
        if let Err(e) = result {
            error!("backup {} failed: {e}", backup.id);
            if let Err(e) = fail_backup(&ctx, &backup, &e.to_string()).await {
                warn!("backup {}: could not record the failure: {e}", backup.id);
            }
        }
        ctx.exec_pumps.lock().unwrap().remove(&backup.id);
    });
}

async fn running_pod(pods: &Api<Pod>, selector: &str) -> Result<String> {
    let started = tokio::time::Instant::now();
    loop {
        let found = pods
            .list(&ListParams::default().labels(selector))
            .await?
            .items
            .into_iter()
            .find(|p| {
                p.metadata.deletion_timestamp.is_none()
                    && p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running")
            })
            .and_then(|p| p.metadata.name);
        if let Some(name) = found {
            return Ok(name);
        }
        if started.elapsed() > POD_WAIT {
            return Err(anyhow!("no running pod matches {selector}"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn drain_stderr(process: &mut AttachedProcess) -> tokio::task::JoinHandle<String> {
    let stderr = process.stderr();
    tokio::spawn(async move {
        let Some(mut stderr) = stderr else {
            return String::new();
        };
        let mut tail: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > 2048 {
                tail.drain(..tail.len() - 2048);
            }
        }
        String::from_utf8_lossy(&tail).trim().to_string()
    })
}

async fn finished(
    mut process: AttachedProcess,
    stderr: tokio::task::JoinHandle<String>,
    what: &str,
) -> Result<()> {
    let status = match process.take_status() {
        Some(s) => s.await,
        None => None,
    };
    let stderr = stderr.await.unwrap_or_default();
    match status {
        Some(s) if s.status.as_deref() == Some("Success") => Ok(()),
        Some(s) => Err(anyhow!(
            "{what} failed: {}{}",
            s.message.unwrap_or_else(|| "non-zero exit".to_string()),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {}", truncate(&stderr, 400))
            }
        )),
        None => Err(anyhow!("{what} ended without reporting an exit status")),
    }
}

async fn pump_exec(ctx: &Context, backup: &AppDeploymentBackup, argv: &[String]) -> Result<()> {
    let ns = namespace_name(backup.deployment_id);
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
    let app_pod = running_pod(
        &pods,
        &label_selector(&service_labels(backup.deployment_id, &backup.service)),
    )
    .await?;
    let job_pod = running_pod(&pods, &format!("job-name={}", backup_job_name(backup.id))).await?;

    let mut sink = pods
        .exec(
            &job_pod,
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("cat > '{WORK_DIR}/{PAYLOAD}.part'"),
            ],
            &AttachParams::default()
                .container(UPLOADER_CONTAINER)
                .stdin(true)
                .stdout(false)
                .stderr(true),
        )
        .await?;
    let sink_err = drain_stderr(&mut sink).await;
    let mut source = pods
        .exec(
            &app_pod,
            argv.to_vec(),
            &AttachParams::default()
                .container(&backup.service)
                .stdout(true)
                .stderr(true),
        )
        .await?;
    let source_err = drain_stderr(&mut source).await;

    let mut stdout = source
        .stdout()
        .ok_or_else(|| anyhow!("the export has no stdout"))?;
    let mut stdin = sink
        .stdin()
        .ok_or_else(|| anyhow!("the staging pod has no stdin"))?;
    let copied = tokio::io::copy(&mut stdout, &mut stdin).await?;
    stdin.shutdown().await?;
    drop(stdin);
    finished(source, source_err, "the app's export").await?;
    finished(sink, sink_err, "staging the export").await?;

    let mut publish = pods
        .exec(
            &job_pod,
            vec![
                "mv".to_string(),
                format!("{WORK_DIR}/{PAYLOAD}.part"),
                format!("{WORK_DIR}/{PAYLOAD}"),
            ],
            &AttachParams::default()
                .container(UPLOADER_CONTAINER)
                .stdout(false)
                .stderr(true),
        )
        .await?;
    let publish_err = drain_stderr(&mut publish).await;
    finished(publish, publish_err, "publishing the export").await?;

    let jobs: Api<Job> = Api::namespaced(ctx.client.clone(), &ns);
    jobs.patch(
        &backup_job_name(backup.id),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({
            "metadata": { "annotations": { PAYLOAD_READY_ANNOTATION: "true" } }
        })),
    )
    .await?;
    info!("backup {}: copied {copied} bytes out of the app", backup.id);
    Ok(())
}

/// Which pending backups may start this pass, oldest first.
///
/// Every app on the same daily schedule comes due in the same minute, so
/// without a cap one sweep would start a Job for every deployment on the
/// cluster at once: each one tars a volume and pushes it at the bucket, on
/// nodes that are also running the customers' apps. The queue is the `pending`
/// rows themselves, so nothing is lost by making a run wait a sweep.
fn startable(active: &[AppDeploymentBackup], limit: usize) -> Vec<u64> {
    let running = active
        .iter()
        .filter(|b| b.state == AppBackupState::Running)
        .count();
    let budget = limit.saturating_sub(running);
    active
        .iter()
        .filter(|b| b.state == AppBackupState::Pending)
        .take(budget)
        .map(|b| b.id)
        .collect()
}

/// Create the rows for every deployment whose schedule has come due.
///
/// Rows only: the Job is created by the same path an on-demand backup takes, so
/// there is one way a backup runs regardless of what asked for it.
async fn schedule_due_backups(ctx: &Context, cluster_id: u64) -> Result<()> {
    let now = Utc::now();
    for deployment in ctx
        .db
        .list_all_app_deployments()
        .await?
        .into_iter()
        .filter(|d| d.cluster_id == cluster_id)
    {
        if let Err(e) = schedule_one(ctx, &deployment, now).await {
            warn!(
                "app deployment {}: could not evaluate backup schedule: {e}",
                deployment.id
            );
        }
    }
    Ok(())
}

async fn schedule_one(
    ctx: &Context,
    deployment: &AppDeployment,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let app = ctx.db.get_app(deployment.app_id).await?;
    let compose = Compose::parse(&app.compose)?;
    let Some(policy) = &compose.backup else {
        return Ok(());
    };

    // Only a deployment that is actually meant to be running is backed up. An
    // unpaid or expired one is not owed storage, and a deleted one is on its
    // way out.
    let sub = ctx
        .db
        .get_subscription_by_line_item_id(deployment.subscription_line_item_id)
        .await
        .ok();
    let gate = gate_running(
        deployment.desired_state == lnvps_db::AppDeploymentDesiredState::Running,
        deployment.deleted,
        sub.as_ref(),
        None,
        now,
    );
    if gate != GateReason::Running {
        return Ok(());
    }

    // Never run before means "measure from when the deployment appeared", so a
    // deployment created at 03:05 is not immediately backed up by an 03:00
    // schedule.
    let since = ctx
        .db
        .last_scheduled_app_deployment_backup(deployment.id)
        .await?
        .unwrap_or(deployment.created);
    if !policy.is_due(since, now)? {
        return Ok(());
    }

    let run_id = Uuid::new_v4().to_string();
    for (service, backup) in compose.backup_services() {
        let row = AppDeploymentBackup {
            id: 0,
            deployment_id: deployment.id,
            run_id: run_id.clone(),
            service: service.to_string(),
            method: backup_method(backup),
            artifact: backup.artifact_name(service),
            object_key: None,
            size_bytes: None,
            state: AppBackupState::Pending,
            message: None,
            scheduled: true,
            created: now,
            started: None,
            completed: None,
            deleted: false,
        };
        ctx.db.insert_app_deployment_backup(&row).await?;
    }
    info!(
        "app deployment {}: scheduled backup run {run_id}",
        deployment.id
    );
    Ok(())
}

/// Sign an upload URL and create the Job that fills it.
async fn start_backup(
    ctx: &Context,
    store: &ObjectStore,
    backup: &AppDeploymentBackup,
    ingress_domain: &str,
) -> Result<()> {
    let deployment = ctx.db.get_app_deployment(backup.deployment_id).await?;
    let app = ctx.db.get_app(deployment.app_id).await?;
    let compose = Compose::parse(&app.compose)?;
    let service = compose
        .services
        .get(&backup.service)
        .ok_or_else(|| anyhow!("service '{}' is not in the app's compose", backup.service))?;
    let method = service
        .backup
        .as_ref()
        .ok_or_else(|| anyhow!("service '{}' declares no backup method", backup.service))?;

    let key = backup_object_key(deployment.id, &backup.run_id, &backup.artifact);
    let url = store.presign_put(&key, ctx.settings.backup_url_expiry())?;
    apply(
        &ctx.client,
        &build_url_secret(deployment.id, backup.id, &url),
    )
    .await?;

    let env = resolved_env(ctx, &deployment, &compose, ingress_domain).await?;
    let job = build_backup_job(&BackupJobSpec {
        deployment_id: deployment.id,
        backup_id: backup.id,
        service_name: &backup.service,
        service,
        backup: method,
        env: &env
            .get(&backup.service)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        artifact: &backup.artifact,
        uploader_image: ctx.settings.backup_uploader_image(),
        multiplier: deployment.resource_multiplier,
        deadline: ctx.settings.backup_job_deadline(),
    })?;
    apply(&ctx.client, &job).await?;

    let mut row = backup.clone();
    row.object_key = Some(key);
    row.state = AppBackupState::Running;
    row.started = backup.started.or(Some(Utc::now()));
    ctx.db.update_app_deployment_backup(&row).await?;
    info!(
        "backup {} started for deployment {} service {}",
        backup.id, deployment.id, backup.service
    );
    Ok(())
}

/// Read a running backup's Job and record the outcome, if it has one.
async fn record_finished(
    ctx: &Context,
    store: &ObjectStore,
    backup: &AppDeploymentBackup,
) -> Result<()> {
    let api: Api<Job> = Api::namespaced(ctx.client.clone(), &namespace_name(backup.deployment_id));
    let Some(job) = api.get_opt(&backup_job_name(backup.id)).await? else {
        // The Job is gone without this row ever seeing it succeed. Something
        // outside the operator removed it; the artifact cannot be trusted to
        // exist, and leaving the row Running would retry nothing forever.
        return fail_backup(ctx, backup, "the backup job disappeared before it finished").await;
    };
    let status = job.status.clone().unwrap_or_default();
    if status.succeeded.unwrap_or(0) > 0 {
        let key = backup
            .object_key
            .clone()
            .ok_or_else(|| anyhow!("a completed backup has no object key"))?;
        let size = store.size(&key).await?;
        let mut row = backup.clone();
        row.state = AppBackupState::Completed;
        row.completed = Some(Utc::now());
        row.size_bytes = size;
        // A Job that reported success with nothing in the bucket is a failure
        // that would otherwise be offered to the customer as a restore point.
        if size.is_none() {
            row.state = AppBackupState::Failed;
            row.message = Some("the job finished but uploaded no artifact".to_string());
        }
        ctx.db.update_app_deployment_backup(&row).await?;
        cleanup_job(ctx, backup).await;
        info!("backup {} completed ({:?} bytes)", backup.id, size);
        return Ok(());
    }
    if status.failed.unwrap_or(0) > 0 {
        let reason = status
            .conditions
            .unwrap_or_default()
            .into_iter()
            .find(|c| c.type_ == "Failed")
            .and_then(|c| c.message.or(c.reason))
            .unwrap_or_else(|| "the backup job failed".to_string());
        return fail_backup(ctx, backup, &reason).await;
    }
    debug!("backup {} still running", backup.id);
    Ok(())
}

/// Mark a backup failed and clear up after it.
async fn fail_backup(ctx: &Context, backup: &AppDeploymentBackup, message: &str) -> Result<()> {
    let mut row = backup.clone();
    row.state = AppBackupState::Failed;
    row.completed = Some(Utc::now());
    row.message = Some(truncate(message, 500));
    ctx.db.update_app_deployment_backup(&row).await?;
    cleanup_job(ctx, backup).await;
    warn!("backup {} failed: {message}", backup.id);
    Ok(())
}

/// Remove a finished backup's Job and its upload URL, so a leaked URL stops
/// being useful the moment the run it belonged to is over.
async fn cleanup_job(ctx: &Context, backup: &AppDeploymentBackup) {
    let ns = namespace_name(backup.deployment_id);
    let jobs: Api<Job> = Api::namespaced(ctx.client.clone(), &ns);
    // Background propagation, or the Job's pod outlives it.
    let params = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Background),
        ..Default::default()
    };
    if let Err(e) = jobs.delete(&backup_job_name(backup.id), &params).await {
        debug!("backup {}: job cleanup: {e}", backup.id);
    }
    let secrets: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);
    if let Err(e) = secrets
        .delete(&backup_url_secret_name(backup.id), &DeleteParams::default())
        .await
    {
        debug!("backup {}: url secret cleanup: {e}", backup.id);
    }
}

/// Drop runs past the app's retention, oldest first.
///
/// Retention counts **runs**, not artifacts: a two-service app keeps two
/// objects per run, and a customer reading "keep 7" means seven restore points.
async fn prune_backups(ctx: &Context, store: &ObjectStore, cluster_id: u64) -> Result<()> {
    for deployment in ctx
        .db
        .list_all_app_deployments()
        .await?
        .into_iter()
        .filter(|d| d.cluster_id == cluster_id)
    {
        let Ok(app) = ctx.db.get_app(deployment.app_id).await else {
            continue;
        };
        let retention = Compose::parse(&app.compose)
            .ok()
            .and_then(|c| retention_for(&c));
        let Some(retention) = retention else {
            continue;
        };

        let rows = ctx.db.list_app_deployment_backups(deployment.id).await?;
        for row in rows_past_retention(&rows, retention) {
            if let Some(key) = &row.object_key
                && let Err(e) = store.delete(key).await
            {
                // Leave the row alone: a key whose object could not be deleted
                // has to stay visible, or the object is orphaned in the bucket
                // with nothing pointing at it.
                warn!("backup {}: could not delete '{key}': {e}", row.id);
                continue;
            }
            ctx.db.delete_app_deployment_backup(row.id).await?;
            info!("backup {} pruned (retention {retention})", row.id);
        }
    }
    Ok(())
}

fn retention_for(compose: &Compose) -> Option<u32> {
    match &compose.backup {
        Some(policy) => Some(policy.retention_or_default()),
        None if !compose.backup_services().is_empty() => {
            Some(lnvps_compose::DEFAULT_BACKUP_RETENTION)
        }
        None => None,
    }
}

/// The rows belonging to runs past the newest `retention` **restorable** runs.
/// Rows are newest-first, as the listing returns them.
///
/// Only a run that produced an artifact counts against the limit. A failed run
/// is not a restore point, so counting it would let a bad night evict a good
/// one: on "keep 3", two failures would leave the customer one real backup.
/// Failures are still shown while the window has room, and drop out with the
/// runs around them once it is full.
///
/// Runs still in flight are never counted or pruned: an in-progress run is not
/// yet a restore point either, and counting it would drop an older one that is.
fn rows_past_retention(rows: &[AppDeploymentBackup], retention: u32) -> Vec<&AppDeploymentBackup> {
    let restorable: Vec<&str> = rows
        .iter()
        .filter(|r| r.state == AppBackupState::Completed)
        .map(|r| r.run_id.as_str())
        .collect();

    let limit = retention as usize;
    let mut keep: BTreeMap<&str, bool> = BTreeMap::new();
    let mut runs = 0usize;
    let mut points = 0usize;
    let mut out = Vec::new();
    for row in rows {
        if matches!(row.state, AppBackupState::Pending | AppBackupState::Running) {
            continue;
        }
        let run = row.run_id.as_str();
        let decided = match keep.get(run) {
            Some(d) => *d,
            None => {
                let is_point = restorable.contains(&run);
                // Kept as one of the newest `retention` restore points, or as
                // one of the newest `retention` runs of any outcome. The second
                // clause is what shows a customer whose backups are all failing
                // that they are failing, and what bounds those rows: an app
                // that has never succeeded keeps `retention` failures, not one
                // row per night forever.
                let d = (is_point && points < limit) || runs < limit;
                if is_point {
                    points += 1;
                }
                runs += 1;
                keep.insert(run, d);
                d
            }
        };
        if !decided {
            out.push(row);
        }
    }
    out
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_compose::Compose;

    fn compose() -> Compose {
        Compose::parse(
            "services:\n  \
               db:\n    \
                 image: mariadb:11\n    \
                 user: root\n    \
                 ports:\n      - { name: mysql, container: 3306, protocol: tcp, expose: none }\n    \
                 env:\n      MARIADB_ROOT_PASSWORD: pw\n    \
                 volumes:\n      - { name: data, path: /var/lib/mysql, size: 5Gi }\n    \
                 backup:\n      \
                   command: [\"sh\", \"-c\", \"exec mariadb-dump -h db -uroot -p$MARIADB_ROOT_PASSWORD\"]\n      \
                   artifact: route96.sql\n  \
               blobs:\n    \
                 image: example/blobs:1\n    \
                 user: \"1000\"\n    \
                 volumes:\n      - { name: files, path: /app/data, size: 20Gi }\n    \
                 backup:\n      volume: files\n\
             backup: { schedule: \"0 3 * * *\", retention: 3 }\n",
        )
        .unwrap()
    }

    fn spec<'a>(
        c: &'a Compose,
        service: &'a str,
        env: &'a BTreeMap<String, String>,
        artifact: &'a str,
    ) -> BackupJobSpec<'a> {
        let svc = c.services.get(service).unwrap();
        BackupJobSpec {
            deployment_id: 12,
            backup_id: 77,
            service_name: service,
            service: svc,
            backup: svc.backup.as_ref().unwrap(),
            env,
            artifact,
            uploader_image: DEFAULT_UPLOADER_IMAGE,
            multiplier: 1,
            deadline: Duration::from_secs(3600),
        }
    }

    /// A `command:` backup runs the dump on the app's own image -- only that
    /// image has the dump tool -- and hands the file to the one container here
    /// that has an HTTP client.
    #[test]
    fn command_backup_dumps_on_the_app_image_and_uploads_separately() {
        let c = compose();
        let env = BTreeMap::from([("MARIADB_ROOT_PASSWORD".to_string(), "hunter2".to_string())]);
        let job = build_backup_job(&spec(&c, "db", &env, "route96.sql.gz")).unwrap();
        let pod = job.spec.unwrap().template.spec.unwrap();

        let init = &pod.init_containers.as_ref().unwrap()[0];
        assert_eq!(init.image.as_deref(), Some("mariadb:11"));
        let script = init.command.as_ref().unwrap()[2].clone();
        // The catalog's argv is re-quoted, not re-parsed, and its stdout is
        // redirected to the staging file.
        assert!(script.contains("'sh' '-c' 'exec mariadb-dump"), "{script}");
        assert!(script.ends_with("> /work/route96.sql"), "{script}");
        // The dump authenticates with the service's own resolved env.
        let vars = init.env.as_ref().unwrap();
        assert_eq!(
            vars.iter()
                .find(|e| e.name == "MARIADB_ROOT_PASSWORD")
                .and_then(|e| e.value.clone()),
            Some("hunter2".to_string())
        );

        let upload = &pod.containers[0];
        assert_eq!(upload.image.as_deref(), Some(DEFAULT_UPLOADER_IMAGE));
        let script = upload.command.as_ref().unwrap()[2].clone();
        // Quoted: the staging path is built from a catalog-supplied name.
        assert!(script.contains("gzip -n '/work/route96.sql'"), "{script}");
        assert!(
            script.contains("--upload-file '/work/route96.sql.gz' \"$LNVPS_UPLOAD_URL\""),
            "{script}"
        );
        // No data volume is mounted: a dump reads through the service, not off
        // the disk.
        assert!(
            !pod.volumes
                .unwrap()
                .iter()
                .any(|v| v.persistent_volume_claim.is_some())
        );
        assert!(pod.affinity.is_none());
    }

    /// A `volume:` backup mounts the customer's data read-only, and is pinned
    /// to the node already holding the claim.
    #[test]
    fn volume_backup_mounts_read_only_and_follows_the_claim() {
        let c = compose();
        let env = BTreeMap::new();
        let job = build_backup_job(&spec(&c, "blobs", &env, "blobs-files.tar.gz")).unwrap();
        let pod = job.spec.unwrap().template.spec.unwrap();
        assert!(pod.init_containers.is_none(), "nothing to dump");

        let claim = pod
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.persistent_volume_claim.is_some())
            .unwrap();
        let pvc = claim.persistent_volume_claim.as_ref().unwrap();
        assert_eq!(pvc.claim_name, "blobs-files");
        assert_eq!(pvc.read_only, Some(true), "the source is never writable");

        let mount = pod.containers[0]
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.name == DATA_VOLUME)
            .unwrap();
        assert_eq!(mount.read_only, Some(true));

        let script = pod.containers[0].command.as_ref().unwrap()[2].clone();
        assert!(
            script.contains("tar -czf '/work/blobs-files.tar.gz' -C /data ."),
            "{script}"
        );

        // ReadWriteOnce: the pod has to land on the node holding the claim.
        let affinity = pod
            .affinity
            .unwrap()
            .pod_affinity
            .unwrap()
            .required_during_scheduling_ignored_during_execution
            .unwrap();
        assert_eq!(affinity[0].topology_key, "kubernetes.io/hostname");
        assert_eq!(
            affinity[0]
                .label_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap(),
            &service_labels(12, "blobs")
        );
    }

    /// The upload URL is a credential: it arrives through a Secret rather than
    /// on a command line, where every other process in the pod could read it.
    #[test]
    fn the_upload_url_never_reaches_a_command_line() {
        let c = compose();
        let env = BTreeMap::new();
        let job = build_backup_job(&spec(&c, "blobs", &env, "a.tar.gz")).unwrap();
        let pod = job.spec.unwrap().template.spec.unwrap();
        let container = &pod.containers[0];

        let source = container.env.as_ref().unwrap()[0]
            .value_from
            .as_ref()
            .unwrap()
            .secret_key_ref
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(source.name, "backup-77-url");
        assert_eq!(source.key, UPLOAD_URL_KEY);
        assert!(container.env.as_ref().unwrap()[0].value.is_none());
        assert!(
            container.command.as_ref().unwrap()[2].contains("\"$LNVPS_UPLOAD_URL\""),
            "the URL is dereferenced from the environment, not interpolated"
        );

        let secret = build_url_secret(12, 77, "https://s3.example.com/put?sig=abc");
        assert_eq!(secret.metadata.name.as_deref(), Some("backup-77-url"));
        assert_eq!(secret.metadata.namespace.as_deref(), Some("app-12"));
    }

    /// The Job is hardened like the app's own pods, and cannot outlive its
    /// upload URL.
    #[test]
    fn backup_pods_are_hardened_and_bounded() {
        let c = compose();
        let env = BTreeMap::new();
        let job = build_backup_job(&spec(&c, "blobs", &env, "a.tar.gz")).unwrap();
        let spec_ = job.spec.unwrap();
        assert_eq!(spec_.backoff_limit, Some(1));
        assert_eq!(spec_.active_deadline_seconds, Some(3600));

        let pod = spec_.template.spec.unwrap();
        assert_eq!(pod.restart_policy.as_deref(), Some("Never"));
        assert_eq!(pod.automount_service_account_token, Some(false));
        assert_eq!(pod.enable_service_links, Some(false));

        let sc = pod.containers[0].security_context.as_ref().unwrap();
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(sc.read_only_root_filesystem, Some(true));
        // Reads a read-only mount, which gets no fsGroup remap, so it has to be
        // the uid that wrote the files.
        assert_eq!(sc.run_as_user, Some(1000));
    }

    /// Staging space is sized from the data being captured, and scales with the
    /// deployment, or a large app's dump fills the node and is evicted.
    #[test]
    fn staging_space_follows_the_data() {
        let c = compose();
        let db = c.services.get("db").unwrap();
        // 5Gi of database, written then gzipped beside itself.
        assert_eq!(staging_size(db, 1), 5 * 1024 * 1024 * 1024 * 2);
        assert_eq!(staging_size(db, 4), 5 * 1024 * 1024 * 1024 * 8);

        let no_volumes = Compose::parse("services:\n  a:\n    image: x\n").unwrap();
        assert_eq!(
            staging_size(no_volumes.services.get("a").unwrap(), 1),
            DEFAULT_WORK_SIZE_BYTES * 2
        );
    }

    /// Artifact names carry the catalog's payload name and our compression
    /// suffix, and the object key is entirely server-derived.
    #[test]
    fn artifact_and_key_naming() {
        let c = compose();
        let db = c.services.get("db").unwrap().backup.as_ref().unwrap();
        let blobs = c.services.get("blobs").unwrap().backup.as_ref().unwrap();
        assert_eq!(db.artifact_name("db"), "route96.sql.gz");
        assert_eq!(blobs.artifact_name("blobs"), "blobs-files.tar.gz");
        assert_eq!(backup_method(db), AppBackupMethod::Command);
        assert_eq!(backup_method(blobs), AppBackupMethod::Volume);

        // An undeclared artifact name falls back to the service and volume.
        let bare =
            Compose::parse("services:\n  a:\n    image: x\n    backup: { command: [\"sh\"] }\n")
                .unwrap();
        assert_eq!(
            bare.services
                .get("a")
                .unwrap()
                .backup
                .as_ref()
                .unwrap()
                .artifact_name("a"),
            "a.dump.gz"
        );

        assert_eq!(
            backup_object_key(12, "run-abc", "route96.sql.gz"),
            "deployments/12/run-abc/route96.sql.gz"
        );
    }

    /// Every backup container asks for what it uses. Without a request the pod
    /// is BestEffort -- first evicted under node pressure -- and is scheduled
    /// onto a node without declaring the staging space it is about to fill.
    #[test]
    fn backup_containers_request_cpu_memory_and_staging_space() {
        let c = compose();
        let env = BTreeMap::new();
        let job = build_backup_job(&spec(&c, "blobs", &env, "blobs-files.tar.gz")).unwrap();
        let pod = job.spec.unwrap().template.spec.unwrap();

        let res = pod.containers[0].resources.as_ref().unwrap();
        let requests = res.requests.as_ref().unwrap();
        let limits = res.limits.as_ref().unwrap();
        assert_eq!(
            requests.get("cpu"),
            Some(&Quantity(UPLOADER_CPU.to_string()))
        );
        assert_eq!(
            requests.get("memory"),
            Some(&Quantity(UPLOADER_MEMORY.to_string()))
        );
        // The staging emptyDir's size limit, asked for as ephemeral storage:
        // 20Gi of volume, doubled for the write-then-compress staging.
        let staging = Quantity((20 * 1024 * 1024 * 1024u64 * 2).to_string());
        assert_eq!(requests.get("ephemeral-storage"), Some(&staging));
        assert_eq!(limits.get("ephemeral-storage"), Some(&staging));
        assert_eq!(requests, limits, "requests == limits, as the apps are");
    }

    /// A catalog command is quoted, never re-parsed, so an argument containing
    /// a quote or a shell metacharacter cannot escape into the redirect.
    #[test]
    fn command_arguments_cannot_escape_the_shell() {
        assert_eq!(shell_join(&["a".into(), "b c".into()]), "'a' 'b c'");
        assert_eq!(
            shell_join(&["it's".into(), "x; rm -rf /".into()]),
            r#"'it'\''s' 'x; rm -rf /'"#
        );
    }

    /// Retention counts restore points, keeps the newest, and never counts a
    /// run that is still in flight -- doing so would drop a finished restore
    /// point in favour of one that does not exist yet.
    #[test]
    fn retention_counts_finished_runs_newest_first() {
        let row = |id: u64, run: &str, state: AppBackupState| AppDeploymentBackup {
            id,
            deployment_id: 1,
            run_id: run.to_string(),
            service: format!("s{id}"),
            method: AppBackupMethod::Volume,
            artifact: "a.tar.gz".to_string(),
            object_key: Some(format!("deployments/1/{run}/a.tar.gz")),
            size_bytes: Some(1),
            state,
            message: None,
            scheduled: true,
            created: Utc::now(),
            started: None,
            completed: None,
            deleted: false,
        };
        // Newest first, as the listing returns them. Run "d" is still running.
        let rows = vec![
            row(1, "d", AppBackupState::Running),
            row(2, "c", AppBackupState::Completed),
            row(3, "c", AppBackupState::Completed),
            row(4, "b", AppBackupState::Failed),
            row(5, "a", AppBackupState::Completed),
        ];

        // Keeping two restore points keeps "c" and "a". The failed run "b" sits
        // between them and is shown, but does not use up a slot: "d" is not yet
        // a restore point and does not count either.
        let pruned: Vec<u64> = rows_past_retention(&rows, 2).iter().map(|r| r.id).collect();
        assert!(pruned.is_empty(), "{pruned:?}");

        // Keeping one keeps run "c", both of its artifacts, and drops the rest.
        let pruned: Vec<u64> = rows_past_retention(&rows, 1).iter().map(|r| r.id).collect();
        assert_eq!(pruned, vec![4, 5]);

        // Retention larger than the history prunes nothing.
        assert!(rows_past_retention(&rows, 7).is_empty());
    }

    /// Regression test: a failed run is not a restore point, so it must not
    /// evict one. On "keep 2" with two failures, counting failures would leave
    /// the customer a single backup and delete a good one to do it.
    #[test]
    fn a_failed_run_does_not_evict_a_restore_point() {
        let row = |id: u64, run: &str, state: AppBackupState| AppDeploymentBackup {
            id,
            deployment_id: 1,
            run_id: run.to_string(),
            service: "db".to_string(),
            method: AppBackupMethod::Volume,
            artifact: "a.tar.gz".to_string(),
            object_key: Some(format!("deployments/1/{run}/a.tar.gz")),
            size_bytes: Some(1),
            state,
            message: None,
            scheduled: true,
            created: Utc::now(),
            started: None,
            completed: None,
            deleted: false,
        };
        // Newest first: two failed nights on top of two good ones.
        let rows = vec![
            row(1, "d", AppBackupState::Failed),
            row(2, "c", AppBackupState::Failed),
            row(3, "b", AppBackupState::Completed),
            row(4, "a", AppBackupState::Completed),
        ];

        // Both restore points survive; the failures are inside the window and
        // are kept as the record of what went wrong.
        assert!(rows_past_retention(&rows, 4).is_empty());

        // On "keep 2" both failures are recent enough to show, and both restore
        // points survive: neither failure spends a restore point's slot.
        let pruned: Vec<u64> = rows_past_retention(&rows, 2).iter().map(|r| r.id).collect();
        assert!(pruned.is_empty(), "a restore point was evicted: {pruned:?}");

        // On "keep 1" the newest run is shown whatever its outcome, and the
        // newest run that is actually restorable is kept with it.
        let pruned: Vec<u64> = rows_past_retention(&rows, 1).iter().map(|r| r.id).collect();
        assert_eq!(pruned, vec![2, 4]);

        // An app that has never succeeded does not accumulate a row per night.
        let failures: Vec<AppDeploymentBackup> = (1..=10)
            .map(|i| row(i, &format!("r{i}"), AppBackupState::Failed))
            .collect();
        assert_eq!(rows_past_retention(&failures, 3).len(), 7);
    }

    /// Every app on the same daily schedule comes due in the same minute, so
    /// the number of Jobs in flight is capped and the rest wait their turn as
    /// pending rows.
    #[test]
    fn concurrency_is_capped_and_the_queue_survives_it() {
        let row = |id: u64, state: AppBackupState| AppDeploymentBackup {
            id,
            deployment_id: id,
            run_id: format!("run-{id}"),
            service: "db".to_string(),
            method: AppBackupMethod::Command,
            artifact: "a.gz".to_string(),
            object_key: None,
            size_bytes: None,
            state,
            message: None,
            scheduled: true,
            created: Utc::now(),
            started: None,
            completed: None,
            deleted: false,
        };

        // Nothing running: the first `limit` pending rows start.
        let queue = vec![
            row(1, AppBackupState::Pending),
            row(2, AppBackupState::Pending),
            row(3, AppBackupState::Pending),
            row(4, AppBackupState::Pending),
        ];
        assert_eq!(startable(&queue, 3), vec![1, 2, 3]);

        // Jobs already in flight spend the budget.
        let queue = vec![
            row(1, AppBackupState::Running),
            row(2, AppBackupState::Running),
            row(3, AppBackupState::Pending),
            row(4, AppBackupState::Pending),
        ];
        assert_eq!(startable(&queue, 3), vec![3]);

        // At the cap, nothing new starts -- and nothing is dropped, because the
        // queue is the pending rows themselves.
        let queue = vec![
            row(1, AppBackupState::Running),
            row(2, AppBackupState::Running),
            row(3, AppBackupState::Running),
            row(4, AppBackupState::Pending),
        ];
        assert!(startable(&queue, 3).is_empty());
        assert!(startable(&queue, 0).is_empty());
    }

    /// The uploader's script, run for real: the exact command line the Job
    /// gives the uploader image, in that image, against a real S3 server.
    ///
    /// The builder tests assert what the script *says*. They cannot catch a
    /// `tar` flag busybox does not take, a `curl` invocation that sends chunked
    /// transfer encoding (which S3 rejects on a presigned `PUT`), or a URL the
    /// server will not accept -- each of which is a backup that silently never
    /// existed until a customer asked to restore one.
    ///
    /// Runs against the `rustfs` service in `docker-compose.e2e.yaml`; skipped
    /// when the e2e stack is not up.
    #[tokio::test]
    async fn the_uploader_script_really_uploads() {
        let Some(store) = test_store() else {
            eprintln!("skipping: LNVPS_TEST_S3_ENDPOINT / _ACCESS_KEY / _SECRET_KEY not set");
            return;
        };
        if !docker_available() {
            eprintln!("skipping: docker is not available");
            return;
        }
        store.create_bucket().await.expect("create bucket");

        // A volume backup's data, as the PVC would present it.
        let data = tempfile::tempdir().expect("tempdir");
        std::fs::write(data.path().join("blob.bin"), vec![7u8; 4096]).unwrap();
        std::fs::create_dir(data.path().join("nested")).unwrap();
        std::fs::write(data.path().join("nested/inner.txt"), b"inner").unwrap();

        let c = compose();
        let env = BTreeMap::new();
        let artifact = "blobs-files.tar.gz";
        let job = build_backup_job(&spec(&c, "blobs", &env, artifact)).unwrap();
        let script = job.spec.unwrap().template.spec.unwrap().containers[0]
            .command
            .as_ref()
            .unwrap()[2]
            .clone();

        let key = backup_object_key(12, "run-live", artifact);
        let url = store
            .presign_put(&key, std::time::Duration::from_secs(300))
            .unwrap();

        // `--network host` so the container reaches the rustfs published on the
        // host; the data mount is read-only exactly as the Job mounts the PVC,
        // and /work is the emptyDir the Job stages into.
        let out = std::process::Command::new("docker")
            .args(["run", "--rm", "--network", "host"])
            .arg("-v")
            .arg(format!("{}:{DATA_DIR}:ro", data.path().display()))
            .args(["--tmpfs", WORK_DIR])
            .arg("-e")
            .arg(format!("{UPLOAD_URL_ENV}={url}"))
            .arg(DEFAULT_UPLOADER_IMAGE)
            .args(["/bin/sh", "-c", &script])
            .output()
            .expect("run the uploader");
        assert!(
            out.status.success(),
            "uploader failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        // The artifact is in the bucket, and it is the archive it claims to be.
        let size = store.size(&key).await.expect("head").expect("no artifact");
        assert!(size > 0, "an empty artifact is not a backup");

        let get = store
            .presign_get(&key, std::time::Duration::from_secs(300), Some(artifact))
            .unwrap();
        let body = reqwest::get(&get)
            .await
            .expect("download")
            .bytes()
            .await
            .expect("body");
        let listing = tempfile::tempdir().unwrap();
        let tarball = listing.path().join(artifact);
        std::fs::write(&tarball, &body).unwrap();
        let listed = std::process::Command::new("tar")
            .arg("-tzf")
            .arg(&tarball)
            .output()
            .expect("list the archive");
        assert!(
            listed.status.success(),
            "the artifact is not a valid tar.gz"
        );
        let names = String::from_utf8_lossy(&listed.stdout);
        assert!(names.contains("blob.bin"), "{names}");
        assert!(names.contains("nested/inner.txt"), "{names}");

        store.delete(&key).await.expect("cleanup");
    }

    fn test_store() -> Option<ObjectStore> {
        ObjectStore::new(lnvps_api_common::ObjectStoreConfig {
            endpoint: std::env::var("LNVPS_TEST_S3_ENDPOINT").ok()?,
            region: "us-east-1".to_string(),
            bucket: "lnvps-backup-uploader-test".to_string(),
            access_key: std::env::var("LNVPS_TEST_S3_ACCESS_KEY").ok()?,
            secret_key: std::env::var("LNVPS_TEST_S3_SECRET_KEY").ok()?,
            path_style: true,
        })
        .ok()
    }

    fn docker_available() -> bool {
        std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A failure message is stored in a bounded column, so a Job condition with
    /// a wall of text cannot fail the write that records the failure.
    #[test]
    fn failure_messages_are_bounded() {
        assert_eq!(truncate("short", 500), "short");
        assert_eq!(truncate(&"x".repeat(600), 500).len(), 500);
        // Counted in characters, so a multi-byte message is not cut mid-symbol.
        assert_eq!(truncate("äöü", 2), "äö");
    }

    #[test]
    fn manual_only_apps_keep_the_default_retention() {
        let scheduled = Compose::parse(
            "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: /d, size: 1Gi }\n    backup: { volume: d }\nbackup: { schedule: \"0 3 * * *\", retention: 3 }\n",
        )
        .unwrap();
        assert_eq!(retention_for(&scheduled), Some(3));
        let manual = Compose::parse(
            "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: /d, size: 1Gi }\n    backup: { volume: d }\n",
        )
        .unwrap();
        assert_eq!(
            retention_for(&manual),
            Some(lnvps_compose::DEFAULT_BACKUP_RETENTION)
        );
        let none = Compose::parse("services:\n  a:\n    image: x\n").unwrap();
        assert_eq!(retention_for(&none), None);
    }

    fn relay_compose(backup: &str) -> Compose {
        Compose::parse(&format!(
            "services:\n  relay:\n    image: example/relay:1\n    user: \"1000\"\n    volumes:\n      - {{ name: db, path: /app/db, size: 5Gi }}\n    backup: {backup}\n"
        ))
        .unwrap()
    }

    #[test]
    fn exec_backup_waits_for_the_streamed_payload_and_uploads_it() {
        let c =
            relay_compose("{ exec: [\"/app/strfry\", \"export\"], artifact: strfry-events.jsonl }");
        let env = BTreeMap::new();
        let job = build_backup_job(&spec(&c, "relay", &env, "strfry-events.jsonl.gz")).unwrap();
        let pod = job.spec.unwrap().template.spec.unwrap();
        assert!(pod.init_containers.is_none());
        assert!(pod.affinity.is_none());
        assert!(
            pod.volumes
                .unwrap()
                .iter()
                .all(|v| v.persistent_volume_claim.is_none())
        );
        let upload = &pod.containers[0];
        assert_eq!(upload.name, UPLOADER_CONTAINER);
        let script = upload.command.as_ref().unwrap()[2].clone();
        assert!(
            script.contains("while [ ! -e '/work/payload' ]"),
            "{script}"
        );
        assert!(
            script.contains("mv '/work/payload.gz' '/work/strfry-events.jsonl.gz'"),
            "{script}"
        );
        assert!(
            script.contains("--upload-file '/work/strfry-events.jsonl.gz'"),
            "{script}"
        );
    }

    #[test]
    fn a_quiesced_volume_backup_is_not_pinned_to_the_stopped_app() {
        let env = BTreeMap::new();
        let live = relay_compose("{ volume: db }");
        let pinned = build_backup_job(&spec(&live, "relay", &env, "relay-db.tar.gz")).unwrap();
        assert!(
            pinned
                .spec
                .unwrap()
                .template
                .spec
                .unwrap()
                .affinity
                .is_some()
        );
        let quiet = relay_compose("{ volume: db, quiesce: true }");
        let free = build_backup_job(&spec(&quiet, "relay", &env, "relay-db.tar.gz")).unwrap();
        let pod = free.spec.unwrap().template.spec.unwrap();
        assert!(pod.affinity.is_none());
        assert!(pod.containers[0].command.as_ref().unwrap()[2].contains("tar -czf"));
    }

    #[test]
    fn only_running_quiesced_backups_stop_their_service() {
        let row = |service: &str, state: AppBackupState| AppDeploymentBackup {
            id: 1,
            deployment_id: 1,
            run_id: "r".to_string(),
            service: service.to_string(),
            method: AppBackupMethod::Volume,
            artifact: "a".to_string(),
            object_key: None,
            size_bytes: None,
            state,
            message: None,
            scheduled: false,
            created: Utc::now(),
            started: None,
            completed: None,
            deleted: false,
        };
        let quiet = relay_compose("{ volume: db, quiesce: true }");
        assert_eq!(
            quiesced_services(&quiet, &[row("relay", AppBackupState::Running)]),
            BTreeSet::from(["relay".to_string()])
        );
        assert!(quiesced_services(&quiet, &[row("relay", AppBackupState::Pending)]).is_empty());
        assert!(quiesced_services(&quiet, &[row("relay", AppBackupState::Completed)]).is_empty());
        assert!(quiesced_services(&quiet, &[row("gone", AppBackupState::Running)]).is_empty());
        let live = relay_compose("{ volume: db }");
        assert!(quiesced_services(&live, &[row("relay", AppBackupState::Running)]).is_empty());
    }

    #[test]
    fn label_selectors_join_every_label() {
        let sel = label_selector(&BTreeMap::from([
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]));
        assert_eq!(sel, "a=1,b=2");
        assert_eq!(
            backup_method(
                &relay_compose("{ exec: [\"x\"] }").services["relay"]
                    .backup
                    .clone()
                    .unwrap()
            ),
            AppBackupMethod::Exec
        );
    }
}
