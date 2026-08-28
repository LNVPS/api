//! Parser, validator and `${…}` resolver for the app-catalog **compose-ish**
//! YAML.
//!
//! The catalog stores each app as a small compose-style document with four
//! top-level keys (no `x-*` extensions):
//!
//! - `services:` — one or more containers (image / ports / env / volumes).
//! - `secrets:` — values the operator generates **once** per deployment and
//!   injects wherever `${NAME}` is referenced (e.g. a DB password shared by two
//!   services).
//! - `config:` — fields the customer fills in (rendered as a form); their
//!   values are stored on the deployment and injected as env.
//!
//! This module only turns the YAML into a typed model, validates it, and
//! resolves `${…}` references. The Kubernetes object mapping lives elsewhere.

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use croner::Cron;
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

/// A parsed app compose document.
#[derive(Debug, Clone, Deserialize)]
pub struct Compose {
    /// Named services (containers). Order is not significant; ordering hints are
    /// expressed via `depends_on` (advisory).
    pub services: HashMap<String, Service>,
    /// Operator-generated secrets, injected as env wherever referenced.
    #[serde(default)]
    pub secrets: Vec<SecretDecl>,
    /// Customer-provided configuration fields (the deploy form).
    #[serde(default)]
    pub config: Vec<ConfigField>,
    /// Automatic backup policy for the whole app. Omit for an app that is only
    /// backed up when the customer asks.
    #[serde(default)]
    pub backup: Option<BackupPolicy>,
}

/// How often the operator runs an app's backups, and how many runs it keeps.
///
/// The policy is app-wide while the *method* is per service, because a run has
/// to be a single point in time across the whole app: a relay's database dump
/// and its blob volume taken hours apart do not restore into a consistent
/// instance.
#[derive(Debug, Clone, Deserialize)]
pub struct BackupPolicy {
    /// When runs start, as a standard 5-field cron expression
    /// (`minute hour day-of-month month day-of-week`) interpreted in **UTC**.
    /// `0 3 * * *` is the common case: every day at 03:00.
    ///
    /// UTC rather than a customer timezone because the deployment has no
    /// timezone of its own, and a schedule that silently shifted by an hour
    /// twice a year is worse than one that is always where it was written.
    pub schedule: String,
    /// How many completed runs to keep; older ones are pruned with their
    /// artifacts. Defaults to [`DEFAULT_BACKUP_RETENTION`].
    #[serde(default)]
    pub retention: Option<u32>,
}

impl BackupPolicy {
    /// Declared retention, or [`DEFAULT_BACKUP_RETENTION`].
    pub fn retention_or_default(&self) -> u32 {
        self.retention.unwrap_or(DEFAULT_BACKUP_RETENTION)
    }

    /// The parsed schedule.
    ///
    /// Parsing at every use rather than caching one: a `Compose` is
    /// deserialised from a stored row and cloned around, and the operator
    /// evaluates this once per deployment per sweep, which is nowhere near
    /// often enough to be worth a lazily-initialised field.
    pub fn cron(&self) -> Result<Cron> {
        Cron::from_str(&self.schedule).map_err(|e| {
            anyhow!(
                "backup schedule '{}' is not a valid cron: {e}",
                self.schedule
            )
        })
    }

    /// The first run due strictly after `after`, in UTC.
    pub fn next_run_after(&self, after: DateTime<Utc>) -> Result<DateTime<Utc>> {
        self.cron()?
            .find_next_occurrence(&after, false)
            .map_err(|e| {
                anyhow!(
                    "backup schedule '{}' has no next occurrence after {after}: {e}",
                    self.schedule
                )
            })
    }

    /// Whether a run is due now, given when the schedule last ran.
    ///
    /// `since` is the last scheduled run, or the deployment's creation time
    /// when the schedule has never run — so a deployment does not get a backup
    /// the instant it is created, and one that has been down past several
    /// occurrences gets a single catch-up run rather than one per missed slot.
    pub fn is_due(&self, since: DateTime<Utc>, now: DateTime<Utc>) -> Result<bool> {
        Ok(self.next_run_after(since)? <= now)
    }

    /// Reject a schedule that fires faster than [`MIN_BACKUP_INTERVAL_MINUTES`].
    ///
    /// `* * * * *` is a valid cron and a way to fill a bucket with a copy of a
    /// customer's data every minute, so the floor is enforced where the catalog
    /// entry is written rather than discovered in a storage bill. Checked over
    /// several consecutive occurrences because a pattern can be sparse in one
    /// place and dense in another (`0,1 3 * * *` fires twice a minute apart).
    fn validate_frequency(&self) -> Result<()> {
        let cron = self.cron()?;
        // A fixed reference instant, so the check does not depend on when it
        // runs: 1 Jan, which every calendar-based pattern reaches.
        let mut at = DateTime::<Utc>::from_timestamp(1_735_689_600, 0)
            .ok_or_else(|| anyhow!("internal: bad reference time"))?;
        for _ in 0..SCHEDULE_SAMPLES {
            let next = cron.find_next_occurrence(&at, false).map_err(|e| {
                anyhow!(
                    "backup schedule '{}' has no next occurrence after {at}: {e}",
                    self.schedule
                )
            })?;
            if (next - at).num_minutes() < MIN_BACKUP_INTERVAL_MINUTES as i64 {
                bail!(
                    "backup schedule '{}' fires more often than every \
                     {MIN_BACKUP_INTERVAL_MINUTES} minutes — each run stores a full copy of the \
                     app's data",
                    self.schedule
                );
            }
            at = next;
        }
        Ok(())
    }
}

/// How many consecutive occurrences [`BackupPolicy::validate_frequency`]
/// inspects. Enough to catch a pattern that is dense in one part of the day
/// and sparse elsewhere, without walking a year of a rare expression.
const SCHEDULE_SAMPLES: usize = 24;

/// Closest two scheduled runs may be. A full copy of the app's data is stored
/// per run, so this is a storage floor, not a scheduling nicety.
pub const MIN_BACKUP_INTERVAL_MINUTES: u32 = 60;

/// Runs kept for an app whose `backup:` policy does not say.
pub const DEFAULT_BACKUP_RETENTION: u32 = 7;

/// Most runs an app may retain. Each retained run holds a full copy of every
/// backed-up volume, so retention is storage the customer did not buy; a
/// customer who wants a deeper history downloads the artifacts.
pub const MAX_BACKUP_RETENTION: u32 = 30;

/// A single service/container within an app.
#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    /// Container image reference.
    pub image: String,
    /// Exposed/served ports.
    #[serde(default)]
    pub ports: Vec<Port>,
    /// Environment variables (values may contain `${…}` references).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Persistent volumes → PVCs.
    #[serde(default)]
    pub volumes: Vec<Volume>,
    /// Writable-but-throwaway paths → `emptyDir`. See [`Scratch`].
    #[serde(default)]
    pub scratch: Vec<Scratch>,
    /// Advisory startup ordering hints (k8s has no hard ordering; apps retry).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Config files injected read-only into the container (ConfigMap/Secret),
    /// separate from `volumes` (which are read-write PVCs for app data).
    #[serde(default)]
    pub files: Vec<File>,
    /// Requested CPU/memory for this service (drives k8s requests/limits and the
    /// app's capacity footprint). Defaults apply when omitted.
    #[serde(default)]
    pub resources: Resources,
    /// Optional backup method for this service's data.
    #[serde(default)]
    pub backup: Option<Backup>,
    /// Run the container as this user. Accepts either:
    ///
    /// - `"root"` / `"0"` — for images whose entrypoint must *start* as root
    ///   and drop privileges itself (e.g. `mariadb`, `postgres`, `redis`); the
    ///   operator then omits `runAsNonRoot` for this container only.
    /// - a numeric UID (e.g. `"1000"`) — required for images whose Dockerfile
    ///   `USER` is a *name* rather than a number (e.g. `USER nonroot`). The
    ///   kubelet enforces `runAsNonRoot` by reading the image config's user
    ///   field and cannot resolve a name to a UID, so such an image fails to
    ///   start with "container has runAsNonRoot and image has non-numeric user
    ///   ... cannot verify user is non-root" unless an explicit `runAsUser` is
    ///   supplied. The value is also used as the pod's `fsGroup` so mounted
    ///   volumes are writable by that user.
    ///
    /// Omit for images whose `USER` is already numeric — the default non-root
    /// hardening then applies unchanged. Only curated catalog apps can set
    /// this; it is not customer-controlled at order time.
    #[serde(default)]
    pub user: Option<String>,
    /// One-shot containers run to completion, in order, before this service's
    /// own container starts. See [`InitContainer`].
    #[serde(default)]
    pub init: Vec<InitContainer>,
}

/// A setup step that must succeed before its service's container starts.
///
/// A compose service is otherwise `image` + `env` + `ports` + `volumes` +
/// `files` — no `command`, no init hook — so a deployment could not perform a
/// setup step that the image does not do on its own entrypoint (#244). Object
/// storage is the case that breaks on it: an S3 server starts empty, and a
/// consumer that expects its bucket to exist dies on `NoSuchBucket` rather
/// than creating it.
///
/// This renders as a Kubernetes init container in the **consuming** service's
/// pod, which is also what supplies the gate: the kubelet does not start the
/// service's container until every init container has exited 0, and restarts a
/// failed one. Bootstrapping a *peer* service therefore belongs on the
/// consumer, not on the peer — a bucket cannot be created in a server that has
/// not started, and the consumer is the pod that must not run without it.
///
/// The step sees exactly what the service's own container sees (its volumes,
/// its config files) plus a writable `/tmp`, and runs under the same non-root
/// hardening.
#[derive(Debug, Clone, Deserialize)]
pub struct InitContainer {
    /// Step name; becomes the init container name, so a DNS-style slug unique
    /// within the service.
    pub name: String,
    /// Container image reference.
    pub image: String,
    /// Entrypoint override. Omit to use the image's own.
    ///
    /// Catalog text only: `${…}` is **not** substituted here, because a
    /// customer-supplied `config` value interpolated into a shell string is an
    /// injection. Pass values through `env` and reference them as shell
    /// variables from a script the catalog author wrote.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Arguments to the entrypoint. Same no-`${…}` rule as `command`.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// Environment variables (values may contain `${…}` references, resolved
    /// exactly like a service's `env`).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Requested CPU/memory. Defaults to [`INIT_DEFAULT_CPU`] /
    /// [`INIT_DEFAULT_MEMORY`] rather than the service defaults: a setup step
    /// is normally tiny, and a pod is scheduled as
    /// `max(init, sum(containers))`, so a small step never raises the app's
    /// footprint.
    #[serde(default)]
    pub resources: Option<Resources>,
    /// Run this step as a specific user, same grammar as a service's `user:`.
    /// Defaults to the service's own `user:` — the step normally writes into
    /// that service's volumes.
    #[serde(default)]
    pub user: Option<String>,
}

/// An [`InitContainer`] with its `env` `${…}` references substituted and its
/// defaults (resources, user) filled in from the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInit {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
    /// Sorted, so a reconcile renders byte-identical env on every pass.
    pub env: std::collections::BTreeMap<String, String>,
    pub resources: Resources,
    /// Effective `user:` (the step's own, else the service's).
    pub user: Option<String>,
}

impl ResolvedInit {
    /// Whether this step must start as root (compose `user: root` / `0`).
    pub fn runs_as_root(&self) -> bool {
        user_is_root(self.user.as_deref())
    }

    /// The explicit numeric UID this step runs as, if any.
    pub fn run_as_user(&self) -> Option<i64> {
        user_uid(self.user.as_deref())
    }
}

/// Default CPU for an init step that declares no `resources:`.
pub const INIT_DEFAULT_CPU: &str = "50m";
/// Default memory for an init step that declares no `resources:`.
pub const INIT_DEFAULT_MEMORY: &str = "64Mi";

/// Whether a compose `user:` value means "start as root".
fn user_is_root(user: Option<&str>) -> bool {
    matches!(user, Some("root") | Some("0"))
}

/// The positive numeric UID a compose `user:` names, if it names one.
fn user_uid(user: Option<&str>) -> Option<i64> {
    match user?.parse::<i64>() {
        Ok(uid) if uid > 0 => Some(uid),
        _ => None,
    }
}

impl Service {
    /// Whether this service must start as root (compose `user: root` / `0`).
    pub fn runs_as_root(&self) -> bool {
        user_is_root(self.user.as_deref())
    }

    /// The explicit numeric UID this service runs as, if the compose specifies
    /// one. `None` for `user: root` (handled by [`Self::runs_as_root`]) and
    /// when no user is set.
    ///
    /// Doubles as the pod's `fsGroup`: a container user's primary group
    /// conventionally matches its UID, and without it a fresh PVC mounts
    /// root-owned `0755` and the non-root process cannot write to it.
    pub fn run_as_user(&self) -> Option<i64> {
        user_uid(self.user.as_deref())
    }
}

/// Default `Resources` for an init step, used when it declares none.
fn init_default_resources() -> Resources {
    Resources {
        cpu: INIT_DEFAULT_CPU.to_string(),
        memory: INIT_DEFAULT_MEMORY.to_string(),
    }
}

/// A service's requested CPU and memory. Kubernetes-style quantities: CPU as
/// cores or millicores (`"1"`, `"500m"`), memory with binary/SI suffixes
/// (`"512Mi"`, `"2Gi"`, `"1G"`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Resources {
    #[serde(default = "default_cpu")]
    pub cpu: String,
    #[serde(default = "default_memory")]
    pub memory: String,
}

fn default_cpu() -> String {
    "250m".to_string()
}

fn default_memory() -> String {
    "256Mi".to_string()
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cpu: default_cpu(),
            memory: default_memory(),
        }
    }
}

/// An app's total resource footprint, summed across its services and volumes,
/// used for cluster capacity accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Footprint {
    /// CPU in millicores (e.g. `1500` = 1.5 cores).
    pub cpu_milli: u64,
    /// Memory in bytes.
    pub memory_bytes: u64,
    /// Persistent storage in bytes (sum of `volumes[].size`).
    pub storage_bytes: u64,
}

/// One service's resource contribution to the [`Footprint`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceFootprint {
    /// Compose service name.
    pub name: String,
    /// CPU in millicores.
    pub cpu_milli: u64,
    /// Memory in bytes.
    pub memory_bytes: u64,
    /// Persistent storage in bytes (sum of this service's `volumes[].size`).
    pub storage_bytes: u64,
}

/// A config file injected into a container (rendered into a ConfigMap, or a
/// Secret when `sensitive`) and mounted **read-only** at `path` via `subPath`
/// so it drops in as a single file without shadowing the directory.
///
/// Exactly one content source is used: an inline templated `content` (with
/// `${…}` filled from `config`/`secrets`), or `content_from` a `config` field
/// (e.g. `type: file`) whose value the customer supplies verbatim.
#[derive(Debug, Clone, Deserialize)]
pub struct File {
    /// Absolute in-container mount path.
    pub path: String,
    /// Inline templated file content.
    #[serde(default)]
    pub content: Option<String>,
    /// Name of a `config` field whose value is used as the file content.
    #[serde(default)]
    pub content_from: Option<String>,
    /// Render into a Secret instead of a ConfigMap (holds secret material).
    #[serde(default)]
    pub sensitive: bool,
}

/// How a port is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expose {
    /// Internal only (ClusterIP Service). Default.
    #[default]
    None,
    /// Public HTTP(S) via nginx Ingress + cert-manager TLS (http protocol only).
    Ingress,
    /// Raw L4 TCP (ingress-controller TCP passthrough / NodePort). Not in MVP.
    Tcp,
    /// Raw L4 UDP. Not in MVP.
    Udp,
}

/// Wire protocol of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    #[default]
    Tcp,
    Udp,
}

/// A service port.
#[derive(Debug, Clone, Deserialize)]
pub struct Port {
    /// Port name (used for the k8s Service port and ingress backend).
    pub name: String,
    /// Container port number.
    pub container: u16,
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(default)]
    pub expose: Expose,
    /// Ingress path (defaults to `/`), only meaningful for `expose: ingress`.
    #[serde(default)]
    pub path: Option<String>,
}

/// A persistent volume mounted into a service → one PVC.
#[derive(Debug, Clone, Deserialize)]
pub struct Volume {
    /// Volume name (becomes the PVC name suffix; must be a slug).
    pub name: String,
    /// Absolute mount path inside the container.
    pub path: String,
    /// Requested size, e.g. `5Gi`.
    pub size: String,
    /// What a buyer gets from this volume, in their words: `events`, `media`,
    /// `database` (issue #260).
    ///
    /// Optional, and authored per app rather than inferred, because the name
    /// carries no meaning that generalises: `db` is HAVEN's event store and
    /// route96's MySQL, `data` is Pyramid's events and Buzz's Postgres, and
    /// Buzz declares two different volumes both called `data`. Only the app
    /// definition knows what a volume is *for*, so only it can say.
    ///
    /// Leave it off for volumes a buyer does not think about (`run`, `packs`):
    /// an unlabelled volume is reported with its size and no label, and an app
    /// with no labels at all just reports its total, so nothing has to be
    /// backfilled.
    #[serde(default)]
    pub label: Option<String>,
}

/// Longest accepted volume label. A label is a noun a price card renders
/// beside a size ("20 GB media"), not a sentence — bounded here so a catalog
/// author cannot put a paragraph on a buyer's screen.
pub const MAX_VOLUME_LABEL_LEN: usize = 40;

/// A writable throwaway path inside a service's container → one `emptyDir`
/// (issue #264).
///
/// Every container runs with a read-only root filesystem, so the only writable
/// paths are the declared `volumes`. That is right for app data and wrong for
/// the runtime scratch an image needs before it has done anything worth
/// keeping: `mariadb` writes InnoDB's temporary files under `/tmp` and its pid
/// file and unix socket under `/run/mysqld`, `postgres` its lock file and
/// socket under `/var/run/postgresql`. Without a writable path for those the
/// process exits on startup — which is not a per-app quirk to work around but
/// the normal shape of a database image.
///
/// A PVC for a socket directory is the wrong instrument: it is billed, backed
/// up, counted against the app's storage footprint, and it survives a restart
/// carrying a stale pid file. An `emptyDir` is none of those — it is created
/// empty with the pod and discarded with it, which is exactly what a runtime
/// directory wants.
///
/// It is declared per path rather than mounted blindly at `/tmp` because the
/// paths differ per image (`/run/mysqld` vs `/var/run/postgresql`) and because
/// a writable path a catalog author did not ask for is a place for an app to
/// silently accumulate state that no backup covers.
#[derive(Debug, Clone, Deserialize)]
pub struct Scratch {
    /// Absolute mount path inside the container.
    pub path: String,
    /// Upper bound on what the app may write there, e.g. `256Mi`. Defaults to
    /// [`DEFAULT_SCRATCH_SIZE`] and may not exceed [`MAX_SCRATCH_BYTES`].
    ///
    /// An `emptyDir` is backed by the node's own disk, which is shared by every
    /// tenant on that node, so it is bounded: the kubelet evicts a pod that
    /// exceeds its `sizeLimit` rather than letting one app fill the node.
    #[serde(default)]
    pub size: Option<String>,
}

impl Scratch {
    /// Declared size, or [`DEFAULT_SCRATCH_SIZE`].
    pub fn size_or_default(&self) -> &str {
        self.size.as_deref().unwrap_or(DEFAULT_SCRATCH_SIZE)
    }
}

/// Size of a `scratch:` path that does not declare one. Enough for a database
/// image's socket, pid file and small temporary files; an app that needs more
/// than this is asking for storage, not scratch.
pub const DEFAULT_SCRATCH_SIZE: &str = "256Mi";

/// Largest accepted `scratch:` size (1 GiB). Node-local disk is shared with
/// every other tenant on the node and is not what a customer bought — anything
/// bigger belongs in a `volume`, where it is sized, billed and backed up.
pub const MAX_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024;

/// The capabilities a "start as root, then drop privileges" entrypoint needs
/// after dropping `ALL` (issue #263).
///
/// `SETGID`/`SETUID` are what `gosu`/`su-exec` costs when the entrypoint drops
/// to its service account — the first thing that fails without them, with
/// mariadb's `error: failed switching to 'mysql': operation not permitted`.
/// `CHOWN`/`DAC_OVERRIDE`/`FOWNER` are what the `chown -R` of a freshly
/// provisioned, root-owned data directory costs, which is the step after it.
/// Dropping to a lower UID is not privilege escalation, so no-new-privileges
/// stays set alongside them.
///
/// All five are on the Kubernetes **baseline** Pod Security Standard
/// allow-list, which is the standard a deployment containing a root service
/// already runs under.
///
/// It lives here, in the grammar crate, because two renderers have to agree on
/// it: the operator's container SecurityContext and `compose-to-docker`'s
/// `cap_add` (issue #268). A local run that granted a different set would
/// reproduce a different bug from the one the cluster has.
pub const ROOT_ENTRYPOINT_CAPABILITIES: [&str; 5] =
    ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"];

/// One persistent volume of an app, resolved for display: which service it
/// belongs to, what it is for, and how big it is (issue #260).
///
/// The sizes sum to the app's total `storage_bytes`, so a client can render a
/// breakdown that adds up to the number it already shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Compose service the volume is mounted into. Carried because a volume
    /// name is only unique within its service — Buzz has two called `data`.
    pub service: String,
    /// Compose volume name. Internal, not buyer-facing: prefer `label`.
    pub name: String,
    /// Buyer-facing purpose, when the app declares one.
    pub label: Option<String>,
    /// Size in bytes, parsed from the compose quantity.
    pub size_bytes: u64,
}

/// Default generated-secret length in bytes. Hex-encoded, so 48 characters.
pub const DEFAULT_SECRET_BYTES: usize = 24;
/// Accepted range for an explicitly declared secret length.
pub const MIN_SECRET_BYTES: usize = 16;
pub const MAX_SECRET_BYTES: usize = 64;

/// An operator-generated secret.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretDecl {
    /// Env var name the generated value is bound to (referenced as `${name}`).
    pub name: String,
    /// How to generate it.
    #[serde(default)]
    pub generate: Generate,
    /// Length of the generated value in **bytes**, hex-encoded into twice as
    /// many characters. Defaults to [`DEFAULT_SECRET_BYTES`].
    ///
    /// A password only needs enough entropy, but a key of an exact size — a
    /// 32-byte Nostr secret key, an AES key, a fixed-width signing secret —
    /// cannot be expressed by the default, and an app fed the wrong width
    /// fails at startup rather than at deploy time.
    #[serde(default)]
    pub bytes: Option<usize>,
}

impl SecretDecl {
    /// Declared length in bytes, or the default when unset.
    pub fn byte_len(&self) -> usize {
        self.bytes.unwrap_or(DEFAULT_SECRET_BYTES)
    }
}

/// Secret generation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Generate {
    /// A random URL-safe password.
    #[default]
    Password,
    /// A random hex token.
    Token,
}

/// A customer-provided config field (rendered as a form input).
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigField {
    /// Env var name (referenced as `${name}`).
    pub name: String,
    /// Human-readable form label.
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub r#type: FieldType,
    /// Default value when the customer leaves it blank.
    #[serde(default)]
    pub default: Option<String>,
    /// Whether the field must be supplied.
    #[serde(default)]
    pub required: bool,
    /// Regex the submitted value must match in full (issue #271).
    ///
    /// `type:` covers what a form input can check — an integer, a boolean — and
    /// nothing else. Most catalog fields are a `string` whose shape the app
    /// depends on: HAVEN takes an `owner_npub` and *panics* on anything that is
    /// not one, so a mistyped character was accepted at order time and became a
    /// crashlooping deployment the customer had already paid for. A pattern is
    /// the smallest thing that closes that, and it generalises — the next app
    /// wants a domain, a URL or a hex key, each of which would otherwise be
    /// another `FieldType` variant.
    ///
    /// Anchored automatically: the value must match end to end, so a pattern
    /// cannot accidentally admit a value with the right prefix. Compiled at
    /// app-create time, so a pattern that does not compile is rejected there
    /// rather than at a customer's order. Ignored for `type: file`, whose
    /// content is arbitrary.
    #[serde(default)]
    pub pattern: Option<String>,
}

/// Longest accepted `pattern`. Long enough for the character-class patterns a
/// catalog field needs (an npub, a domain, a hex key) and short enough that the
/// admin API is not a place to paste a program.
pub const MAX_PATTERN_LEN: usize = 200;

impl ConfigField {
    /// The label a customer sees, falling back to the field name.
    ///
    /// Error messages use this: the customer typed into a box labelled "Owner
    /// npub", and telling them `owner_npub` is wrong makes them hunt for it.
    pub fn display_label(&self) -> &str {
        match self.label.as_deref() {
            Some(l) if !l.trim().is_empty() => l,
            _ => &self.name,
        }
    }

    /// Check one submitted value against this field's declared type and
    /// pattern. `Ok(())` when the value is usable.
    ///
    /// Called for a customer's submitted value *and* for a declared `default`
    /// at app-create time — a default that its own field would reject is a
    /// broken app definition, and it fails at order time for whoever leaves the
    /// field blank rather than for the person who authored it.
    pub fn check_value(&self, value: &str) -> Result<()> {
        let label = self.display_label();
        match self.r#type {
            FieldType::Int => {
                if value.trim().parse::<i64>().is_err() {
                    bail!("config field '{label}' must be a whole number (got '{value}')");
                }
            }
            FieldType::Bool => {
                if !matches!(value.trim(), "true" | "false") {
                    bail!("config field '{label}' must be true or false (got '{value}')");
                }
            }
            // A string is unconstrained unless the app says otherwise, and a
            // file is arbitrary content by definition.
            FieldType::String | FieldType::File => {}
        }
        if let Some(pattern) = &self.pattern
            && self.r#type != FieldType::File
        {
            let re =
                compile_pattern(pattern).map_err(|e| anyhow!("config field '{label}': {e}"))?;
            if !re.is_match(value) {
                bail!("config field '{label}' has the wrong format (expected: {pattern})");
            }
        }
        Ok(())
    }
}

/// Compile a `pattern` into a fully-anchored regex.
///
/// Anchoring is not the author's job: `npub1…` without `^…$` silently accepts a
/// value with junk on either end, and that is exactly the mistake that produces
/// a crashlooping deployment. The pattern is wrapped rather than rewritten, so
/// an author's own `^`/`$` stay valid and mean the same thing.
///
/// The `regex` crate has no backtracking, so a catalog pattern cannot be made
/// to hang the API on a crafted input; the length bound keeps the declaration
/// readable, it is not a safety measure.
fn compile_pattern(pattern: &str) -> Result<regex::Regex> {
    if pattern.trim().is_empty() {
        bail!("pattern is empty — omit it instead");
    }
    if pattern.len() > MAX_PATTERN_LEN {
        bail!("pattern must be at most {MAX_PATTERN_LEN} characters");
    }
    regex::Regex::new(&format!("^(?:{pattern})$"))
        .map_err(|e| anyhow!("pattern '{pattern}' is not a valid regex: {e}"))
}

/// Longest accepted `backup.artifact` filename.
const MAX_ARTIFACT_NAME_LEN: usize = 64;

/// A `backup.artifact` is a filename, not a path.
fn validate_artifact_name(service: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_ARTIFACT_NAME_LEN {
        bail!(
            "service '{service}': backup artifact name must be 1-{MAX_ARTIFACT_NAME_LEN} characters"
        );
    }
    if name.starts_with('.') {
        bail!("service '{service}': backup artifact '{name}' must not start with a dot");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        bail!(
            "service '{service}': backup artifact '{name}' may only contain letters, digits, \
             '.', '-' and '_'"
        );
    }
    Ok(())
}

/// Config field input type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    #[default]
    String,
    Int,
    Bool,
    /// Multiline free-form content, typically referenced by a file's
    /// `content_from` to let the customer supply a whole config file.
    File,
}

/// A service's backup method.
#[derive(Debug, Clone, Deserialize)]
pub struct Backup {
    /// App-consistent dump command; stdout is captured as the artifact.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Alternatively, raw tar of this named volume (append-only data only).
    #[serde(default)]
    pub volume: Option<String>,
    /// Suggested artifact filename.
    #[serde(default)]
    pub artifact: Option<String>,
}

impl Compose {
    /// Parse an app compose document from YAML.
    pub fn parse(yaml: &str) -> Result<Self> {
        let c: Compose =
            serde_yaml_ng::from_str(yaml).map_err(|e| anyhow!("invalid compose YAML: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Values the operator supplies itself, so they need no `config:` entry.
    pub const BUILTIN_VARS: &'static [&'static str] = &["HOSTNAME"];

    /// Declared config defaults, for seeding a substitution map so a field the
    /// deployment never supplied renders as its default rather than blank.
    pub fn config_defaults(&self) -> std::collections::BTreeMap<String, String> {
        self.config
            .iter()
            .filter_map(|f| f.default.clone().map(|d| (f.name.clone(), d)))
            .collect()
    }

    /// Every `${...}` must be declared in `config:`/`secrets:` or be a builtin.
    ///
    /// **An authoring rule, checked at admission only** — deliberately *not*
    /// part of [`Self::validate`], because the operator parses the stored
    /// compose on every reconcile: enforcing it there would take an already
    /// deployed app offline over a reference it cannot fix, which is exactly the
    /// failure this is meant to prevent. Substitution at reconcile time stays
    /// tolerant (missing -> declared default -> empty).
    ///
    /// Call this wherever a compose is *authored* (admin create/update, the
    /// `compose-validate` CLI) so a typo or a newly added reference is caught
    /// while a human can still fix it.
    pub fn validate_declarations(&self) -> Result<()> {
        // A service addressed as `name:port` by another service must declare a
        // port (issue #281).
        //
        // `build_service` is the only thing that gives a compose service a DNS
        // name inside the namespace, and it renders nothing for a service with
        // no `ports:`. So `postgres://buzz:pw@db:5432/buzz` in the relay's env,
        // with a `db` service that declares no ports, is a name that does not
        // resolve — which is how the Buzz app reached production and failed
        // with "Name or service not known" on its first connection.
        //
        // Only in-document names are checked: an external `redis.example.com`
        // is not a compose service and is nothing to do with us.
        for (sname, svc) in &self.services {
            // Everywhere a service can name a peer: its own env, its inline
            // file contents, and its init steps' env (the setup step that waits
            // for a peer is exactly this pattern).
            let mut texts: Vec<&str> = svc.env.values().map(String::as_str).collect();
            for f in &svc.files {
                if let Some(c) = &f.content {
                    texts.push(c.as_str());
                }
            }
            for init in &svc.init {
                texts.extend(init.env.values().map(String::as_str));
            }
            for (target, tsvc) in &self.services {
                if target == sname || !tsvc.ports.is_empty() {
                    continue;
                }
                if !texts.iter().any(|t| addresses_host(t, target)) {
                    continue;
                }
                bail!(
                    "service '{sname}' addresses '{target}:<port>', but service '{target}' \
                     declares no `ports:` — the operator only creates a Service (and therefore a \
                     DNS name) for a service with declared ports, so that hostname will not \
                     resolve. Add an internal port block to '{target}', e.g. \
                     `ports: [{{ name: {target}, container: <port>, protocol: tcp, expose: none }}]`"
                );
            }
        }

        // A declared `default` must satisfy its own field (#271): an `int`
        // defaulting to "abc" fails at order time for whoever leaves the box
        // blank, which is a customer paying for the author's typo. Authoring-
        // time only, like the rest of this function — a row stored before the
        // rule existed keeps rendering, and is caught the next time an admin
        // edits it.
        for f in &self.config {
            if let Some(default) = &f.default {
                f.check_value(default)
                    .map_err(|e| anyhow!("config field '{}': default is invalid: {e}", f.name))?;
            }
        }
        // A fresh PVC is chowned to the pod's fsGroup, which comes from a
        // numeric `user:`; volumes plus silence is the unwritable combination.
        for (sname, svc) in &self.services {
            if !svc.volumes.is_empty() && svc.user.is_none() {
                bail!(
                    "service '{sname}': declares volumes but no `user:` — a fresh PVC is chowned \
                     to the pod's fsGroup, which comes from a numeric `user:`, so without one the \
                     volume mounts root-owned 0755 and a non-root image cannot write to it. Set \
                     the image's numeric UID (`docker inspect -f '{{{{.Config.User}}}}' <image>`), \
                     or `user: root` if its entrypoint starts as root."
                );
            }
        }
        for name in self.referenced_vars() {
            let declared = self.config.iter().any(|c| c.name == name)
                || self.secrets.iter().any(|s| s.name == name)
                || Self::BUILTIN_VARS.contains(&name.as_str());
            if !declared {
                bail!(
                    "'${{{name}}}' is referenced but not declared — add it to the `config:` list \
                     (or `secrets:`), or remove the reference. Built-ins: {}",
                    Self::BUILTIN_VARS.join(", ")
                );
            }
        }
        Ok(())
    }

    /// Check this compose against the one it would replace: a persistent
    /// volume may grow, but it may not shrink, vanish or be renamed.
    ///
    /// An authoring rule, checked at admission only, like
    /// [`Self::validate_declarations`]: a row that already violates it has to
    /// keep reconciling rather than disappear.
    ///
    /// Volumes are matched on `(service, volume name)` — the PVC identity the
    /// operator builds — and compared in bytes, so a change of unit alone
    /// passes. An unparseable *previous* document is the caller's problem, not
    /// this function's.
    pub fn validate_volume_changes(&self, previous: &Compose) -> Result<()> {
        for (sname, prev_svc) in &previous.services {
            for prev in &prev_svc.volumes {
                let prev_bytes = parse_bytes(&prev.size).map_err(|e| {
                    anyhow!("stored service '{sname}': volume '{}': {e}", prev.name)
                })?;
                let current = self
                    .services
                    .get(sname)
                    .and_then(|s| s.volumes.iter().find(|v| v.name == prev.name));
                let Some(current) = current else {
                    bail!(
                        "service '{sname}': volume '{}' is missing — the operator cannot prune \
                         a PVC it stops applying, so it would survive unmounted with the \
                         customer's data in it. A rename is a remove plus an add and orphans it \
                         the same way.",
                        prev.name
                    );
                };
                let bytes = parse_bytes(&current.size)
                    .map_err(|e| anyhow!("service '{sname}': volume '{}': {e}", current.name))?;
                if bytes < prev_bytes {
                    bail!(
                        "service '{sname}': volume '{}' shrinks from {} to {} — Kubernetes permits \
                         PVC expansion only, so every existing deployment of this app would fail \
                         to reconcile with a 422 until the size is put back. The floor checked \
                         here is this row's stored size; the real floor is whatever capacity the \
                         PVCs were provisioned at, which can be larger if the row was lowered \
                         before this rule existed.",
                        current.name,
                        prev.size.trim(),
                        current.size.trim()
                    );
                }
            }
        }
        Ok(())
    }

    /// Validate structural + policy rules. Enforced at parse time so the
    /// operator never tries to render an unsafe or malformed app.
    ///
    /// Note this does **not** check that `${...}` references are declared — see
    /// [`Self::validate_declarations`].
    pub fn validate(&self) -> Result<()> {
        if self.services.is_empty() {
            bail!("compose must define at least one service");
        }

        for (sname, svc) in &self.services {
            if svc.image.trim().is_empty() {
                bail!("service '{sname}': image is required");
            }
            for p in &svc.ports {
                // Ingress is HTTP only (WebSocket rides HTTP → wss).
                if p.expose == Expose::Ingress && p.protocol != Protocol::Http {
                    bail!(
                        "service '{sname}' port '{}': expose: ingress requires protocol: http",
                        p.name
                    );
                }
            }
            // `user:` must be root or a numeric UID. A name (e.g. `nonroot`)
            // is rejected here rather than at runtime: the kubelet cannot
            // resolve a name against the image, so under `runAsNonRoot` the
            // pod would fail to start with "image has non-numeric user" and
            // retry for minutes with no signal to whoever added the app.
            if let Some(u) = svc.user.as_deref()
                && !svc.runs_as_root()
                && svc.run_as_user().is_none()
            {
                bail!(
                    "service '{sname}': user '{u}' must be \"root\", \"0\", or a positive numeric UID \
                     (a user *name* cannot be verified by the kubelet under runAsNonRoot — use the \
                     numeric UID from the image's /etc/passwd)"
                );
            }
            for v in &svc.volumes {
                validate_mount_path(sname, &v.name, &v.path)?;
                if let Some(label) = &v.label {
                    let l = label.trim();
                    if l.is_empty() {
                        bail!(
                            "service '{sname}': volume '{}': label is empty — omit it instead",
                            v.name
                        );
                    }
                    if l.chars().count() > MAX_VOLUME_LABEL_LEN {
                        bail!(
                            "service '{sname}': volume '{}': label must be at most \
                             {MAX_VOLUME_LABEL_LEN} characters",
                            v.name
                        );
                    }
                }
            }
            // Scratch paths: absolute, bounded, and not overlapping anything
            // that holds data. A scratch mount that shadowed a volume would
            // hide the customer's data behind an empty directory on every
            // restart, and the app would look like it had lost it.
            for (i, s) in svc.scratch.iter().enumerate() {
                check_abs_no_traversal(sname, "scratch", &s.path)?;
                let bytes = parse_bytes(s.size_or_default())
                    .map_err(|e| anyhow!("service '{sname}': scratch '{}': {e}", s.path))?;
                if bytes == 0 {
                    bail!(
                        "service '{sname}': scratch '{}': size must be non-zero",
                        s.path
                    );
                }
                if bytes > MAX_SCRATCH_BYTES {
                    bail!(
                        "service '{sname}': scratch '{}': size exceeds {MAX_SCRATCH_BYTES} bytes \
                         — a path that needs more than that is a volume, not scratch",
                        s.path
                    );
                }
                for v in &svc.volumes {
                    if s.path == v.path || path_is_within(&s.path, &v.path) {
                        bail!(
                            "service '{sname}': scratch '{}' is inside data volume '{}' — it would \
                             shadow persisted data with an empty directory",
                            s.path,
                            v.path
                        );
                    }
                    if path_is_within(&v.path, &s.path) {
                        bail!(
                            "service '{sname}': data volume '{}' is inside scratch '{}' — the \
                             volume's data would not survive a restart",
                            v.path,
                            s.path
                        );
                    }
                }
                for other in svc.scratch.iter().skip(i + 1) {
                    if s.path == other.path {
                        bail!("service '{sname}': duplicate scratch path '{}'", s.path);
                    }
                    if path_is_within(&s.path, &other.path) || path_is_within(&other.path, &s.path)
                    {
                        bail!(
                            "service '{sname}': scratch '{}' and '{}' are nested",
                            s.path,
                            other.path
                        );
                    }
                }
            }
            // depends_on must reference real services.
            for dep in &svc.depends_on {
                if !self.services.contains_key(dep) {
                    bail!("service '{sname}': depends_on unknown service '{dep}'");
                }
            }
            // Config files: valid path, single content source, size-bounded,
            // and not overlapping a data volume.
            for f in &svc.files {
                check_abs_no_traversal(sname, "file", &f.path)?;
                match (&f.content, &f.content_from) {
                    (Some(_), Some(_)) => {
                        bail!(
                            "service '{sname}': file '{}' has both content and content_from",
                            f.path
                        )
                    }
                    (None, None) => {
                        bail!(
                            "service '{sname}': file '{}' needs content or content_from",
                            f.path
                        )
                    }
                    (Some(c), None) => {
                        if c.len() > MAX_FILE_BYTES {
                            bail!(
                                "service '{sname}': file '{}' content exceeds {MAX_FILE_BYTES} bytes",
                                f.path
                            );
                        }
                    }
                    (None, Some(field)) => {
                        if !self.config.iter().any(|cf| &cf.name == field) {
                            bail!(
                                "service '{sname}': file '{}' content_from references unknown config field '{field}'",
                                f.path
                            );
                        }
                    }
                }
                // A config file must not land inside a read-write data volume.
                for v in &svc.volumes {
                    if f.path == v.path || path_is_within(&f.path, &v.path) {
                        bail!(
                            "service '{sname}': file '{}' overlaps data volume mount '{}'",
                            f.path,
                            v.path
                        );
                    }
                }
                // Nor inside a scratch path: the file is mounted read-only and
                // the scratch directory is emptied on every restart, so which
                // one wins is a question a catalog author should not have to
                // ask.
                for s in &svc.scratch {
                    if f.path == s.path || path_is_within(&f.path, &s.path) {
                        bail!(
                            "service '{sname}': file '{}' overlaps scratch path '{}'",
                            f.path,
                            s.path
                        );
                    }
                }
            }

            // A backup entry is exactly one of command | volume, and the
            // artifact name is a filename we control the shape of (it becomes
            // the tail of an object key).
            if let Some(b) = &svc.backup {
                match (&b.command, &b.volume) {
                    (Some(_), Some(_)) => {
                        bail!("service '{sname}': backup has both command and volume")
                    }
                    (None, None) => {
                        bail!("service '{sname}': backup needs either command or volume")
                    }
                    (None, Some(vol)) => {
                        if !svc.volumes.iter().any(|v| &v.name == vol) {
                            bail!("service '{sname}': backup volume '{vol}' is not declared");
                        }
                    }
                    _ => {}
                }
                // The artifact name is appended to a server-derived object key
                // and shown as a download filename, so it is a plain filename:
                // no directory separators, no traversal, no leading dot.
                if let Some(a) = &b.artifact {
                    validate_artifact_name(sname, a)?;
                }
            }

            // Init steps: a name we can render, something to run, and no
            // `${…}` in the command — an interpolated customer config value
            // there would be shell injection, so values go through `env`.
            for (i, init) in svc.init.iter().enumerate() {
                validate_init_name(sname, &init.name)?;
                if svc.init[..i].iter().any(|o| o.name == init.name) {
                    bail!(
                        "service '{sname}': duplicate init step '{}' — names become container \
                         names and must be unique within the service",
                        init.name
                    );
                }
                if init.image.trim().is_empty() {
                    bail!("service '{sname}': init '{}': image is required", init.name);
                }
                for (field, argv) in [("command", &init.command), ("args", &init.args)] {
                    let Some(argv) = argv else { continue };
                    if argv.is_empty() {
                        bail!(
                            "service '{sname}': init '{}': {field} is empty — omit it to use the \
                             image's own",
                            init.name
                        );
                    }
                    if argv.iter().any(|a| !extract_refs(a).is_empty()) {
                        bail!(
                            "service '{sname}': init '{}': {field} must not contain '${{…}}' — a \
                             customer-supplied value interpolated into a command is injectable; \
                             put it in the step's `env:` and read it as a shell variable",
                            init.name
                        );
                    }
                }
                if let Some(u) = init.user.as_deref()
                    && !user_is_root(Some(u))
                    && user_uid(Some(u)).is_none()
                {
                    bail!(
                        "service '{sname}': init '{}': user '{u}' must be \"root\", \"0\", or a \
                         positive numeric UID",
                        init.name
                    );
                }
            }
        }

        // A declared secret length must be usable. Checked at authoring time
        // because the failure mode otherwise is an app that starts, rejects its
        // own key and crash-loops — long after whoever typed the number left.
        for s in &self.secrets {
            if let Some(bytes) = s.bytes
                && !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&bytes)
            {
                bail!(
                    "secret '{}': bytes must be between {MIN_SECRET_BYTES} and {MAX_SECRET_BYTES} \
                     (got {bytes})",
                    s.name
                );
            }
        }

        // A declared `pattern` must compile (#271). Safe to enforce here, where
        // the operator also runs it, because the field is new: no stored row
        // can carry one that predates the rule.
        for f in &self.config {
            if let Some(pattern) = &f.pattern {
                compile_pattern(pattern).map_err(|e| anyhow!("config field '{}': {e}", f.name))?;
            }
        }

        // A schedule with nothing to run would bill storage and produce empty
        // runs forever, and reads in the catalog as if the app were protected.
        if let Some(policy) = &self.backup {
            if !self.services.values().any(|s| s.backup.is_some()) {
                bail!(
                    "backup schedule is set but no service declares a `backup:` method — there \
                     would be nothing to capture"
                );
            }
            let retention = policy.retention_or_default();
            if !(1..=MAX_BACKUP_RETENTION).contains(&retention) {
                bail!(
                    "backup retention must be between 1 and {MAX_BACKUP_RETENTION} (got \
                     {retention})"
                );
            }
            policy.validate_frequency()?;
        }
        Ok(())
    }

    /// Services that declare a backup method, in a stable order so a run's
    /// artifacts are created the same way every time.
    pub fn backup_services(&self) -> Vec<(&str, &Backup)> {
        let mut out: Vec<(&str, &Backup)> = self
            .services
            .iter()
            .filter_map(|(name, svc)| svc.backup.as_ref().map(|b| (name.as_str(), b)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(b.0));
        out
    }

    /// Every distinct env var name referenced as `${…}` across all services —
    /// in env values and in inline file `content` templates.
    pub fn referenced_vars(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let push = |val: &str, out: &mut Vec<String>| {
            for name in extract_refs(val) {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        };
        for svc in self.services.values() {
            for val in svc.env.values() {
                push(val, &mut out);
            }
            for f in &svc.files {
                if let Some(content) = &f.content {
                    push(content, &mut out);
                }
            }
            // An init step's env is `${…}` like any other value, and an
            // undeclared reference there fails the same way.
            for init in &svc.init {
                for val in init.env.values() {
                    push(val, &mut out);
                }
            }
        }
        out
    }

    /// Resolve every service's init steps: substitute their `env` and fill in
    /// the defaults each step inherits from its service. Keyed by service name,
    /// in declaration order (which is the order the kubelet runs them in).
    pub fn resolve_init(
        &self,
        vars: &HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<ResolvedInit>>> {
        let mut out = HashMap::new();
        for (sname, svc) in &self.services {
            if svc.init.is_empty() {
                continue;
            }
            let mut steps = Vec::with_capacity(svc.init.len());
            for init in &svc.init {
                let mut env = std::collections::BTreeMap::new();
                for (k, v) in &init.env {
                    env.insert(k.clone(), substitute(v, vars)?);
                }
                steps.push(ResolvedInit {
                    name: init.name.clone(),
                    image: init.image.clone(),
                    command: init.command.clone(),
                    args: init.args.clone(),
                    env,
                    resources: init
                        .resources
                        .clone()
                        .unwrap_or_else(init_default_resources),
                    user: init.user.clone().or_else(|| svc.user.clone()),
                });
            }
            out.insert(sname.clone(), steps);
        }
        Ok(out)
    }

    /// Resolve every service's env by substituting `${NAME}` from `vars`.
    ///
    /// `vars` is the merged map of generated secret values, resolved config
    /// values, and operator-provided context (e.g. `HOSTNAME`). A reference with
    /// no matching entry resolves to the empty string rather than failing — see
    /// [`substitute`] for why, and [`Compose::config_defaults`] for seeding
    /// declared defaults so a newly added field takes its default instead of a
    /// blank.
    pub fn resolve_env(
        &self,
        vars: &HashMap<String, String>,
    ) -> Result<HashMap<String, HashMap<String, String>>> {
        let mut out = HashMap::new();
        for (sname, svc) in &self.services {
            let mut resolved = HashMap::new();
            for (k, v) in &svc.env {
                resolved.insert(k.clone(), substitute(v, vars)?);
            }
            out.insert(sname.clone(), resolved);
        }
        Ok(out)
    }

    /// Resolve every service's config files to their final (path, content,
    /// sensitive) form: inline `content` has `${…}` substituted; `content_from`
    /// takes the customer-supplied value from `vars`. Errors on unknown refs.
    pub fn resolve_files(
        &self,
        vars: &HashMap<String, String>,
    ) -> Result<HashMap<String, Vec<ResolvedFile>>> {
        let mut out = HashMap::new();
        for (sname, svc) in &self.services {
            let mut files = Vec::new();
            for f in &svc.files {
                let content = match (&f.content, &f.content_from) {
                    (Some(c), _) => substitute(c, vars)?,
                    // Same tolerance as `substitute`: a value the deployment
                    // never supplied yields empty content rather than breaking
                    // the reconcile.
                    (_, Some(field)) => vars.get(field).cloned().unwrap_or_default(),
                    (None, None) => bail!("file '{}': no content source", f.path),
                };
                files.push(ResolvedFile {
                    path: f.path.clone(),
                    content,
                    sensitive: f.sensitive,
                });
            }
            out.insert(sname.clone(), files);
        }
        Ok(out)
    }

    /// Every persistent volume the app declares, with its purpose and size
    /// (issue #260).
    ///
    /// Sizes sum to [`Footprint::storage_bytes`], so a client can render a
    /// breakdown that adds up to the total it already shows. Ordered by service
    /// name, then by the order the volumes are declared in that service — an
    /// author who wants a particular volume read first writes it first. There
    /// is deliberately no "primary" flag: the two consumers this was built for
    /// (HAVEN's `events` + `media`, route96's `files` + `database`) both render
    /// every labelled volume, so a flag for "the main one" would be a second
    /// mechanism guessing at the same intent. Easy to add later; hard to
    /// retract once clients depend on it.
    ///
    /// Errors if any size quantity is malformed, exactly like
    /// [`Compose::service_footprints`].
    pub fn volumes(&self) -> Result<Vec<VolumeInfo>> {
        let mut names: Vec<&String> = self.services.keys().collect();
        names.sort();
        let mut out = Vec::new();
        for sname in names {
            let svc = &self.services[sname];
            for v in &svc.volumes {
                out.push(VolumeInfo {
                    service: sname.clone(),
                    name: v.name.clone(),
                    label: v.label.as_ref().map(|l| l.trim().to_string()),
                    size_bytes: parse_bytes(&v.size)
                        .map_err(|e| anyhow!("service '{sname}': volume '{}': {e}", v.name))?,
                });
            }
        }
        Ok(out)
    }

    /// Compute the app's total resource footprint: CPU/memory summed across all
    /// services' `resources`, plus storage summed across all `volumes[].size`.
    /// Errors if any quantity string is malformed.
    pub fn footprint(&self) -> Result<Footprint> {
        let mut f = Footprint::default();
        for s in self.service_footprints()? {
            f.cpu_milli += s.cpu_milli;
            f.memory_bytes += s.memory_bytes;
            f.storage_bytes += s.storage_bytes;
        }
        Ok(f)
    }

    /// Per-service resource breakdown (CPU / memory / storage), sorted by
    /// service name for a stable order. Sums to [`Compose::footprint`]. Each
    /// service contributes its `resources` (defaulted when omitted) plus the
    /// sizes of its `volumes`.
    ///
    /// An `init:` step contributes only when it asks for *more* than the
    /// service's own container: Kubernetes schedules a pod as
    /// `max(largest init container, sum of containers)`, so a small setup step
    /// costs nothing, and a large one is what the pod actually reserves.
    pub fn service_footprints(&self) -> Result<Vec<ServiceFootprint>> {
        let mut out = Vec::with_capacity(self.services.len());
        for (sname, svc) in &self.services {
            let mut cpu_milli = parse_cpu_milli(&svc.resources.cpu)
                .map_err(|e| anyhow!("service '{sname}': cpu: {e}"))?;
            let mut memory_bytes = parse_bytes(&svc.resources.memory)
                .map_err(|e| anyhow!("service '{sname}': memory: {e}"))?;
            for init in &svc.init {
                let r = init
                    .resources
                    .clone()
                    .unwrap_or_else(init_default_resources);
                cpu_milli =
                    cpu_milli.max(parse_cpu_milli(&r.cpu).map_err(|e| {
                        anyhow!("service '{sname}': init '{}': cpu: {e}", init.name)
                    })?);
                memory_bytes = memory_bytes.max(parse_bytes(&r.memory).map_err(|e| {
                    anyhow!("service '{sname}': init '{}': memory: {e}", init.name)
                })?);
            }
            let mut storage_bytes = 0u64;
            for v in &svc.volumes {
                storage_bytes += parse_bytes(&v.size)
                    .map_err(|e| anyhow!("service '{sname}': volume '{}': {e}", v.name))?;
            }
            out.push(ServiceFootprint {
                name: sname.clone(),
                cpu_milli,
                memory_bytes,
                storage_bytes,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// Parse a Kubernetes CPU quantity to millicores: `"500m"` → 500, `"2"` → 2000,
/// `"1.5"` → 1500.
pub fn parse_cpu_milli(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(m) = s.strip_suffix('m') {
        return m
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid cpu '{s}'"));
    }
    let cores: f64 = s.parse().map_err(|_| anyhow!("invalid cpu '{s}'"))?;
    if cores < 0.0 {
        bail!("negative cpu '{s}'");
    }
    Ok((cores * 1000.0).round() as u64)
}

/// Parse a Kubernetes memory/storage quantity to bytes. Supports binary
/// suffixes (`Ki`,`Mi`,`Gi`,`Ti`), decimal suffixes (`k`,`M`,`G`,`T`), and bare
/// byte counts.
pub fn parse_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult): (&str, u128) = if let Some(n) = s.strip_suffix("Ki") {
        (n, 1 << 10)
    } else if let Some(n) = s.strip_suffix("Mi") {
        (n, 1 << 20)
    } else if let Some(n) = s.strip_suffix("Gi") {
        (n, 1 << 30)
    } else if let Some(n) = s.strip_suffix("Ti") {
        (n, 1u128 << 40)
    } else if let Some(n) = s.strip_suffix('k') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix('G') {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix('T') {
        (n, 1_000_000_000_000)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid size '{s}'"))?;
    u64::try_from(n as u128 * mult).map_err(|_| anyhow!("size '{s}' overflows"))
}

/// Validate a deployment's instance `name` as a DNS-safe label usable as an
/// ingress subdomain. Shared by the customer and admin APIs.
pub fn validate_deployment_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() || n.len() > 40 {
        bail!("name must be 1–40 characters");
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || n.starts_with('-')
        || n.ends_with('-')
    {
        bail!("name must be a DNS-safe label (lowercase letters, digits, hyphens)");
    }
    Ok(())
}

/// Validate and normalize a customer-supplied custom domain: lowercase DNS
/// hostname with at least one dot, no scheme/port/path. Returns the normalized
/// (trimmed, lowercased, trailing-dot-stripped) domain. Shared by the customer
/// and admin APIs.
pub fn validate_custom_domain(d: &str) -> Result<String> {
    let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        bail!("custom domain must be 1–253 characters");
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    // Require at least one dot (a registrable host, not a bare TLD/label).
    if !d.contains('.') || !d.split('.').all(label_ok) {
        bail!("custom domain must be a valid DNS hostname (e.g. blog.example.com)");
    }
    Ok(d)
}

/// Resolve a submitted `config` map against the app's `config` schema: required
/// fields must be present, unknown keys rejected, and every submitted value
/// must satisfy its field's declared `type` and `pattern` (#271). Returns the
/// resolved map (submitted values ∪ declared defaults). Shared by the customer
/// and admin APIs. `submitted` keys/values are the customer-supplied field
/// values.
///
/// The type check happens here, at order time, because here is the last moment
/// the customer can still fix it. A value that reaches the operator is a value
/// the customer has already paid for: HAVEN panics on an `owner_npub` that is
/// not an npub, so before this the order was accepted and the deployment
/// crashlooped with nothing on screen saying which character was wrong.
pub fn resolve_config(
    compose: &Compose,
    submitted: &std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let declared: std::collections::HashSet<&str> =
        compose.config.iter().map(|c| c.name.as_str()).collect();
    for key in submitted.keys() {
        if !declared.contains(key.as_str()) {
            bail!("unknown config field '{key}'");
        }
    }
    let mut out = std::collections::BTreeMap::new();
    for field in &compose.config {
        // An empty `int`/`bool` is "the customer left the box alone", not a
        // value: a form that posts every field sends "" for the ones nobody
        // touched, and failing those would reject an order over a field the
        // app has a default for. An empty *string* is left alone — blank is a
        // legitimate value there, and always has been.
        let submitted_value = submitted.get(&field.name).filter(|v| {
            !(v.trim().is_empty() && matches!(field.r#type, FieldType::Int | FieldType::Bool))
        });
        match submitted_value.or(field.default.as_ref()) {
            Some(v) => {
                field.check_value(v)?;
                out.insert(field.name.clone(), v.clone());
            }
            None if field.required => {
                bail!("config field '{}' is required", field.display_label());
            }
            None => {}
        }
    }
    Ok(out)
}

/// A config file with its final rendered content, ready to become a ConfigMap
/// (or Secret when `sensitive`) mounted read-only at `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFile {
    pub path: String,
    pub content: String,
    pub sensitive: bool,
}

/// Maximum inline file / ConfigMap content size we accept (well under the k8s
/// ~1 MiB ConfigMap limit).
const MAX_FILE_BYTES: usize = 256 * 1024;

/// Whether `path` sits inside directory `dir` (both absolute).
fn path_is_within(path: &str, dir: &str) -> bool {
    let dir = dir.trim_end_matches('/');
    path.starts_with(&format!("{dir}/"))
}

/// Whether `text` addresses `host` as a hostname followed by a port, the way a
/// connection string does: `postgres://u:p@db:5432/x`, `redis://redis:6379`,
/// `http://s3:9000`, `db:3306`.
///
/// Deliberately narrow — the name must be preceded by a URL/host boundary and
/// followed by `:` and a digit. `redis://redis:6379` matches once (the second
/// `redis`), and a mention of the word in prose or in a longer token
/// (`mydb:5432`, `db.example.com:5432`) does not match at all.
fn addresses_host(text: &str, host: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(host) {
        let start = from + rel;
        let end = start + host.len();
        let before_ok = start == 0
            || matches!(
                bytes[start - 1],
                b'/' | b'@' | b' ' | b'\t' | b'"' | b'\'' | b'=' | b',' | b'(' | b'[' | b'\n'
            );
        let after_ok = bytes.get(end) == Some(&b':')
            && bytes
                .get(end + 1)
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);
        if before_ok && after_ok {
            return true;
        }
        from = end.max(start + 1);
    }
    false
}

/// Validate an init step's name as a DNS label: it becomes a container name,
/// which Kubernetes rejects outright if it is not one — and a rejected pod spec
/// is a deployment that never becomes ready, with the reason buried in the
/// operator's log rather than returned to whoever typed the name.
fn validate_init_name(service: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 40 {
        bail!("service '{service}': init name '{name}' must be 1–40 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        bail!(
            "service '{service}': init name '{name}' must be lowercase letters, digits and \
             hyphens (not leading or trailing)"
        );
    }
    Ok(())
}

/// Validate an in-container path: absolute, not root, no `..` traversal.
fn check_abs_no_traversal(service: &str, label: &str, path: &str) -> Result<()> {
    if !path.starts_with('/') {
        bail!("service '{service}': {label} path '{path}' must be absolute");
    }
    if path == "/" {
        bail!("service '{service}': {label} path cannot be '/'");
    }
    if path.split('/').any(|seg| seg == "..") {
        bail!("service '{service}': {label} path '{path}' must not contain '..'");
    }
    Ok(())
}

/// Validate a volume mount: name is a slug, path is absolute/non-traversal.
fn validate_mount_path(service: &str, name: &str, path: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("service '{service}': volume name '{name}' must be a lowercase slug");
    }
    check_abs_no_traversal(service, "volume", path)?;
    Ok(())
}

/// Extract the `NAME`s referenced as `${NAME}` in a string.
fn extract_refs(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some(end) = s[i + 2..].find('}')
        {
            let name = &s[i + 2..i + 2 + end];
            if !name.is_empty() {
                out.push(name.to_string());
            }
            i = i + 2 + end + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Substitute every `${NAME}` in `s` from `vars`, erroring on an unknown name.
/// Substitute `${NAME}` references from `vars`.
///
/// A reference with no value substitutes the **empty string** rather than
/// failing. This is deliberate: substitution runs in the operator's reconcile
/// loop against a deployment's *stored* config, which can legitimately predate
/// a catalog compose that has since gained a new field. Failing there would
/// break a running customer workload over a value it never had the chance to
/// supply. Authoring mistakes are caught instead by [`Compose::validate`],
/// which rejects a reference that is not declared in `config:`/`secrets:` (or a
/// builtin) at the point a human can still fix it.
///
/// Callers that want defaults rather than blanks should seed `vars` from
/// [`Compose::config_defaults`] first.
fn substitute(s: &str, vars: &HashMap<String, String>) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        // A malformed `${` is still an error: it is a syntax mistake in the
        // compose, not a missing value, and validate() rejects it too.
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unterminated '${{' in '{s}'"))?;
        let name = &after[..end];
        out.push_str(vars.get(name).map(String::as_str).unwrap_or(""));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE96: &str = r#"
services:
  mariadb:
    image: mariadb:11
    env:
      MARIADB_PASSWORD: ${DB_PASSWORD}
    volumes:
      - { name: db, path: /var/lib/mysql, size: 5Gi }
    backup:
      command: ["sh", "-c", "mariadb-dump"]
      artifact: dump.sql
  route96:
    image: ghcr.io/v0l/route96:latest
    depends_on: [mariadb]
    ports:
      - { name: http, container: 8000, protocol: http, expose: ingress }
    env:
      DATABASE_URL: "mysql://route96:${DB_PASSWORD}@mariadb:3306/route96"
      PUBLIC_URL: "https://${HOSTNAME}"
      MAX_UPLOAD_MB: ${max_upload_mb}
    volumes:
      - { name: blobs, path: /app/data, size: 20Gi }
    backup:
      volume: blobs

secrets:
  - { name: DB_PASSWORD, generate: password }

config:
  - { name: max_upload_mb, label: "Max upload (MB)", type: int, default: "100" }
"#;

    #[test]
    fn parses_multi_service_app() {
        let c = Compose::parse(ROUTE96).unwrap();
        assert_eq!(c.services.len(), 2);
        assert_eq!(c.secrets.len(), 1);
        assert_eq!(c.secrets[0].generate, Generate::Password);
        assert_eq!(c.config.len(), 1);

        let route96 = &c.services["route96"];
        assert_eq!(route96.depends_on, vec!["mariadb"]);
        assert_eq!(route96.ports[0].expose, Expose::Ingress);
        assert_eq!(route96.ports[0].protocol, Protocol::Http);
        assert_eq!(route96.volumes[0].name, "blobs");

        // mariadb has no ports -> internal only, and a command backup.
        let db = &c.services["mariadb"];
        assert!(db.ports.is_empty());
        assert!(db.backup.as_ref().unwrap().command.is_some());
    }

    /// A two-service compose — an `s3` service and an `app` that depends on it
    /// — with `decl` spliced into the app as its init steps.
    fn init_compose(decl: &str) -> String {
        format!(
            "services:\n  \
               s3:\n    image: rustfs/rustfs:latest\n    ports:\n      \
                 - {{ name: api, container: 9000 }}\n    env:\n      \
                 K: ${{S3_KEY}}\n  \
               app:\n    image: example/app:latest\n    user: \"1000\"\n    \
                 depends_on: [s3]\n{decl}\
             secrets:\n  - {{ name: S3_KEY, generate: token }}\n"
        )
    }

    /// An init step resolves its `env` like any other, keeps declaration order,
    /// and inherits the service's `user:` and a small default size.
    #[test]
    fn init_steps_resolve_with_service_defaults() {
        let c = Compose::parse(&init_compose(
            "    init:\n      \
               - name: wait-s3\n        image: minio/mc:latest\n        \
                 command: [\"sh\", \"-c\", \"until mc ls t; do sleep 2; done\"]\n        \
                 env:\n          MC_HOST_t: http://k:${S3_KEY}@s3:9000\n      \
               - name: make-bucket\n        image: minio/mc:latest\n        \
                 resources: { cpu: 100m, memory: 128Mi }\n        user: \"65534\"\n",
        ))
        .unwrap();
        c.validate_declarations().unwrap();

        let vars = HashMap::from([("S3_KEY".to_string(), "abc123".to_string())]);
        let resolved = c.resolve_init(&vars).unwrap();
        // Only the service that declares steps appears.
        assert_eq!(resolved.len(), 1);
        let steps = &resolved["app"];
        assert_eq!(
            steps.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["wait-s3", "make-bucket"]
        );

        let wait = &steps[0];
        assert_eq!(wait.env["MC_HOST_t"], "http://k:abc123@s3:9000");
        assert_eq!(wait.command.as_ref().unwrap()[0], "sh");
        assert!(wait.args.is_none());
        // No `resources:` → the init default, not the service default (250m).
        assert_eq!(wait.resources.cpu, INIT_DEFAULT_CPU);
        assert_eq!(wait.resources.memory, INIT_DEFAULT_MEMORY);
        // No `user:` → the service's, so it can write that service's volumes.
        assert_eq!(wait.run_as_user(), Some(1000));

        let make = &steps[1];
        assert_eq!(make.resources.cpu, "100m");
        assert_eq!(make.run_as_user(), Some(65534));
        assert!(!make.runs_as_root());
    }

    #[test]
    fn validate_rejects_unusable_init_steps() {
        let err = |decl: &str| {
            Compose::parse(&init_compose(decl))
                .expect_err("should be rejected")
                .to_string()
        };
        let step = |body: &str| format!("    init:\n      - {body}\n");

        // The name becomes a container name, so it must be a DNS label.
        for bad in ["Setup", "set_up", "-setup", "setup-"] {
            let e = err(&step(&format!("{{ name: {bad}, image: busybox }}")));
            assert!(e.contains("init name"), "{bad}: {e}");
        }
        // Two steps cannot share a container name.
        let e = err("    init:\n      - { name: setup, image: busybox }\n      \
             - { name: setup, image: alpine }\n");
        assert!(e.contains("duplicate init step"), "{e}");
        // Something has to run.
        assert!(
            err(&step("{ name: setup, image: \"\" }")).contains("image is required"),
            "empty image"
        );
        assert!(
            err(&step("{ name: setup, image: busybox, command: [] }")).contains("command is empty"),
            "empty command"
        );
        // A `user:` the kubelet cannot verify is rejected at authoring time.
        let e = err(&step("{ name: setup, image: busybox, user: nonroot }"));
        assert!(e.contains("positive numeric UID"), "{e}");
    }

    /// `${…}` in a command would interpolate a customer-supplied config value
    /// into a shell string. Values go through `env` instead, where the script
    /// reads them as shell variables.
    #[test]
    fn validate_rejects_substitution_in_init_commands() {
        for decl in [
            "    init:\n      - name: setup\n        image: busybox\n        \
             command: [\"sh\", \"-c\", \"echo ${S3_KEY}\"]\n",
            "    init:\n      - name: setup\n        image: busybox\n        \
             args: [\"${S3_KEY}\"]\n",
        ] {
            let e = Compose::parse(&init_compose(decl))
                .expect_err("substitution in argv")
                .to_string();
            assert!(e.contains("must not contain"), "{e}");
        }
    }

    /// An init step's env is `${…}` like any other value, so an undeclared
    /// reference is caught by the same admission rule rather than at deploy.
    #[test]
    fn init_env_counts_as_references() {
        let c = Compose::parse(&init_compose(
            "    init:\n      - name: setup\n        image: busybox\n        \
             env:\n          A: ${NOPE}\n",
        ))
        .unwrap();
        assert!(c.referenced_vars().contains(&"NOPE".to_string()));
        let err = c
            .validate_declarations()
            .expect_err("undeclared")
            .to_string();
        assert!(err.contains("NOPE"), "{err}");
    }

    /// A pod reserves `max(largest init, sum of containers)`, so a small setup
    /// step is free and only a larger one moves the app's footprint.
    #[test]
    fn init_resources_only_count_when_larger_than_the_service() {
        let small = Compose::parse(&init_compose(
            "    init:\n      - { name: setup, image: busybox }\n",
        ))
        .unwrap();
        let bare = Compose::parse(&init_compose("")).unwrap();
        assert_eq!(small.footprint().unwrap(), bare.footprint().unwrap());

        let big = Compose::parse(&init_compose(
            "    init:\n      - name: setup\n        image: busybox\n        \
             resources: { cpu: \"2\", memory: 1Gi }\n",
        ))
        .unwrap();
        let app = big
            .service_footprints()
            .unwrap()
            .into_iter()
            .find(|s| s.name == "app")
            .unwrap();
        assert_eq!(app.cpu_milli, 2000);
        assert_eq!(app.memory_bytes, 1 << 30);
    }

    /// A secret's length is declarable, and defaults to 24 bytes so every
    /// compose written before the field existed is unaffected.
    #[test]
    fn secret_byte_length_is_declarable() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      K: ${KEY}\n      P: ${PW}\n\
             secrets:\n  - { name: PW, generate: password }\n  \
             - { name: KEY, generate: token, bytes: 32 }\n",
        )
        .unwrap();
        let by_name = |n: &str| c.secrets.iter().find(|s| s.name == n).unwrap().clone();
        assert_eq!(by_name("PW").bytes, None);
        assert_eq!(by_name("PW").byte_len(), DEFAULT_SECRET_BYTES);
        assert_eq!(by_name("KEY").byte_len(), 32);
        c.validate().unwrap();
        c.validate_declarations().unwrap();
    }

    /// An unusable length is rejected at authoring time — the alternative is an
    /// app that deploys and then crash-loops on its own key.
    #[test]
    fn validate_rejects_out_of_range_secret_bytes() {
        let with_bytes = |n: usize| {
            format!(
                "services:\n  a:\n    image: x\nsecrets:\n  - {{ name: K, generate: token, bytes: {n} }}\n"
            )
        };
        for good in [MIN_SECRET_BYTES, 32, MAX_SECRET_BYTES] {
            Compose::parse(&with_bytes(good))
                .unwrap_or_else(|e| panic!("{good} bytes should parse: {e}"));
        }
        for bad in [0, MIN_SECRET_BYTES - 1, MAX_SECRET_BYTES + 1, 4096] {
            let err = Compose::parse(&with_bytes(bad))
                .expect_err(&format!("{bad} bytes should be rejected"));
            assert!(err.to_string().contains("bytes must be between"), "{err}");
        }
    }

    #[test]
    fn defaults_apply() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 80 }\n",
        )
        .unwrap();
        let p = &c.services["a"].ports[0];
        assert_eq!(p.expose, Expose::None);
        assert_eq!(p.protocol, Protocol::Tcp);
        // No `user:` -> default non-root hardening applies.
        assert!(!c.services["a"].runs_as_root());
    }

    /// A service may opt into starting as root (e.g. mariadb/postgres/redis
    /// whose entrypoint drops privileges itself) via `user: root` / `0`.
    #[test]
    fn user_root_opts_out_of_non_root() {
        let c = Compose::parse(
            "services:\n  db:\n    image: mariadb:11\n    user: root\n  app:\n    image: x\n",
        )
        .unwrap();
        assert!(c.services["db"].runs_as_root());
        assert!(!c.services["app"].runs_as_root());

        // `0` is equivalent to `root`.
        let c = Compose::parse("services:\n  db:\n    image: x\n    user: \"0\"\n").unwrap();
        assert!(c.services["db"].runs_as_root());
    }

    /// A numeric `user:` yields an explicit UID, which the operator turns into
    /// `runAsUser` + `fsGroup`. Required for images whose `USER` is a name
    /// (e.g. `USER nonroot`), which the kubelet cannot verify.
    #[test]
    fn numeric_user_is_parsed_as_uid() {
        let c = Compose::parse("services:\n  a:\n    image: x\n    user: \"1000\"\n").unwrap();
        assert_eq!(c.services["a"].run_as_user(), Some(1000));
        assert!(!c.services["a"].runs_as_root());

        // root / 0 / unset carry no explicit uid.
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n  b:\n    image: x\n    user: root\n  c:\n    image: x\n    user: \"0\"\n",
        )
        .unwrap();
        assert_eq!(c.services["a"].run_as_user(), None);
        assert_eq!(c.services["b"].run_as_user(), None);
        assert_eq!(c.services["c"].run_as_user(), None);
    }

    /// Regression: a *named* user was silently accepted and then ignored, so
    /// the pod was refused by the kubelet at runtime ("image has non-numeric
    /// user (nonroot), cannot verify user is non-root") and retried for
    /// minutes. It must fail when the catalog app is validated instead.
    #[test]
    fn named_user_is_rejected_at_validation() {
        for bad in ["nonroot", "app", "-1", "1.5", ""] {
            let yaml = format!("services:\n  a:\n    image: x\n    user: \"{bad}\"\n");
            let err = Compose::parse(&yaml).expect_err("named user must be rejected");
            assert!(
                err.to_string().contains("numeric UID"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn referenced_vars_collected() {
        let c = Compose::parse(ROUTE96).unwrap();
        let mut refs = c.referenced_vars();
        refs.sort();
        assert_eq!(refs, vec!["DB_PASSWORD", "HOSTNAME", "max_upload_mb"]);
    }

    #[test]
    fn resolves_env_across_services() {
        let c = Compose::parse(ROUTE96).unwrap();
        let mut vars = HashMap::new();
        vars.insert("DB_PASSWORD".to_string(), "s3cr3t".to_string());
        vars.insert(
            "HOSTNAME".to_string(),
            "my-relay.apps.example.com".to_string(),
        );
        vars.insert("max_upload_mb".to_string(), "100".to_string());

        let env = c.resolve_env(&vars).unwrap();
        assert_eq!(env["mariadb"]["MARIADB_PASSWORD"], "s3cr3t");
        assert_eq!(
            env["route96"]["DATABASE_URL"],
            "mysql://route96:s3cr3t@mariadb:3306/route96"
        );
        assert_eq!(
            env["route96"]["PUBLIC_URL"],
            "https://my-relay.apps.example.com"
        );
        assert_eq!(env["route96"]["MAX_UPLOAD_MB"], "100");
    }

    /// A reference that is not declared in `config:`/`secrets:` (and is not a
    /// builtin) is rejected at validation, so an authoring mistake is caught
    /// while a human can still fix it.
    #[test]
    fn undeclared_reference_rejected_at_admission() {
        let yaml = "services:\n  a:\n    image: x\n    env:\n      TOKEN: ${not_declared}\n";
        // Structurally valid, so it still parses...
        let c = Compose::parse(yaml).expect("parse must stay lenient for the operator");
        // ...but authoring it is rejected.
        let err = c
            .validate_declarations()
            .expect_err("undeclared reference must be rejected");
        assert!(err.to_string().contains("not declared"), "{err}");

        // Declaring it as a config field fixes it...
        let ok = "services:\n  a:\n    image: x\n    env:\n      TOKEN: ${tok}\nconfig:\n  - { name: tok, type: string }\n";
        assert!(Compose::parse(ok).unwrap().validate_declarations().is_ok());
        // ...as does a secret, or a builtin.
        let sec = "services:\n  a:\n    image: x\n    env:\n      TOKEN: ${TOK}\nsecrets:\n  - { name: TOK, generate: password }\n";
        assert!(Compose::parse(sec).unwrap().validate_declarations().is_ok());
        let builtin = "services:\n  a:\n    image: x\n    env:\n      URL: https://${HOSTNAME}\n";
        assert!(
            Compose::parse(builtin)
                .unwrap()
                .validate_declarations()
                .is_ok()
        );
    }

    /// The operator must keep rendering an already-stored app whose compose has
    /// an undeclared reference: `parse` (used on every reconcile) must not
    /// enforce the authoring rule, or the deployment goes offline over something
    /// it cannot fix.
    #[test]
    fn parse_stays_lenient_so_reconcile_never_breaks() {
        let yaml = "services:\n  a:\n    image: x\n    env:\n      TOKEN: ${gone}\n";
        let c = Compose::parse(yaml).expect("must parse");
        let env = c.resolve_env(&HashMap::new()).expect("must resolve");
        assert_eq!(env["a"]["TOKEN"], "");
    }

    /// Substitution at reconcile time is deliberately tolerant: a declared field
    /// the deployment never supplied must not break a running workload. It
    /// resolves to the empty string, and the operator seeds declared defaults
    /// first so a newly added field renders as its default.
    #[test]
    fn missing_value_substitutes_empty_not_error() {
        let c = Compose::parse(ROUTE96).unwrap();
        // Only DB_PASSWORD supplied: max_upload_mb and HOSTNAME are missing.
        let mut vars = HashMap::new();
        vars.insert("DB_PASSWORD".to_string(), "x".to_string());
        let env = c.resolve_env(&vars).expect("must not error");
        assert_eq!(env["route96"]["MAX_UPLOAD_MB"], "");
        assert_eq!(env["route96"]["PUBLIC_URL"], "https://");
        assert_eq!(env["mariadb"]["MARIADB_PASSWORD"], "x");

        // Seeding declared defaults gives the default instead of a blank.
        let mut vars = HashMap::new();
        for (k, v) in c.config_defaults() {
            vars.insert(k, v);
        }
        let env = c.resolve_env(&vars).unwrap();
        assert_eq!(env["route96"]["MAX_UPLOAD_MB"], "100");
    }

    #[test]
    fn rejects_ingress_on_non_http() {
        let yaml = "services:\n  a:\n    image: x\n    ports:\n      - { name: p, container: 5, protocol: tcp, expose: ingress }\n";
        assert!(Compose::parse(yaml).is_err());
    }

    #[test]
    fn rejects_bad_mount_paths() {
        // relative
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: data, size: 1Gi }\n"
            )
            .is_err()
        );
        // traversal
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: /var/../etc, size: 1Gi }\n"
            )
            .is_err()
        );
        // root
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    volumes:\n      - { name: d, path: /, size: 1Gi }\n"
            )
            .is_err()
        );
    }

    /// `scratch:` parses with and without an explicit size (#264).
    #[test]
    fn parses_scratch_paths() {
        let c = Compose::parse(
            "services:\n  db:\n    image: mariadb:11\n    scratch:\n      - { path: /tmp, size: 512Mi }\n      - { path: /run/mysqld }\n",
        )
        .unwrap();
        let s = &c.services["db"].scratch;
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].path, "/tmp");
        assert_eq!(s[0].size_or_default(), "512Mi");
        // An undeclared size falls back rather than being unbounded: an
        // emptyDir with no sizeLimit can fill the node's disk.
        assert_eq!(s[1].size_or_default(), DEFAULT_SCRATCH_SIZE);
    }

    /// Scratch paths are bounded, absolute, and may not overlap anything that
    /// holds data (#264).
    #[test]
    fn validate_rejects_unusable_scratch() {
        let svc = |scratch: &str| {
            format!(
                "services:\n  db:\n    image: mariadb:11\n    volumes:\n      - {{ name: data, path: /var/lib/mysql, size: 5Gi }}\n    scratch:\n{scratch}"
            )
        };
        // Absolute, non-traversing, not '/' — the same rule volumes get.
        assert!(Compose::parse(&svc("      - { path: tmp }\n")).is_err());
        assert!(Compose::parse(&svc("      - { path: /var/../tmp }\n")).is_err());
        assert!(Compose::parse(&svc("      - { path: / }\n")).is_err());
        // Bounded: node-local disk is shared with every other tenant.
        assert!(Compose::parse(&svc("      - { path: /tmp, size: 4Gi }\n")).is_err());
        assert!(Compose::parse(&svc("      - { path: /tmp, size: 0 }\n")).is_err());
        assert!(Compose::parse(&svc("      - { path: /tmp, size: enormous }\n")).is_err());
        // Scratch inside a data volume would hide the customer's data behind an
        // empty directory on every restart...
        assert!(Compose::parse(&svc("      - { path: /var/lib/mysql/tmp }\n")).is_err());
        assert!(Compose::parse(&svc("      - { path: /var/lib/mysql }\n")).is_err());
        // ...and a data volume inside scratch would not survive one.
        assert!(Compose::parse(&svc("      - { path: /var/lib }\n")).is_err());
        // Duplicate and nested scratch paths render two mounts at one path,
        // which the kubelet rejects.
        assert!(Compose::parse(&svc("      - { path: /tmp }\n      - { path: /tmp }\n")).is_err());
        assert!(
            Compose::parse(&svc(
                "      - { path: /run }\n      - { path: /run/mysqld }\n"
            ))
            .is_err()
        );
        // A config file inside a scratch path: mounted read-only into a
        // directory that is emptied on restart.
        assert!(
            Compose::parse(
                "services:\n  db:\n    image: mariadb:11\n    scratch:\n      - { path: /run/mysqld }\n    files:\n      - { path: /run/mysqld/my.cnf, content: \"x\" }\n"
            )
            .is_err()
        );
        // The shape route96's database actually needs.
        let ok = Compose::parse(&svc(
            "      - { path: /tmp }\n      - { path: /run/mysqld, size: 32Mi }\n",
        ))
        .unwrap();
        assert_eq!(ok.services["db"].scratch.len(), 2);
    }

    /// A declared `type` is enforced against a submitted value (#271) — before
    /// this, `resolve_config` read `required` and never `type`.
    #[test]
    fn resolve_config_enforces_declared_types() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      N: ${n}\n      B: ${b}\n      S: ${s}\n\
             config:\n  - { name: n, label: \"Count\", type: int }\n  \
             - { name: b, label: \"Enabled\", type: bool }\n  \
             - { name: s, label: \"Name\", type: string }\n",
        )
        .unwrap();
        let sub =
            |k: &str, v: &str| std::collections::BTreeMap::from([(k.to_string(), v.to_string())]);

        assert!(resolve_config(&c, &sub("n", "42")).is_ok());
        assert!(resolve_config(&c, &sub("n", "-1")).is_ok());
        assert!(resolve_config(&c, &sub("n", " 7 ")).is_ok(), "trimmed");
        let err = resolve_config(&c, &sub("n", "abc"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Count"),
            "names the label the customer saw: {err}"
        );
        assert!(err.contains("whole number"), "{err}");
        assert!(resolve_config(&c, &sub("n", "1.5")).is_err());
        // An empty int is an untouched form box, not a value: it falls back to
        // the field's default (here: absent) rather than failing the order.
        assert!(resolve_config(&c, &sub("n", "")).is_ok());
        assert!(!resolve_config(&c, &sub("n", "")).unwrap().contains_key("n"));
        assert!(resolve_config(&c, &sub("b", "  ")).is_ok());
        // ...but a blank string is a legitimate value and is still stored.
        assert_eq!(resolve_config(&c, &sub("s", "")).unwrap()["s"], "");

        assert!(resolve_config(&c, &sub("b", "true")).is_ok());
        assert!(resolve_config(&c, &sub("b", "false")).is_ok());
        assert!(resolve_config(&c, &sub("b", "maybe")).is_err());
        assert!(resolve_config(&c, &sub("b", "1")).is_err());

        // A string is unconstrained unless the app declares a pattern.
        assert!(resolve_config(&c, &sub("s", "anything at all")).is_ok());
    }

    /// A `pattern` is anchored, enforced at order time, and compiled at
    /// authoring time — the npub case that produced a crashlooping, paid-for
    /// deployment (#271).
    #[test]
    fn resolve_config_enforces_patterns() {
        let npub = "npub1v0lxxxxutpvrelsksy8cdhgfux9l6a42hsj2qzquu2zk7vc9qnkszrqj49";
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      O: ${owner_npub}\n\
             config:\n  - { name: owner_npub, label: \"Owner npub\", type: string, \
             required: true, pattern: \"npub1[02-9ac-hj-np-z]{58}\" }\n",
        )
        .unwrap();
        let sub =
            |v: &str| std::collections::BTreeMap::from([("owner_npub".to_string(), v.to_string())]);

        assert!(resolve_config(&c, &sub(npub)).is_ok());
        // One character out of the bech32 alphabet.
        assert!(resolve_config(&c, &sub(&npub.replace("v0l", "b0l"))).is_err());
        // Right shape, wrong length.
        assert!(resolve_config(&c, &sub("npub1abc")).is_err());
        // Anchored at both ends: a value that merely *contains* an npub is not
        // an npub, and an unanchored pattern would have accepted both.
        assert!(resolve_config(&c, &sub(&format!("{npub}junk"))).is_err());
        assert!(resolve_config(&c, &sub(&format!("junk{npub}"))).is_err());
        let err = resolve_config(&c, &sub("nope")).unwrap_err().to_string();
        assert!(err.contains("Owner npub"), "{err}");

        // A pattern that does not compile is the author's error, refused when
        // the app is created rather than at a customer's order.
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    env:\n      O: ${o}\n\
                 config:\n  - { name: o, type: string, pattern: \"[unclosed\" }\n"
            )
            .is_err()
        );
        // As is a default its own field would reject — authoring-time only, so
        // a row stored before the rule still renders.
        let bad_default = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      N: ${n}\n\
             config:\n  - { name: n, type: int, default: \"abc\" }\n",
        )
        .unwrap();
        assert!(bad_default.validate_declarations().is_err());
        assert!(resolve_config(&bad_default, &std::collections::BTreeMap::new()).is_err());
    }

    /// A service addressed as `name:port` must declare a port, because that is
    /// what makes the operator render a Service — and a Service is the only
    /// thing that gives the name a DNS record (#281).
    #[test]
    fn addressed_services_must_declare_a_port() {
        // The shape that reached production: the relay points at `db:5432`,
        // and `db` declares no ports.
        let broken = "services:\n  db:\n    image: postgres:17\n    user: root\n  \
             relay:\n    image: example/relay\n    user: \"1000\"\n    \
             ports:\n      - { name: http, container: 3000, protocol: http, expose: ingress }\n    \
             env:\n      DATABASE_URL: \"postgres://buzz:pw@db:5432/buzz\"\n";
        let c = Compose::parse(broken).unwrap();
        let err = c.validate_declarations().unwrap_err().to_string();
        assert!(err.contains("addresses 'db:<port>'"), "{err}");
        assert!(err.contains("declares no `ports:`"), "{err}");
        // Rendering is unchanged: `validate()` (which the operator runs on
        // stored rows) still accepts it, so an app already deployed keeps
        // reconciling rather than disappearing.
        assert!(Compose::parse(broken).is_ok());

        // With an internal port block it passes — `expose: none` is enough,
        // since the Service is what DNS needs, not the ingress.
        let fixed = broken.replace(
            "  db:\n    image: postgres:17\n    user: root\n",
            "  db:\n    image: postgres:17\n    user: root\n    ports:\n      \
             - { name: postgres, container: 5432, protocol: tcp, expose: none }\n",
        );
        Compose::parse(&fixed)
            .unwrap()
            .validate_declarations()
            .unwrap();

        // An init step naming a portless peer counts: the step that waits for
        // a backing service is exactly where this bites first.
        let init_case = "services:\n  cache:\n    image: redis:7\n    user: root\n  \
             app:\n    image: example/app\n    user: \"1000\"\n    \
             ports:\n      - { name: http, container: 80, protocol: http, expose: ingress }\n    \
             init:\n      - name: wait\n        image: busybox\n        \
             env:\n          TARGET: \"redis://cache:6379\"\n";
        assert!(
            Compose::parse(init_case)
                .unwrap()
                .validate_declarations()
                .is_err()
        );

        // A file's content counts too — a config file is where a hostname
        // usually lives for apps that do not read env.
        let file_case = "services:\n  cache:\n    image: redis:7\n    user: root\n  \
             app:\n    image: example/app\n    user: \"1000\"\n    \
             ports:\n      - { name: http, container: 80, protocol: http, expose: ingress }\n    \
             files:\n      - { path: /app/c.yaml, content: \"redis: cache:6379\\n\" }\n";
        assert!(
            Compose::parse(file_case)
                .unwrap()
                .validate_declarations()
                .is_err()
        );
    }

    /// The host match is deliberately narrow: a hostname position followed by a
    /// port, not any mention of the name (#281).
    #[test]
    fn addresses_host_matches_only_host_positions() {
        assert!(addresses_host("postgres://buzz:pw@db:5432/buzz", "db"));
        assert!(addresses_host("redis://redis:6379", "redis"));
        assert!(addresses_host("http://s3:9000", "s3"));
        assert!(addresses_host("db:3306", "db"));
        assert!(addresses_host("host = \"cache:6379\"", "cache"));

        // Not a host position: part of a longer name, or a different host that
        // merely ends with ours.
        assert!(!addresses_host("mydb:5432", "db"));
        assert!(!addresses_host("db.example.com:5432", "db"));
        // Named without a port — nothing here needs a Service.
        assert!(!addresses_host("the db is postgres", "db"));
        assert!(!addresses_host("redis://redis", "redis"));
        // The scheme alone must not match its own service name.
        assert!(!addresses_host("redis://other:6379", "redis"));
    }

    /// A service with a data volume must declare who writes to it (#277).
    /// Without a numeric `user:` there is no fsGroup, so the PVC mounts
    /// root-owned and the non-root container the kubelet starts cannot write.
    #[test]
    fn volumes_require_a_declared_user() {
        let svc = |user: &str| {
            format!(
                "services:\n  a:\n    image: x\n{user}    \
                 volumes:\n      - {{ name: data, path: /data, size: 1Gi }}\n"
            )
        };

        // Volumes + silence: refused, with the fix in the message.
        let c = Compose::parse(&svc("")).unwrap();
        let err = c.validate_declarations().unwrap_err().to_string();
        assert!(err.contains("declares volumes but no `user:`"), "{err}");
        assert!(err.contains("fsGroup"), "{err}");

        // A numeric UID becomes the fsGroup...
        assert!(
            Compose::parse(&svc("    user: \"1000\"\n"))
                .unwrap()
                .validate_declarations()
                .is_ok()
        );
        // ...and root is a valid answer too: a root process can write to a
        // root-owned volume, so there is nothing to chown.
        assert!(
            Compose::parse(&svc("    user: root\n"))
                .unwrap()
                .validate_declarations()
                .is_ok()
        );

        // No volumes, no requirement — the rule is about who writes to a PVC,
        // not about declaring a user for its own sake.
        assert!(
            Compose::parse("services:\n  a:\n    image: x\n")
                .unwrap()
                .validate_declarations()
                .is_ok()
        );

        // Authoring-time only: `validate()` (which the operator runs on stored
        // rows) still accepts it, so an app stored before this rule keeps
        // reconciling rather than vanishing from the cluster.
        assert!(Compose::parse(&svc("")).is_ok());
    }

    /// A stored persistent volume may grow, but it may not shrink, vanish or
    /// be renamed (#292) — each of those is unrecoverable once a deployment
    /// exists.
    #[test]
    fn volumes_may_grow_but_not_shrink_or_vanish() {
        let app = |vols: &str| {
            Compose::parse(&format!(
                "services:\n  db:\n    image: x\n    user: \"1000\"\n    volumes:\n{vols}"
            ))
            .unwrap()
        };
        let stored = app("      - { name: data, path: /data, size: 5Gi }\n");

        // Same size, and a larger one, both pass.
        assert!(
            app("      - { name: data, path: /data, size: 5Gi }\n")
                .validate_volume_changes(&stored)
                .is_ok()
        );
        assert!(
            app("      - { name: data, path: /data, size: 20Gi }\n")
                .validate_volume_changes(&stored)
                .is_ok()
        );
        // Compared in bytes, so a change of unit alone is a no-op.
        assert!(
            app("      - { name: data, path: /data, size: 5120Mi }\n")
                .validate_volume_changes(&stored)
                .is_ok()
        );
        // A new volume beside the old one is fine: nothing existing moves.
        assert!(
            app("      - { name: data, path: /data, size: 5Gi }\n      \
                 - { name: logs, path: /logs, size: 1Gi }\n")
            .validate_volume_changes(&stored)
            .is_ok()
        );

        // Shrink: the 422 loop.
        let err = app("      - { name: data, path: /data, size: 1Gi }\n")
            .validate_volume_changes(&stored)
            .unwrap_err()
            .to_string();
        assert!(err.contains("shrinks from 5Gi to 1Gi"), "{err}");

        // Removal: the PVC survives unmounted, holding the customer's data.
        let err = Compose::parse("services:\n  db:\n    image: x\n")
            .unwrap()
            .validate_volume_changes(&stored)
            .unwrap_err()
            .to_string();
        assert!(err.contains("volume 'data' is missing"), "{err}");

        // Rename is a remove plus an add, and orphans the old PVC the same way.
        let err = app("      - { name: store, path: /data, size: 5Gi }\n")
            .validate_volume_changes(&stored)
            .unwrap_err()
            .to_string();
        assert!(err.contains("volume 'data' is missing"), "{err}");

        // Volumes are keyed by (service, name): moving one to another service
        // is a different PVC, so it counts as dropping the original.
        let moved = Compose::parse(
            "services:\n  cache:\n    image: x\n    user: \"1000\"\n    volumes:\n      \
             - { name: data, path: /data, size: 5Gi }\n",
        )
        .unwrap();
        assert!(moved.validate_volume_changes(&stored).is_err());

        // Authoring-time only: `validate()` still accepts the shrunk document,
        // so a row stored before this rule keeps reconciling.
        assert!(
            Compose::parse(
                "services:\n  db:\n    image: x\n    user: \"1000\"\n    volumes:\n      \
                 - { name: data, path: /data, size: 1Gi }\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_empty_and_bad_refs() {
        assert!(Compose::parse("services: {}\n").is_err());
        assert!(
            Compose::parse("services:\n  a:\n    image: x\n    depends_on: [ghost]\n").is_err()
        );
        // backup volume not declared
        assert!(
            Compose::parse("services:\n  a:\n    image: x\n    backup: { volume: nope }\n")
                .is_err()
        );
    }

    /// The app-wide `backup:` policy: what it accepts, and the two ways it can
    /// be written such that a customer would believe they had backups when
    /// they did not.
    #[test]
    fn backup_policy_grammar() {
        let with = |policy: &str, method: &str| {
            Compose::parse(&format!(
                "services:\n  db:\n    image: x\n    volumes:\n      - {{ name: data, path: \
                 /data, size: 5Gi }}\n{method}{policy}"
            ))
        };
        let method = "    backup: { volume: data }\n";

        let c = with("backup: { schedule: \"0 3 * * *\" }\n", method).unwrap();
        let policy = c.backup.as_ref().unwrap();
        assert_eq!(policy.schedule, "0 3 * * *");
        // Unset retention is the default, not "keep nothing".
        assert_eq!(policy.retention_or_default(), DEFAULT_BACKUP_RETENTION);
        assert_eq!(c.backup_services().len(), 1);
        assert_eq!(c.backup_services()[0].0, "db");

        assert_eq!(
            with(
                "backup: { schedule: \"0 4 * * 0\", retention: 2 }\n",
                method
            )
            .unwrap()
            .backup
            .unwrap()
            .retention_or_default(),
            2
        );

        // A schedule with no service method captures nothing, but would read
        // in the catalog as if the app were protected.
        assert!(with("backup: { schedule: \"0 3 * * *\" }\n", "").is_err());
        // Retention outside the accepted range, in both directions.
        assert!(
            with(
                "backup: { schedule: \"0 3 * * *\", retention: 0 }\n",
                method
            )
            .is_err()
        );
        assert!(
            with(
                "backup: { schedule: \"0 3 * * *\", retention: 31 }\n",
                method
            )
            .is_err()
        );
        // Not a cron expression at all.
        assert!(with("backup: { schedule: daily }\n", method).is_err());
        assert!(with("backup: { schedule: \"0 3 * *\" }\n", method).is_err());
        // Faster than the floor: every minute, and twice a minute apart within
        // an otherwise daily pattern.
        assert!(with("backup: { schedule: \"* * * * *\" }\n", method).is_err());
        assert!(with("backup: { schedule: \"0,1 3 * * *\" }\n", method).is_err());
        assert!(with("backup: { schedule: \"*/30 * * * *\" }\n", method).is_err());
        // Exactly at the floor is allowed.
        assert!(with("backup: { schedule: \"0 * * * *\" }\n", method).is_ok());
        // No policy at all stays valid: on-demand backups need no schedule.
        assert!(with("", method).unwrap().backup.is_none());
    }

    /// The operator asks one question of a schedule: is a run due? Answered
    /// from the last run, so a deployment that was down through several
    /// occurrences gets one catch-up run rather than one per missed slot.
    #[test]
    fn backup_schedule_due_from_last_run() {
        let c = Compose::parse(
            "services:\n  db:\n    image: x\n    backup: { command: [\"sh\"] }\nbackup: { \
             schedule: \"0 3 * * *\" }\n",
        )
        .unwrap();
        let policy = c.backup.as_ref().unwrap();
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);

        // Next 03:00 UTC after a mid-morning run.
        assert_eq!(
            policy.next_run_after(at("2026-03-01T09:15:00Z")).unwrap(),
            at("2026-03-02T03:00:00Z")
        );

        // Ran this morning, so nothing is due until tomorrow.
        assert!(
            !policy
                .is_due(at("2026-03-01T03:00:00Z"), at("2026-03-01T23:00:00Z"))
                .unwrap()
        );
        assert!(
            policy
                .is_due(at("2026-03-01T03:00:00Z"), at("2026-03-02T03:00:00Z"))
                .unwrap()
        );
        // Down for a week: due, once.
        assert!(
            policy
                .is_due(at("2026-03-01T03:00:00Z"), at("2026-03-08T12:00:00Z"))
                .unwrap()
        );
    }

    /// `artifact:` becomes the tail of an object key and the download
    /// filename, so it is a filename and nothing else.
    #[test]
    fn backup_artifact_must_be_a_plain_filename() {
        let app = |artifact: &str| {
            Compose::parse(&format!(
                "services:\n  db:\n    image: x\n    backup:\n      command: [\"sh\"]\n      \
                 artifact: {artifact}\n"
            ))
        };
        assert!(app("dump.sql").is_ok());
        assert!(app("route96_db-1.sql").is_ok());
        assert!(app("\"../../etc/passwd\"").is_err());
        assert!(app("\"sub/dir.sql\"").is_err());
        assert!(app("\".hidden\"").is_err());
        assert!(app("\"\"").is_err());
        assert!(app(&format!("\"{}\"", "a".repeat(65))).is_err());
    }

    #[test]
    fn substitute_unterminated_errors() {
        let vars = HashMap::new();
        assert!(substitute("${oops", &vars).is_err());
    }

    #[test]
    fn parses_cpu_quantities() {
        assert_eq!(parse_cpu_milli("500m").unwrap(), 500);
        assert_eq!(parse_cpu_milli("2").unwrap(), 2000);
        assert_eq!(parse_cpu_milli("1.5").unwrap(), 1500);
        assert!(parse_cpu_milli("abc").is_err());
        assert!(parse_cpu_milli("-1").is_err());
    }

    #[test]
    fn parses_byte_quantities() {
        assert_eq!(parse_bytes("512Mi").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_bytes("2Gi").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("1G").unwrap(), 1_000_000_000);
        assert_eq!(parse_bytes("1000").unwrap(), 1000);
        assert!(parse_bytes("big").is_err());
    }

    #[test]
    fn resources_default_and_footprint() {
        // mariadb: default resources + 5Gi vol; route96: default + 20Gi vol.
        let c = Compose::parse(ROUTE96).unwrap();
        // route96 has no explicit resources -> defaults (250m / 256Mi).
        assert_eq!(c.services["route96"].resources.cpu, "250m");
        let f = c.footprint().unwrap();
        // two services @ 250m = 500m, @ 256Mi = 512Mi, storage 25Gi.
        assert_eq!(f.cpu_milli, 500);
        assert_eq!(f.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(f.storage_bytes, 25u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn service_footprints_breaks_down_by_service() {
        let c = Compose::parse(ROUTE96).unwrap();
        let sf = c.service_footprints().unwrap();
        assert_eq!(sf.len(), 2);
        // Sorted by name: mariadb before route96.
        assert_eq!(sf[0].name, "mariadb");
        assert_eq!(sf[1].name, "route96");
        // Each defaults to 250m / 256Mi; volumes differ per service.
        for s in &sf {
            assert_eq!(s.cpu_milli, 250);
            assert_eq!(s.memory_bytes, 256 * 1024 * 1024);
        }
        assert_eq!(sf[0].storage_bytes, 5u64 * 1024 * 1024 * 1024);
        assert_eq!(sf[1].storage_bytes, 20u64 * 1024 * 1024 * 1024);
        // The breakdown sums to the flat footprint.
        let f = c.footprint().unwrap();
        assert_eq!(f.cpu_milli, sf.iter().map(|s| s.cpu_milli).sum::<u64>());
        assert_eq!(
            f.memory_bytes,
            sf.iter().map(|s| s.memory_bytes).sum::<u64>()
        );
        assert_eq!(
            f.storage_bytes,
            sf.iter().map(|s| s.storage_bytes).sum::<u64>()
        );
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    /// A flat total misreports any app that stores more than one kind of thing
    /// (#260): HAVEN's 30 GB is 10 GB of events and 20 GB of media, and read
    /// next to event-only relays quoting 10 GB it looks like three times the
    /// event storage a buyer gets. The breakdown carries the purpose the app
    /// authored, and still sums to the total.
    #[test]
    fn volumes_report_their_purpose_and_sum_to_the_total() {
        let c = Compose::parse(
            "services:\n  haven:\n    image: x\n    volumes:\n      \
             - { name: db, path: /app/db, size: 10Gi, label: events }\n      \
             - { name: blossom, path: /app/blossom, size: 20Gi, label: media }\n",
        )
        .unwrap();
        let v = c.volumes().unwrap();
        assert_eq!(v.len(), 2);
        // Declaration order within a service is preserved: an author who wants
        // a volume read first writes it first.
        assert_eq!(v[0].name, "db");
        assert_eq!(v[0].label.as_deref(), Some("events"));
        assert_eq!(v[0].size_bytes, 10 * GIB);
        assert_eq!(v[1].label.as_deref(), Some("media"));
        assert_eq!(v[1].size_bytes, 20 * GIB);
        assert!(v.iter().all(|x| x.service == "haven"));

        assert_eq!(
            c.footprint().unwrap().storage_bytes,
            v.iter().map(|x| x.size_bytes).sum::<u64>(),
            "the breakdown must add up to the number already shown"
        );
    }

    /// Labels are optional and nothing has to be backfilled: an unlabelled
    /// volume still reports its size, and its service, because a volume name
    /// is only unique within a service.
    #[test]
    fn volumes_without_labels_still_report_size_and_service() {
        let c = Compose::parse(ROUTE96).unwrap();
        let v = c.volumes().unwrap();
        assert_eq!(v.len(), 2);
        // Sorted by service name, so the same compose always renders the same
        // order (services live in a map).
        assert_eq!(v[0].service, "mariadb");
        assert_eq!(v[1].service, "route96");
        assert!(v.iter().all(|x| x.label.is_none()));
        assert_eq!(v[0].size_bytes, 5 * GIB);
        assert_eq!(v[1].size_bytes, 20 * GIB);
    }

    /// Two services can declare volumes with the same name (Buzz does), so the
    /// owning service is what disambiguates them.
    #[test]
    fn volumes_from_different_services_can_share_a_name() {
        let c = Compose::parse(
            "services:\n  db:\n    image: x\n    volumes:\n      \
             - { name: data, path: /var/lib/postgresql, size: 20Gi, label: database }\n  \
             relay:\n    image: y\n    volumes:\n      \
             - { name: data, path: /data, size: 10Gi, label: events }\n",
        )
        .unwrap();
        let v = c.volumes().unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(
            (v[0].service.as_str(), v[0].label.as_deref()),
            ("db", Some("database"))
        );
        assert_eq!(
            (v[1].service.as_str(), v[1].label.as_deref()),
            ("relay", Some("events"))
        );
    }

    /// A label lands on a price card next to a size, so it is a noun, not a
    /// sentence — and an empty one is an authoring mistake, not "no label".
    #[test]
    fn validate_rejects_unusable_volume_labels() {
        let vol = |label: &str| {
            format!(
                "services:\n  a:\n    image: x\n    volumes:\n      \
                 - {{ name: d, path: /data, size: 1Gi, label: \"{label}\" }}\n"
            )
        };
        let err = Compose::parse(&vol(""))
            .expect_err("empty label")
            .to_string();
        assert!(err.contains("label is empty"), "{err}");

        let long = "x".repeat(MAX_VOLUME_LABEL_LEN + 1);
        let err = Compose::parse(&vol(&long))
            .expect_err("overlong label")
            .to_string();
        assert!(err.contains("at most"), "{err}");

        // At the limit is fine, and surrounding whitespace is trimmed off.
        let c = Compose::parse(&vol(&"y".repeat(MAX_VOLUME_LABEL_LEN))).unwrap();
        assert_eq!(
            c.volumes().unwrap()[0].label.as_deref().map(str::len),
            Some(MAX_VOLUME_LABEL_LEN)
        );
        let c = Compose::parse(&vol("  events  ")).unwrap();
        assert_eq!(c.volumes().unwrap()[0].label.as_deref(), Some("events"));
    }

    #[test]
    fn footprint_uses_explicit_resources() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    resources: { cpu: \"2\", memory: 1Gi }\n    volumes:\n      - { name: d, path: /data, size: 10Gi }\n",
        )
        .unwrap();
        let f = c.footprint().unwrap();
        assert_eq!(f.cpu_milli, 2000);
        assert_eq!(f.memory_bytes, 1024 * 1024 * 1024);
        assert_eq!(f.storage_bytes, 10u64 * 1024 * 1024 * 1024);
    }

    const STRFRY: &str = r#"
services:
  strfry:
    image: ghcr.io/hoytech/strfry:latest
    ports:
      - { name: ws, container: 7777, protocol: http, expose: ingress }
    files:
      - path: /etc/strfry.conf
        content: |
          relay { info { name = "${relay_name}"; } }
      - path: /etc/custom.conf
        content_from: custom_conf
      - path: /etc/secret.key
        content: "${API_KEY}"
        sensitive: true
    volumes:
      - { name: db, path: /app/db, size: 5Gi }

secrets:
  - { name: API_KEY, generate: token }

config:
  - { name: relay_name, label: "Relay name", type: string, default: "My Relay" }
  - { name: custom_conf, label: "Custom config", type: file }
"#;

    #[test]
    fn parses_and_resolves_files() {
        let c = Compose::parse(STRFRY).unwrap();
        let files = &c.services["strfry"].files;
        assert_eq!(files.len(), 3);
        assert!(files[2].sensitive);

        // referenced_vars picks up ${…} in file content too.
        let mut refs = c.referenced_vars();
        refs.sort();
        assert_eq!(refs, vec!["API_KEY", "relay_name"]);

        let mut vars = HashMap::new();
        vars.insert("relay_name".to_string(), "Zap Relay".to_string());
        vars.insert("API_KEY".to_string(), "deadbeef".to_string());
        vars.insert("custom_conf".to_string(), "my custom file body".to_string());

        let resolved = c.resolve_files(&vars).unwrap();
        let sf = &resolved["strfry"];
        assert!(sf.iter().any(|f| f.path == "/etc/strfry.conf"
            && f.content.contains("name = \"Zap Relay\"")));
        // content_from injects the customer-supplied value verbatim.
        assert!(
            sf.iter()
                .any(|f| f.path == "/etc/custom.conf" && f.content == "my custom file body")
        );
        // sensitive file flagged for a Secret.
        assert!(
            sf.iter()
                .any(|f| f.path == "/etc/secret.key" && f.sensitive)
        );
    }

    #[test]
    fn rejects_bad_files() {
        // both content and content_from
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    files:\n      - { path: /e.conf, content: 'x', content_from: y }\n"
            )
            .is_err()
        );
        // neither content nor content_from
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    files:\n      - { path: /e.conf }\n"
            )
            .is_err()
        );
        // content_from unknown config field
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    files:\n      - { path: /e.conf, content_from: nope }\n"
            )
            .is_err()
        );
        // traversal path
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    files:\n      - { path: /etc/../x, content: 'y' }\n"
            )
            .is_err()
        );
        // file overlaps a data volume
        assert!(
            Compose::parse(
                "services:\n  a:\n    image: x\n    files:\n      - { path: /app/db/f.conf, content: 'y' }\n    volumes:\n      - { name: db, path: /app/db, size: 1Gi }\n"
            )
            .is_err()
        );
    }
}
