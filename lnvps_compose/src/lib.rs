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
use serde::Deserialize;
use std::collections::HashMap;

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
}

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
}

impl Service {
    /// Whether this service must start as root (compose `user: root` / `0`).
    pub fn runs_as_root(&self) -> bool {
        matches!(self.user.as_deref(), Some("root") | Some("0"))
    }

    /// The explicit numeric UID this service runs as, if the compose specifies
    /// one. `None` for `user: root` (handled by [`Self::runs_as_root`]) and
    /// when no user is set.
    ///
    /// Doubles as the pod's `fsGroup`: a container user's primary group
    /// conventionally matches its UID, and without it a fresh PVC mounts
    /// root-owned `0755` and the non-root process cannot write to it.
    pub fn run_as_user(&self) -> Option<i64> {
        match self.user.as_deref() {
            Some(u) => match u.parse::<i64>() {
                Ok(uid) if uid > 0 => Some(uid),
                _ => None,
            },
            None => None,
        }
    }
}

/// A service's requested CPU and memory. Kubernetes-style quantities: CPU as
/// cores or millicores (`"1"`, `"500m"`), memory with binary/SI suffixes
/// (`"512Mi"`, `"2Gi"`, `"1G"`).
#[derive(Debug, Clone, Deserialize)]
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
            serde_yaml::from_str(yaml).map_err(|e| anyhow!("invalid compose YAML: {e}"))?;
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
            }

            // A backup entry is exactly one of command | volume.
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
        Ok(())
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
        }
        out
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
    pub fn service_footprints(&self) -> Result<Vec<ServiceFootprint>> {
        let mut out = Vec::with_capacity(self.services.len());
        for (sname, svc) in &self.services {
            let cpu_milli = parse_cpu_milli(&svc.resources.cpu)
                .map_err(|e| anyhow!("service '{sname}': cpu: {e}"))?;
            let memory_bytes = parse_bytes(&svc.resources.memory)
                .map_err(|e| anyhow!("service '{sname}': memory: {e}"))?;
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
/// fields must be present, unknown keys rejected; returns the resolved map
/// (submitted values ∪ declared defaults). Shared by the customer and admin
/// APIs. `submitted` keys/values are the customer-supplied field values.
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
        match submitted.get(&field.name).or(field.default.as_ref()) {
            Some(v) => {
                out.insert(field.name.clone(), v.clone());
            }
            None if field.required => {
                bail!("config field '{}' is required", field.name);
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
