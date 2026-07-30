//! `compose-to-docker` — turn a managed-app compose document into a
//! `docker-compose.yaml` that starts the app locally under the same hardening
//! the cluster applies (issue #268).
//!
//! ```text
//! compose-to-docker app.yaml --out-dir .local/haven \
//!     --config RELAY_URL=wss://localhost:7777 --hostname localhost
//! docker compose -f .local/haven/docker-compose.yaml up
//! ```
//!
//! `compose-validate` answers "is this document well-formed?". This answers the
//! question validation cannot: does the image actually *start* under a
//! read-only root filesystem, with all capabilities dropped, as the declared
//! user, with only the declared volumes and scratch paths writable? Every
//! managed-app outage found so far (#248, #256, #263, #264) was a container
//! that could not start, and none of them was visible in the document.
//!
//! So the hardening is the point of the transform: the emitted services carry
//! `read_only`, `cap_drop: [ALL]`, `no-new-privileges` and `user:` exactly as
//! [`lnvps_operator`]'s container SecurityContext sets them. A permissive
//! docker-compose would have started all four broken apps cleanly and taught us
//! nothing.
//!
//! It is not a deployment test — see the "Known non-equivalences" section of
//! `docs/managed-app-examples.md`. Most importantly Docker has no `fsGroup`, so
//! a fresh named volume is root-owned and a non-root service cannot write to
//! it; the tool prints the `chown` that stands in for it rather than silently
//! doing it.

use anyhow::{Context, Result, anyhow, bail};
use lnvps_compose::{
    Compose, DEFAULT_SCRATCH_SIZE, Expose, ROOT_ENTRYPOINT_CAPABILITIES, ResolvedFile,
    ResolvedInit, Service, parse_bytes, parse_cpu_milli, resolve_config,
};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Name of the emitted compose file inside `--out-dir`.
const OUT_FILE: &str = "docker-compose.yaml";
/// Where generated secret values are kept between runs, so re-running the tool
/// against the same out-dir does not invalidate the data a previous run wrote
/// (a rotated `MARIADB_ROOT_PASSWORD` locks you out of your own volume).
const SECRETS_FILE: &str = "secrets.env";
/// Subdirectory of `--out-dir` holding rendered `files[]`, bind-mounted `:ro`.
const FILES_DIR: &str = "files";
/// Writable scratch every init step gets, mirroring the operator's `emptyDir`.
const INIT_TMP_DIR: &str = "/tmp";
/// containerd's default `nofile` limit, which is what a container gets in the
/// cluster. dockerd's default is lower, so it is set explicitly here — see
/// [`harden`].
const CONTAINERD_NOFILE: u64 = 1048576;

// ── CLI ─────────────────────────────────────────────────────────────────────

struct Args {
    source: String,
    out_dir: PathBuf,
    config: BTreeMap<String, String>,
    hostname: String,
    publish: bool,
}

const USAGE: &str = "\
compose-to-docker — render a managed-app compose as a runnable docker-compose

USAGE:
    compose-to-docker <app.yaml|-> --out-dir <dir> [--config K=V]... [--hostname H]

OPTIONS:
    --out-dir <dir>    Where to write docker-compose.yaml, rendered files and
                       generated secrets (created if missing).
    --config K=V       A customer config value. Repeatable. Declared defaults
                       apply to anything omitted; a required field with neither
                       is an error, exactly as at order time.
    --hostname <H>     Value for ${HOSTNAME} (default: localhost).
    --no-publish       Do not map `expose: ingress` ports onto the host. Use
                       when a host port is already taken; services still reach
                       each other by name.
";

fn parse_args(argv: Vec<String>) -> Result<Args> {
    let mut source: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut config = BTreeMap::new();
    let mut hostname = "localhost".to_string();
    let mut publish = true;

    let mut it = argv.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--out-dir" => {
                out_dir = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| anyhow!("--out-dir needs a value"))?,
                ));
            }
            "--hostname" => {
                hostname = it
                    .next()
                    .ok_or_else(|| anyhow!("--hostname needs a value"))?;
            }
            "--config" => {
                let kv = it.next().ok_or_else(|| anyhow!("--config needs K=V"))?;
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| anyhow!("--config expects K=V, got '{kv}'"))?;
                config.insert(k.to_string(), v.to_string());
            }
            "--no-publish" => publish = false,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with("--") => bail!("unknown option '{other}'"),
            other => {
                if source.replace(other.to_string()).is_some() {
                    bail!("only one compose document at a time");
                }
            }
        }
    }

    Ok(Args {
        source: source.ok_or_else(|| anyhow!("no compose document given\n\n{USAGE}"))?,
        out_dir: out_dir.ok_or_else(|| anyhow!("--out-dir is required\n\n{USAGE}"))?,
        config,
        hostname,
        publish,
    })
}

// ── secrets ─────────────────────────────────────────────────────────────────

/// Read `secrets.env`, generate anything still missing, and write it back.
///
/// Mirrors the operator's `ensure_secrets`: only missing values are generated,
/// so an existing local deployment keeps the password its data was initialised
/// with. Same hex encoding at the declared byte length.
fn ensure_secrets(compose: &Compose, out_dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = out_dir.join(SECRETS_FILE);
    let mut values = match std::fs::read_to_string(&path) {
        Ok(s) => parse_env_file(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    for s in &compose.secrets {
        values
            .entry(s.name.clone())
            .or_insert_with(|| generate_secret_value(s.byte_len()));
    }
    let body: String = values
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect::<Vec<_>>()
        .concat();
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(values)
}

fn parse_env_file(s: &str) -> BTreeMap<String, String> {
    s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .collect()
}

/// Random hex of `len` bytes — the operator's `generate_secret_value`.
fn generate_secret_value(len: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; len];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── substitution vars ───────────────────────────────────────────────────────

/// Merge the `${…}` map in the operator's order: declared defaults, then
/// generated secrets, then supplied config, then `HOSTNAME`.
///
/// Returns the map plus any referenced variable that still has no value —
/// those substitute empty (as they do in a real reconcile), which is how an app
/// ends up running with a blank `RELAY_URL` and exiting (#248). Reporting them
/// is the whole point of surfacing this locally.
fn build_vars(
    compose: &Compose,
    generated: &BTreeMap<String, String>,
    config: &BTreeMap<String, String>,
    hostname: &str,
) -> (HashMap<String, String>, Vec<String>) {
    let mut vars: HashMap<String, String> = HashMap::new();
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

    let missing: Vec<String> = compose
        .referenced_vars()
        .into_iter()
        .filter(|n| !vars.contains_key(n))
        .collect();
    (vars, missing)
}

// ── mapping ─────────────────────────────────────────────────────────────────

/// Everything the transform needs that came from outside the document.
struct Rendered<'a> {
    env: HashMap<String, HashMap<String, String>>,
    files: HashMap<String, Vec<ResolvedFile>>,
    init: HashMap<String, Vec<ResolvedInit>>,
    /// Relative path of each rendered file, keyed by (service, in-container
    /// path) — the bind-mount source.
    file_sources: BTreeMap<(String, String), String>,
    /// Compose project name, emitted into the document so it does not depend on
    /// which directory `docker compose` is run from.
    project: String,
    /// Whether `expose: ingress` ports are mapped onto the host.
    publish: bool,
    compose: &'a Compose,
}

/// Compose project name derived from the out-dir, sanitised the way docker
/// requires (lowercase alphanumerics, dashes and underscores).
///
/// Emitted as the document's `name:` so it is fixed rather than taken from
/// whatever directory the run happens in — which is what makes the volume names
/// in [`ownership_notes`] correct.
fn project_name(out_dir: &Path) -> String {
    let raw = out_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "lnvps-app".to_string());
    let cleaned: String = raw
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '-' || c == '_').to_string();
    if trimmed.is_empty() {
        "lnvps-app".to_string()
    } else {
        trimmed
    }
}

/// Docker volume name for a compose volume, matching the operator's PVC naming
/// (`{service}-{name}`) so the two are recognisably the same thing.
fn volume_name(service: &str, name: &str) -> String {
    format!("{service}-{name}")
}

/// The volume as docker actually names it once the project prefix is applied —
/// what `docker volume create` and a `chown` have to spell.
fn qualified_volume_name(project: &str, service: &str, name: &str) -> String {
    format!("{project}_{}", volume_name(service, name))
}

/// Service name for an init step: its own compose service, run once.
fn init_service_name(service: &str, step: &str) -> String {
    format!("{service}-init-{step}")
}

/// The four lines that make a local run mean something, plus the capabilities a
/// root entrypoint gets back (#263) — the docker equivalent of the operator's
/// `container_security_context_for`.
fn harden(svc_user: Option<&str>, runs_as_root: bool, into: &mut Mapping) {
    into.insert("read_only".into(), true.into());
    into.insert("cap_drop".into(), Value::Sequence(vec!["ALL".into()]));
    if runs_as_root {
        into.insert(
            "cap_add".into(),
            Value::Sequence(
                ROOT_ENTRYPOINT_CAPABILITIES
                    .iter()
                    .map(|&c| c.into())
                    .collect(),
            ),
        );
    }
    into.insert(
        "security_opt".into(),
        Value::Sequence(vec!["no-new-privileges:true".into()]),
    );
    // The kubelet reads the image's own USER when the compose names none; so
    // does docker, so leaving it unset is the same behaviour.
    if let Some(u) = svc_user {
        into.insert("user".into(), u.into());
    }
    // Match containerd's default file-descriptor limit rather than dockerd's,
    // which is lower: strfry asks for 1000000 fds at startup and aborts with
    // "Unable to set NOFILES limit to 1000000, exceeds max of 524288" under
    // docker's default while starting cleanly in the cluster. A local failure
    // the cluster would not have is worse than no local run at all.
    let mut nofile = Mapping::new();
    nofile.insert("soft".into(), Value::from(CONTAINERD_NOFILE));
    nofile.insert("hard".into(), Value::from(CONTAINERD_NOFILE));
    let mut ulimits = Mapping::new();
    ulimits.insert("nofile".into(), Value::Mapping(nofile));
    into.insert("ulimits".into(), Value::Mapping(ulimits));
}

/// `scratch:` → tmpfs mounts with the same byte limit the `emptyDir` gets.
fn scratch_mounts(svc: &Service) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for s in &svc.scratch {
        let bytes = parse_bytes(s.size_or_default())?;
        out.push(Value::from(format!("{}:size={bytes}", s.path)));
    }
    Ok(out)
}

/// `KEY=value` list form. A mapping would re-emit an env value as whatever
/// YAML type it looks like — a bare date becomes a timestamp and compose
/// rejects the file — and every env value here is a string.
fn env_sequence<'a>(env: impl IntoIterator<Item = (&'a String, &'a String)>) -> Value {
    Value::Sequence(
        env.into_iter()
            .map(|(k, v)| Value::from(format!("{k}={v}")))
            .collect(),
    )
}

/// Turn one compose service into its docker-compose service mapping.
fn service_mapping(name: &str, svc: &Service, r: &Rendered) -> Result<Mapping> {
    let mut m = Mapping::new();
    m.insert("image".into(), svc.image.as_str().into());

    if let Some(env) = r.env.get(name).filter(|e| !e.is_empty()) {
        let sorted: BTreeMap<_, _> = env.iter().collect();
        m.insert("environment".into(), env_sequence(sorted));
    }

    // Data volumes (PVC equivalent) followed by read-only file bind mounts.
    let mut mounts: Vec<Value> = svc
        .volumes
        .iter()
        .map(|v| Value::from(format!("{}:{}", volume_name(name, &v.name), v.path)))
        .collect();
    for f in r.files.get(name).into_iter().flatten() {
        let src = r
            .file_sources
            .get(&(name.to_string(), f.path.clone()))
            .ok_or_else(|| anyhow!("no rendered file for {name}{}", f.path))?;
        mounts.push(Value::from(format!("{src}:{}:ro", f.path)));
    }
    if !mounts.is_empty() {
        m.insert("volumes".into(), Value::Sequence(mounts));
    }

    let scratch = scratch_mounts(svc)?;
    if !scratch.is_empty() {
        m.insert("tmpfs".into(), Value::Sequence(scratch));
    }

    // A cluster Service is internal; only an ingress port is reachable from
    // outside. Published on loopback so a local run cannot be reached off-box.
    let mut expose: Vec<Value> = Vec::new();
    let mut ports: Vec<Value> = Vec::new();
    for p in &svc.ports {
        expose.push(Value::from(p.container.to_string()));
        if r.publish && p.expose == Expose::Ingress {
            ports.push(Value::from(format!(
                "127.0.0.1:{}:{}",
                p.container, p.container
            )));
        }
    }
    if !expose.is_empty() {
        m.insert("expose".into(), Value::Sequence(expose));
    }
    if !ports.is_empty() {
        m.insert("ports".into(), Value::Sequence(ports));
    }

    // Resources: the same numbers the pod requests, in docker's units.
    let cpus = parse_cpu_milli(&svc.resources.cpu)? as f64 / 1000.0;
    m.insert("cpus".into(), Value::from(cpus));
    m.insert(
        "mem_limit".into(),
        Value::from(parse_bytes(&svc.resources.memory)?),
    );

    harden(svc.user.as_deref(), svc.runs_as_root(), &mut m);

    // `depends_on` is advisory in k8s and enforced here, which is the one place
    // the local run is *stricter*: an init step must exit 0 before the service
    // it gates starts, exactly as the kubelet requires.
    let mut deps = Mapping::new();
    for d in &svc.depends_on {
        let mut cond = Mapping::new();
        cond.insert("condition".into(), "service_started".into());
        deps.insert(d.as_str().into(), Value::Mapping(cond));
    }
    for step in r.init.get(name).into_iter().flatten() {
        let mut cond = Mapping::new();
        cond.insert("condition".into(), "service_completed_successfully".into());
        deps.insert(
            init_service_name(name, &step.name).into(),
            Value::Mapping(cond),
        );
    }
    if !deps.is_empty() {
        m.insert("depends_on".into(), Value::Mapping(deps));
    }

    let _ = r.compose;
    Ok(m)
}

/// Turn one `init:` step into a one-shot docker-compose service.
///
/// It sees what its service sees — the same volumes and files — plus a writable
/// `/tmp`, and is hardened identically. `command`/`args` map to
/// `entrypoint`/`command`, which is the same split Kubernetes makes.
fn init_mapping(
    service: &str,
    svc: &Service,
    step: &ResolvedInit,
    r: &Rendered,
) -> Result<Mapping> {
    let mut m = Mapping::new();
    m.insert("image".into(), step.image.as_str().into());
    if !step.env.is_empty() {
        let sorted: BTreeMap<_, _> = step.env.iter().collect();
        m.insert("environment".into(), env_sequence(sorted));
    }
    if let Some(cmd) = &step.command {
        m.insert(
            "entrypoint".into(),
            Value::Sequence(cmd.iter().map(|c| c.as_str().into()).collect()),
        );
    }
    if let Some(args) = &step.args {
        m.insert(
            "command".into(),
            Value::Sequence(args.iter().map(|a| a.as_str().into()).collect()),
        );
    }

    let mut mounts: Vec<Value> = svc
        .volumes
        .iter()
        .map(|v| Value::from(format!("{}:{}", volume_name(service, &v.name), v.path)))
        .collect();
    for f in r.files.get(service).into_iter().flatten() {
        if let Some(src) = r.file_sources.get(&(service.to_string(), f.path.clone())) {
            mounts.push(Value::from(format!("{src}:{}:ro", f.path)));
        }
    }
    if !mounts.is_empty() {
        m.insert("volumes".into(), Value::Sequence(mounts));
    }

    // The step's writable /tmp, unless the service declares scratch there — in
    // which case that declaration already covers it, as it does in the pod.
    let mut scratch = scratch_mounts(svc)?;
    if !svc.scratch.iter().any(|s| s.path == INIT_TMP_DIR) {
        scratch.push(Value::from(format!(
            "{INIT_TMP_DIR}:size={}",
            parse_bytes(DEFAULT_SCRATCH_SIZE)?
        )));
    }
    m.insert("tmpfs".into(), Value::Sequence(scratch));

    m.insert(
        "cpus".into(),
        Value::from(parse_cpu_milli(&step.resources.cpu)? as f64 / 1000.0),
    );
    m.insert(
        "mem_limit".into(),
        Value::from(parse_bytes(&step.resources.memory)?),
    );
    harden(step.user.as_deref(), step.runs_as_root(), &mut m);
    // One-shot: it must not be restarted after it exits 0.
    m.insert("restart".into(), "no".into());

    // A step that bootstraps a peer (creating a bucket in an S3 service) needs
    // that peer running, and `depends_on` on the step is what expresses it.
    let mut deps = Mapping::new();
    for d in &svc.depends_on {
        let mut cond = Mapping::new();
        cond.insert("condition".into(), "service_started".into());
        deps.insert(d.as_str().into(), Value::Mapping(cond));
    }
    if !deps.is_empty() {
        m.insert("depends_on".into(), Value::Mapping(deps));
    }
    Ok(m)
}

/// The whole document: services, init steps as one-shot services, and the named
/// volumes they mount.
fn to_docker_compose(r: &Rendered) -> Result<Mapping> {
    let mut services = Mapping::new();
    let mut volumes = Mapping::new();

    let mut names: Vec<&String> = r.compose.services.keys().collect();
    names.sort();
    for name in names {
        let svc = &r.compose.services[name];
        for step in r.init.get(name).into_iter().flatten() {
            services.insert(
                init_service_name(name, &step.name).into(),
                Value::Mapping(init_mapping(name, svc, step, r)?),
            );
        }
        services.insert(
            name.as_str().into(),
            Value::Mapping(service_mapping(name, svc, r)?),
        );
        for v in &svc.volumes {
            volumes.insert(volume_name(name, &v.name).into(), Value::Null);
        }
    }

    let mut doc = Mapping::new();
    // Pin the project name rather than letting docker infer it from the working
    // directory: the volume names it prefixes are the ones the fsGroup
    // stand-in `chown` has to match, and a mismatch chowns a volume nothing
    // mounts (the app then fails on a permission error that looks like a bug in
    // the app).
    doc.insert("name".into(), r.project.as_str().into());
    doc.insert("services".into(), Value::Mapping(services));
    if !volumes.is_empty() {
        doc.insert("volumes".into(), Value::Mapping(volumes));
    }
    Ok(doc)
}

// ── output ──────────────────────────────────────────────────────────────────

/// Filename for a rendered config file: its in-container path flattened, so two
/// files with the same basename in different directories cannot collide.
fn file_slug(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "_")
}

/// Write every service's `files[]` under `<out-dir>/files/<service>/` and record
/// the relative bind-mount source for each.
fn write_files(
    out_dir: &Path,
    files: &HashMap<String, Vec<ResolvedFile>>,
) -> Result<BTreeMap<(String, String), String>> {
    let mut sources = BTreeMap::new();
    for (service, list) in files {
        if list.is_empty() {
            continue;
        }
        let dir = out_dir.join(FILES_DIR).join(service);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        for f in list {
            let rel = format!("./{FILES_DIR}/{service}/{}", file_slug(&f.path));
            let abs = out_dir.join(rel.trim_start_matches("./"));
            std::fs::write(&abs, &f.content)
                .with_context(|| format!("writing {}", abs.display()))?;
            // A `sensitive: true` file is a Secret in the cluster; locally the
            // least we can do is keep it off other users' reads.
            #[cfg(unix)]
            if f.sensitive {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(0o600))?;
            }
            sources.insert((service.clone(), f.path.clone()), rel);
        }
    }
    Ok(sources)
}

/// Read a whole file (or stdin for `-`).
fn read_source(path: &str) -> std::io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
    }
}

/// The `chown` a non-root service needs before its first run, standing in for
/// the `fsGroup` Kubernetes sets. Printed rather than performed: a tool that
/// silently fixed ownership would hide the class of failure it exists to show.
fn ownership_notes(compose: &Compose, project: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut names: Vec<&String> = compose.services.keys().collect();
    names.sort();
    for name in names {
        let svc = &compose.services[name];
        let Some(uid) = svc.run_as_user() else {
            continue;
        };
        for v in &svc.volumes {
            // Docker prefixes a named volume with the project, so this is the
            // name the volume will actually have — creating it up front under
            // that exact name is what lets compose reuse it instead of making
            // a fresh root-owned one.
            let vol = qualified_volume_name(project, name, &v.name);
            out.push(format!(
                "docker run --rm -u 0 -v {vol}:/d busybox chown -R {uid}:{uid} /d"
            ));
        }
    }
    out
}

fn run(args: Args) -> Result<()> {
    let source =
        read_source(&args.source).with_context(|| format!("cannot read {}", args.source))?;
    let compose = Compose::parse(&source).context("parse error")?;
    compose.validate().context("validation error")?;
    // This is an authoring tool, so it applies the admission-only rules too —
    // as `compose-validate` does. One of them matters especially here: docker
    // gives every service a DNS alias whether or not it declares ports, and
    // Kubernetes only gives one to a service that renders a Service. So a
    // compose that addresses a portless peer runs *fine locally* and fails in
    // the cluster with "Name or service not known" (#281). Refusing it here is
    // what keeps a green local run meaningful.
    compose
        .validate_declarations()
        .context("validation error")?;

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating {}", args.out_dir.display()))?;

    // Same config resolution the order path performs: submitted ∪ declared
    // defaults, with the same "required field" error.
    let config = resolve_config(&compose, &args.config)?;
    let generated = ensure_secrets(&compose, &args.out_dir)?;
    let (vars, missing) = build_vars(&compose, &generated, &config, &args.hostname);

    let env = compose.resolve_env(&vars)?;
    let files = compose.resolve_files(&vars)?;
    let init = compose.resolve_init(&vars)?;
    let file_sources = write_files(&args.out_dir, &files)?;

    let project = project_name(&args.out_dir);
    let rendered = Rendered {
        env,
        files,
        init,
        file_sources,
        project: project.clone(),
        publish: args.publish,
        compose: &compose,
    };
    let doc = to_docker_compose(&rendered)?;

    let path = args.out_dir.join(OUT_FILE);
    let body = format!(
        "# Generated by compose-to-docker from {} — do not edit.\n\
         # Hardening matches the cluster: read-only rootfs, all capabilities\n\
         # dropped, no privilege escalation. See docs/managed-app-examples.md\n\
         # for what a local run does and does not prove.\n{}",
        args.source,
        serde_yaml::to_string(&Value::Mapping(doc))?
    );
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;

    println!("wrote {}", path.display());
    let notes = ownership_notes(&compose, &project);
    if !notes.is_empty() {
        // `up --no-start` creates the volumes (labelled as compose's own, so
        // it does not then warn about adopting a foreign volume) without
        // starting anything, which is the window in which the chown has to
        // happen.
        println!(
            "  fsGroup has no docker equivalent — create the volumes, chown them, then start:"
        );
        println!("    docker compose -f {} up --no-start", path.display());
        for note in notes {
            println!("    {note}");
        }
    }
    if !missing.is_empty() {
        println!(
            "  warning: no value for {} — substituted empty, as a reconcile would",
            missing.join(", ")
        );
    }
    println!("  docker compose -f {} up", path.display());
    Ok(())
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1).collect()).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FAIL {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a document the way `run` does, without touching the filesystem.
    fn render(yaml: &str) -> Mapping {
        render_with(yaml, true)
    }

    fn render_with(yaml: &str, publish: bool) -> Mapping {
        let compose = Compose::parse(yaml).expect("parse");
        compose.validate().expect("validate");
        let config = resolve_config(&compose, &BTreeMap::new()).expect("config");
        let generated: BTreeMap<String, String> = compose
            .secrets
            .iter()
            .map(|s| (s.name.clone(), "sekret".to_string()))
            .collect();
        let (vars, _) = build_vars(&compose, &generated, &config, "localhost");
        let files = compose.resolve_files(&vars).expect("files");
        let mut file_sources = BTreeMap::new();
        for (service, list) in &files {
            for f in list {
                file_sources.insert(
                    (service.clone(), f.path.clone()),
                    format!("./{FILES_DIR}/{service}/{}", file_slug(&f.path)),
                );
            }
        }
        let r = Rendered {
            env: compose.resolve_env(&vars).expect("env"),
            files,
            init: compose.resolve_init(&vars).expect("init"),
            file_sources,
            project: "testproj".to_string(),
            publish,
            compose: &compose,
        };
        to_docker_compose(&r).expect("transform")
    }

    fn service<'a>(doc: &'a Mapping, name: &str) -> &'a Mapping {
        doc["services"][name].as_mapping().expect("service")
    }

    /// Env values are strings whatever they look like: serialised as a mapping,
    /// a date- or number-shaped value comes back as a typed scalar and compose
    /// refuses the file.
    #[test]
    fn env_values_stay_strings_when_serialised() {
        let doc = render(
            "services:\n  app:\n    image: example/app:latest\n    user: \"1000\"\n    \
             env:\n      SINCE: \"2023-01-01\"\n      REPLICAS: \"3\"\n      DEBUG: \"true\"\n",
        );
        let text = serde_yaml::to_string(&Value::Mapping(doc)).expect("serialise");
        let back: Value = serde_yaml::from_str(&text).expect("reparse");
        assert_eq!(
            back["services"]["app"]["environment"],
            Value::Sequence(vec![
                "DEBUG=true".into(),
                "REPLICAS=3".into(),
                "SINCE=2023-01-01".into(),
            ])
        );
    }

    const DB_APP: &str = "services:\n  db:\n    image: mariadb:11\n    user: root\n    \
         resources: { cpu: 500m, memory: 512Mi }\n    \
         env:\n      MARIADB_ROOT_PASSWORD: ${DB_PASSWORD}\n    \
         volumes:\n      - { name: data, path: /var/lib/mysql, size: 5Gi }\n    \
         scratch:\n      - { path: /tmp }\n      - { path: /run/mysqld, size: 32Mi }\n  \
         app:\n    image: example/app:latest\n    user: \"1000\"\n    depends_on: [db]\n    \
         ports:\n      - { name: http, container: 3000, protocol: http, expose: ingress }\n      \
         - { name: metrics, container: 9100, protocol: http, expose: none }\n    \
         files:\n      - { path: /app/config.yaml, content: \"url: https://${HOSTNAME}\\n\" }\n\
         secrets:\n  - { name: DB_PASSWORD, generate: password }\n";

    /// The four lines that make a local run mean anything are emitted for every
    /// service, and a `user: root` service gets the capabilities #263 restored —
    /// no more, and none of them for a non-root service.
    #[test]
    fn every_service_is_hardened_like_the_cluster() {
        let doc = render(DB_APP);

        for name in ["db", "app"] {
            let s = service(&doc, name);
            assert_eq!(s["read_only"], Value::from(true), "{name}");
            assert_eq!(s["cap_drop"], Value::Sequence(vec!["ALL".into()]), "{name}");
            assert_eq!(
                s["security_opt"],
                Value::Sequence(vec!["no-new-privileges:true".into()]),
                "{name}"
            );
            // containerd's limit, not dockerd's lower default — otherwise an
            // app that raises its fd limit (strfry asks for 1000000) fails
            // locally and starts in the cluster.
            assert_eq!(
                s["ulimits"]["nofile"]["soft"],
                Value::from(1048576u64),
                "{name}"
            );
            assert_eq!(
                s["ulimits"]["nofile"]["hard"],
                Value::from(1048576u64),
                "{name}"
            );
        }

        assert_eq!(service(&doc, "db")["user"], Value::from("root"));
        assert_eq!(
            service(&doc, "db")["cap_add"],
            Value::Sequence(
                ROOT_ENTRYPOINT_CAPABILITIES
                    .iter()
                    .map(|&c| c.into())
                    .collect()
            )
        );
        assert_eq!(service(&doc, "app")["user"], Value::from("1000"));
        assert!(
            !service(&doc, "app").contains_key("cap_add"),
            "a non-root service keeps drop: ALL with nothing added"
        );
    }

    /// Volumes, scratch, files, ports and resources map to their docker
    /// equivalents — and scratch keeps the byte limit the `emptyDir` has.
    #[test]
    fn volumes_scratch_ports_and_resources_map_over() {
        let doc = render(DB_APP);
        let db = service(&doc, "db");

        assert_eq!(
            db["volumes"],
            Value::Sequence(vec!["db-data:/var/lib/mysql".into()])
        );
        assert_eq!(
            db["tmpfs"],
            Value::Sequence(vec![
                "/tmp:size=268435456".into(),
                "/run/mysqld:size=33554432".into(),
            ])
        );
        assert_eq!(db["cpus"], Value::from(0.5));
        assert_eq!(db["mem_limit"], Value::from(536870912u64));
        assert_eq!(
            db["environment"],
            Value::Sequence(vec!["MARIADB_ROOT_PASSWORD=sekret".into()])
        );
        // The named volume is declared, so `docker compose up` creates it.
        assert!(doc["volumes"].as_mapping().unwrap().contains_key("db-data"));

        let app = service(&doc, "app");
        // Only an ingress port is published, and only on loopback; everything
        // else stays reachable service-to-service, as a ClusterIP would be.
        assert_eq!(
            app["ports"],
            Value::Sequence(vec!["127.0.0.1:3000:3000".into()])
        );
        assert_eq!(
            app["expose"],
            Value::Sequence(vec!["3000".into(), "9100".into()])
        );
        // Files are bind-mounted read-only at their in-container path.
        assert_eq!(
            app["volumes"],
            Value::Sequence(vec![
                "./files/app/app_config.yaml:/app/config.yaml:ro".into()
            ])
        );
        assert_eq!(
            app["depends_on"]["db"]["condition"],
            Value::from("service_started")
        );
    }

    /// An `init:` step becomes a one-shot service its own service waits on,
    /// with the same mounts, the same hardening and a writable `/tmp`.
    #[test]
    fn init_steps_become_one_shot_services() {
        let doc = render(
            "services:\n  s3:\n    image: rustfs/rustfs:latest\n    user: \"10001\"\n    \
             ports:\n      - { name: s3, container: 9000, protocol: http, expose: none }\n  \
             app:\n    image: example/app:latest\n    user: \"1000\"\n    depends_on: [s3]\n    \
             volumes:\n      - { name: data, path: /data, size: 1Gi }\n    \
             init:\n      - name: make-bucket\n        image: minio/mc:latest\n        \
             args: [\"mb\", \"-p\", \"s3/media\"]\n        \
             env:\n          MC_HOST_s3: http://k:${S3_KEY}@s3:9000\n\
             secrets:\n  - { name: S3_KEY, generate: token }\n",
        );

        let step = service(&doc, "app-init-make-bucket");
        assert_eq!(step["image"], Value::from("minio/mc:latest"));
        assert_eq!(step["restart"], Value::from("no"));
        assert_eq!(step["read_only"], Value::from(true));
        assert_eq!(
            step["user"],
            Value::from("1000"),
            "inherits its service's user"
        );
        assert_eq!(
            step["command"],
            Value::Sequence(vec!["mb".into(), "-p".into(), "s3/media".into()])
        );
        assert_eq!(
            step["environment"],
            Value::Sequence(vec!["MC_HOST_s3=http://k:sekret@s3:9000".into()])
        );
        // Sees the service's volume, plus scratch it can write to.
        assert_eq!(
            step["volumes"],
            Value::Sequence(vec!["app-data:/data".into()])
        );
        assert_eq!(
            step["tmpfs"],
            Value::Sequence(vec!["/tmp:size=268435456".into()])
        );
        // Its peer must be up before it runs; its service must wait for it to
        // succeed — the gate the kubelet gives init containers.
        assert_eq!(
            step["depends_on"]["s3"]["condition"],
            Value::from("service_started")
        );
        assert_eq!(
            service(&doc, "app")["depends_on"]["app-init-make-bucket"]["condition"],
            Value::from("service_completed_successfully")
        );
    }

    /// A service declaring scratch at `/tmp` supplies the step's writable
    /// `/tmp`, rather than the step adding a second mount at the same path.
    #[test]
    fn service_scratch_at_tmp_covers_the_init_step() {
        let doc = render(
            "services:\n  db:\n    image: mariadb:11\n    user: \"999\"\n    \
             scratch:\n      - { path: /tmp, size: 64Mi }\n    \
             ports:\n      - { name: http, container: 80, protocol: http, expose: ingress }\n    \
             init:\n      - name: seed\n        image: busybox\n        command: [\"true\"]\n",
        );
        assert_eq!(
            service(&doc, "db-init-seed")["tmpfs"],
            Value::Sequence(vec!["/tmp:size=67108864".into()])
        );
        assert_eq!(
            service(&doc, "db-init-seed")["entrypoint"],
            Value::Sequence(vec!["true".into()])
        );
    }

    /// `--no-publish` drops the host mapping and keeps everything else: the
    /// services still reach each other by name, as they would in a namespace.
    #[test]
    fn no_publish_keeps_services_reachable_but_off_the_host() {
        let doc = render_with(DB_APP, false);
        let app = service(&doc, "app");
        assert!(!app.contains_key("ports"));
        assert_eq!(
            app["expose"],
            Value::Sequence(vec!["3000".into(), "9100".into()])
        );
    }

    /// The `chown` that stands in for `fsGroup` is reported for every non-root
    /// service with a volume, and not performed.
    #[test]
    fn ownership_notes_name_the_fsgroup_workaround() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    user: \"1000\"\n    \
             volumes:\n      - { name: data, path: /data, size: 1Gi }\n  \
             b:\n    image: y\n    user: root\n    \
             volumes:\n      - { name: data, path: /var/lib/mysql, size: 1Gi }\n",
        )
        .unwrap();
        let notes = ownership_notes(&c, "proj");
        assert_eq!(notes.len(), 1, "root services need no chown: {notes:?}");
        assert!(
            notes[0].contains("proj_a-data"),
            "the project prefix docker actually applies: {}",
            notes[0]
        );
        assert!(
            !notes[0].contains("docker volume create"),
            "the volume is created by `up --no-start`, so compose owns it: {}",
            notes[0]
        );
        assert!(notes[0].contains("chown -R 1000:1000"), "{}", notes[0]);
    }

    /// Generated secrets survive a re-run against the same out-dir: rotating a
    /// database password locks you out of the volume it initialised.
    #[test]
    fn secrets_are_stable_across_runs() {
        let dir =
            std::env::temp_dir().join(format!("compose-to-docker-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      P: ${PW}\n\
             secrets:\n  - { name: PW, generate: password }\n",
        )
        .unwrap();
        let first = ensure_secrets(&c, &dir).unwrap();
        let second = ensure_secrets(&c, &dir).unwrap();
        assert_eq!(first["PW"], second["PW"]);
        assert_eq!(first["PW"].len(), 48, "24 bytes, hex-encoded");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A required config field with no value fails here, exactly as it does at
    /// order time — rather than starting a container with an empty env var.
    #[test]
    fn missing_required_config_is_an_error() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      R: ${relay}\n\
             config:\n  - { name: relay, label: Relay, type: string, required: true }\n",
        )
        .unwrap();
        assert!(resolve_config(&c, &BTreeMap::new()).is_err());
        let supplied = BTreeMap::from([("relay".to_string(), "wss://localhost".to_string())]);
        assert_eq!(
            resolve_config(&c, &supplied).unwrap()["relay"],
            "wss://localhost"
        );
    }

    /// A reference with no value substitutes empty (as a reconcile does) and is
    /// reported — that is how #248 looked from the outside.
    #[test]
    fn unresolved_vars_are_reported() {
        let c = Compose::parse(
            "services:\n  a:\n    image: x\n    env:\n      R: ${relay}\n\
             config:\n  - { name: relay, label: Relay, type: string }\n",
        )
        .unwrap();
        let config = resolve_config(&c, &BTreeMap::new()).unwrap();
        let (vars, missing) = build_vars(&c, &BTreeMap::new(), &config, "localhost");
        assert_eq!(missing, vec!["relay".to_string()]);
        assert_eq!(c.resolve_env(&vars).unwrap()["a"]["R"], "");
    }

    #[test]
    fn args_require_a_document_and_an_out_dir() {
        assert!(parse_args(vec![]).is_err());
        assert!(parse_args(vec!["a.yaml".into()]).is_err());
        assert!(parse_args(vec!["--out-dir".into(), "d".into()]).is_err());
        assert!(
            parse_args(vec![
                "a.yaml".into(),
                "--config".into(),
                "no-equals".into(),
                "--out-dir".into(),
                "d".into()
            ])
            .is_err()
        );
        let a = parse_args(vec![
            "a.yaml".into(),
            "--out-dir".into(),
            "d".into(),
            "--config".into(),
            "k=v=v".into(),
            "--hostname".into(),
            "h.example".into(),
        ])
        .unwrap();
        assert_eq!(a.source, "a.yaml");
        assert_eq!(a.out_dir, PathBuf::from("d"));
        assert_eq!(a.config["k"], "v=v");
        assert_eq!(a.hostname, "h.example");
    }
}
