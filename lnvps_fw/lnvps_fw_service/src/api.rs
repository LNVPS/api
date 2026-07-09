//! RESTful control API for `lnvps_fw_service`.
//!
//! The daemon is the *server*; the primary `lnvps_api` service is the *client*
//! and the source of truth. There is **no database** here: rules are pushed by
//! `lnvps_api` and held in memory, and mitigation events go into a bounded
//! in-memory ring buffer that `lnvps_api` polls (via a monotonic cursor) and
//! persists itself.
//!
//! HTTPS is required (rustls). A cert/key can be supplied in config; otherwise
//! a self-signed cert is generated at startup so HTTPS always works. Every
//! request is authenticated with a static bearer token (constant-time compare)
//! and an optional source-IP allow-list.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router, middleware};
use serde::{Deserialize, Serialize};

/// A CIDR parsed into an address family + network bytes, for applying to the
/// BPF longest-prefix-match maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrKey {
    V4 { bits: u32, net: [u8; 4] },
    V6 { bits: u32, net: [u8; 16] },
}

/// Parse a `"203.0.113.0/24"` / `"2001:db8::/48"` CIDR string. A bare address is
/// treated as a host route (/32 or /128).
pub fn parse_cidr(s: &str) -> Option<CidrKey> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let bits = len.map_or(Some(32), |l| l.parse().ok())?;
            if bits > 32 {
                return None;
            }
            Some(CidrKey::V4 {
                bits,
                net: v4.octets(),
            })
        }
        IpAddr::V6(v6) => {
            let bits = len.map_or(Some(128), |l| l.parse().ok())?;
            if bits > 128 {
                return None;
            }
            Some(CidrKey::V6 {
                bits,
                net: v6.octets(),
            })
        }
    }
}

impl CidrKey {
    /// Canonical `"net/len"` string.
    pub fn to_cidr_string(self) -> String {
        match self {
            CidrKey::V4 { bits, net } => format!("{}/{bits}", Ipv4Addr::from(net)),
            CidrKey::V6 { bits, net } => format!("{}/{bits}", Ipv6Addr::from(net)),
        }
    }
}

// --- Wire types ---

/// A manual mitigation override pushed by an operator / `lnvps_api`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Override {
    /// Target CIDR (e.g. `"203.0.113.7/32"`).
    pub cidr: String,
    /// Protection-flag bitmask to pin (`DEST_MODE_*` OR'd together).
    pub flags: u32,
}

/// The full pushed ruleset. `PUT /rules` replaces it atomically.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuleSet {
    /// Protected prefixes (CIDR strings) for prefix-wide (carpet-bomb) defence.
    pub protected: Vec<String>,
    /// Manual mitigation overrides.
    pub overrides: Vec<Override>,
}

/// One currently-active mitigation, reported in the status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Mitigation {
    pub cidr: String,
    pub flags: u32,
    pub since_unix: u64,
    pub manual: bool,
    pub peak_pps: u64,
    pub peak_bps: u64,
    pub peak_syn_pps: u64,
}

/// Kind of mitigation event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Start,
    Flags,
    Stop,
}

/// A mitigation start/flags/stop event, buffered for polling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Monotonic sequence number (the poll cursor).
    pub seq: u64,
    pub kind: EventKind,
    pub cidr: String,
    pub flags: u32,
    pub ts_unix: u64,
    pub pps: u64,
    pub bps: u64,
    pub syn_pps: u64,
}

/// Live per-destination rates for a currently-active tracked IP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrackedIp {
    pub ip: String,
    pub pps: u64,
    pub bps: u64,
    pub syn_pps: u64,
    pub drop_pps: u64,
    pub mitigating: bool,
    pub flags: u32,
    /// How close this IP is to tripping mitigation: the max of its pps/syn/bps
    /// rates as a percentage of their entry thresholds (>=100 = tripping).
    pub load_pct: u32,
}

/// Live aggregate rates for one protected prefix vs the carpet-bomb thresholds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixLoad {
    pub cidr: String,
    pub pps: u64,
    pub bps: u64,
    pub syn_pps: u64,
    pub mitigating: bool,
    pub flags: u32,
    /// Aggregate load as a percentage of the network thresholds (>=100 =
    /// carpet-bomb mitigation trips for the whole prefix).
    pub load_pct: u32,
}

/// The detection thresholds, exposed so operators can see how much headroom
/// remains before mitigation engages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Limits {
    /// Per-destination entry thresholds.
    pub pps: u64,
    pub syn_pps: u64,
    pub bps: u64,
    /// Per-protected-prefix (carpet-bomb) aggregate thresholds.
    pub net_pps: u64,
    pub net_syn_pps: u64,
    pub net_bps: u64,
    /// Exit hysteresis (% of entry) and cooldown.
    pub exit_pct: u64,
    pub cooldown_secs: u64,
}

/// A learned open port on a protected IP (surfaced for `lnvps_api` / admin).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LearnedPort {
    pub ip: String,
    pub port: u16,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Seconds since this port was last seen serving (0 if unknown).
    pub age_secs: u64,
}

/// Daemon status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub uptime_secs: u64,
    pub interfaces: Vec<String>,
    pub protected_prefixes: usize,
    pub active_mitigations: usize,
    pub learned_ports: usize,
    pub events_cursor: u64,
}

/// Bounded ring buffer of events with a monotonic cursor.
#[derive(Debug)]
struct EventRing {
    buf: VecDeque<Event>,
    next_seq: u64,
    cap: usize,
}

impl EventRing {
    fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            next_seq: 1,
            cap: cap.max(1),
        }
    }

    fn push(
        &mut self,
        kind: EventKind,
        cidr: String,
        flags: u32,
        pps: u64,
        bps: u64,
        syn_pps: u64,
    ) {
        let ev = Event {
            seq: self.next_seq,
            kind,
            cidr,
            flags,
            ts_unix: now_unix(),
            pps,
            bps,
            syn_pps,
        };
        self.next_seq += 1;
        self.buf.push_back(ev);
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
    }

    /// Events with `seq > cursor`, plus the new cursor to poll from next.
    fn since(&self, cursor: u64) -> (Vec<Event>, u64) {
        let out: Vec<Event> = self
            .buf
            .iter()
            .filter(|e| e.seq > cursor)
            .cloned()
            .collect();
        let next = self.next_seq - 1;
        (out, next.max(cursor))
    }
}

/// Shared control-API state. The HTTP handlers only read/write this; the
/// control loop reads the pushed rules and publishes the active snapshot +
/// events into it. No BPF handles cross into the handlers.
pub struct SharedState {
    token: String,
    allow_ips: Vec<IpAddr>,
    started: Instant,
    interfaces: Vec<String>,
    rules: RwLock<RuleSet>,
    active: RwLock<Vec<Mitigation>>,
    tracked: RwLock<Vec<TrackedIp>>,
    prefixes: RwLock<Vec<PrefixLoad>>,
    ports: RwLock<Vec<LearnedPort>>,
    limits: RwLock<Limits>,
    events: Mutex<EventRing>,
    /// Bumped whenever the ruleset changes so the control loop reloads it.
    rules_version: AtomicU64,
    /// Bumped whenever the limits are edited so the control loop reloads them.
    limits_version: AtomicU64,
}

impl SharedState {
    pub fn new(
        token: String,
        allow_ips: Vec<IpAddr>,
        interfaces: Vec<String>,
        initial: RuleSet,
        events_cap: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            token,
            allow_ips,
            started: Instant::now(),
            interfaces,
            rules: RwLock::new(initial),
            active: RwLock::new(Vec::new()),
            tracked: RwLock::new(Vec::new()),
            prefixes: RwLock::new(Vec::new()),
            ports: RwLock::new(Vec::new()),
            limits: RwLock::new(Limits::default()),
            events: Mutex::new(EventRing::new(events_cap)),
            rules_version: AtomicU64::new(1),
            limits_version: AtomicU64::new(1),
        })
    }

    /// Current ruleset (clone) — read by the control loop.
    pub fn rules(&self) -> RuleSet {
        self.rules.read().unwrap().clone()
    }

    /// Monotonic ruleset version; changes on every push/override edit.
    pub fn rules_version(&self) -> u64 {
        self.rules_version.load(Ordering::Relaxed)
    }

    fn bump_rules(&self) {
        self.rules_version.fetch_add(1, Ordering::Relaxed);
    }

    /// Replace the active-mitigation snapshot (called by the control loop).
    pub fn set_active(&self, active: Vec<Mitigation>) {
        *self.active.write().unwrap() = active;
    }

    /// Replace the learned-open-ports snapshot (called by the control loop).
    pub fn set_ports(&self, ports: Vec<LearnedPort>) {
        *self.ports.write().unwrap() = ports;
    }

    /// Replace the live tracked-IP rate snapshot (called by the control loop).
    pub fn set_tracked(&self, tracked: Vec<TrackedIp>) {
        *self.tracked.write().unwrap() = tracked;
    }

    /// Replace the per-prefix (carpet-bomb) load snapshot.
    pub fn set_prefixes(&self, prefixes: Vec<PrefixLoad>) {
        *self.prefixes.write().unwrap() = prefixes;
    }

    /// Publish the detection thresholds (called at startup).
    pub fn set_limits(&self, limits: Limits) {
        *self.limits.write().unwrap() = limits;
    }

    /// Current limits (clone) — read by the control loop on version change.
    pub fn limits(&self) -> Limits {
        *self.limits.read().unwrap()
    }

    /// Monotonic limits version; changes on every live edit.
    pub fn limits_version(&self) -> u64 {
        self.limits_version.load(Ordering::Relaxed)
    }

    /// Record a mitigation event (called by the control loop).
    pub fn record_event(
        &self,
        kind: EventKind,
        cidr: String,
        flags: u32,
        pps: u64,
        bps: u64,
        syn_pps: u64,
    ) {
        self.events
            .lock()
            .unwrap()
            .push(kind, cidr, flags, pps, bps, syn_pps);
    }

    fn token_matches(&self, presented: &str) -> bool {
        constant_time_eq(presented.as_bytes(), self.token.as_bytes())
    }

    fn ip_allowed(&self, peer: Option<IpAddr>) -> bool {
        if self.allow_ips.is_empty() {
            return true;
        }
        match peer {
            Some(ip) => self.allow_ips.contains(&ip),
            None => false,
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time byte comparison (avoids leaking the token via timing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build the full router: the JSON API (behind bearer-token auth) plus the
/// internal HTML dashboard (outside the token layer, gated only by the
/// source-IP allow-list, since a browser can't send a bearer header on
/// navigation — the page itself prompts for the token and calls the API).
pub fn router(state: Arc<SharedState>) -> Router {
    let api = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/rules", get(get_rules).put(put_rules))
        .route(
            "/api/v1/mitigations",
            get(get_mitigations)
                .post(post_override)
                .delete(delete_override),
        )
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/ports", get(get_ports))
        .route("/api/v1/tracked", get(get_tracked))
        .route("/api/v1/prefixes", get(get_prefixes))
        .route("/api/v1/limits", get(get_limits).put(put_limits))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state.clone());

    let dashboard = Router::new()
        .route("/", get(dashboard))
        .layer(middleware::from_fn_with_state(state.clone(), ip_gate))
        .with_state(state);

    Router::new().merge(api).merge(dashboard)
}

/// Serve the API + dashboard over HTTPS (rustls) until the process exits.
pub async fn serve(state: Arc<SharedState>, addr: SocketAddr, tls: TlsPem) -> anyhow::Result<()> {
    install_crypto_provider();
    let cfg = axum_server::tls_rustls::RustlsConfig::from_pem(tls.cert_pem, tls.key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("rustls config: {e}"))?;
    let app = router(state);
    axum_server::bind_rustls(addr, cfg)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| anyhow::anyhow!("https server: {e}"))
}

/// Source-IP-only gate for the dashboard (no bearer token required).
async fn ip_gate(
    State(state): State<Arc<SharedState>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    if state.ip_allowed(peer) {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "source ip not allowed").into_response()
    }
}

async fn dashboard() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
        .into_response()
}

/// Bearer-token + source-IP auth middleware.
async fn auth(
    State(state): State<Arc<SharedState>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    if !state.ip_allowed(peer) {
        return (StatusCode::FORBIDDEN, "source ip not allowed").into_response();
    }
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(tok) if state.token_matches(tok) => next.run(req).await,
        _ => (StatusCode::UNAUTHORIZED, "invalid or missing token").into_response(),
    }
}

async fn get_status(State(state): State<Arc<SharedState>>) -> Json<Status> {
    let rules = state.rules.read().unwrap();
    let active = state.active.read().unwrap();
    let cursor = state.events.lock().unwrap().next_seq - 1;
    Json(Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.started.elapsed().as_secs(),
        interfaces: state.interfaces.clone(),
        protected_prefixes: rules.protected.len(),
        active_mitigations: active.len(),
        learned_ports: state.ports.read().unwrap().len(),
        events_cursor: cursor,
    })
}

async fn get_ports(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<PortsQuery>,
) -> Json<PortsPage> {
    let all = state.ports.read().unwrap();
    let needle = q.q.trim().to_lowercase();
    let matches = |p: &LearnedPort| {
        needle.is_empty()
            || format!("{} {} {}", p.ip, p.port, p.proto)
                .to_lowercase()
                .contains(&needle)
    };
    let total = all.iter().filter(|p| matches(p)).count();
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let items: Vec<LearnedPort> = all
        .iter()
        .filter(|p| matches(p))
        .skip(q.offset)
        .take(limit)
        .cloned()
        .collect();
    Json(PortsPage {
        total,
        offset: q.offset,
        limit,
        items,
    })
}

async fn get_tracked(State(state): State<Arc<SharedState>>) -> Json<Vec<TrackedIp>> {
    Json(state.tracked.read().unwrap().clone())
}

async fn get_prefixes(State(state): State<Arc<SharedState>>) -> Json<Vec<PrefixLoad>> {
    Json(state.prefixes.read().unwrap().clone())
}

async fn get_limits(State(state): State<Arc<SharedState>>) -> Json<Limits> {
    Json(*state.limits.read().unwrap())
}

/// Live-edit the detection thresholds. Held in memory (not persisted); the
/// control loop reloads them on the next tick.
async fn put_limits(State(state): State<Arc<SharedState>>, Json(l): Json<Limits>) -> Response {
    let thresholds = [l.pps, l.syn_pps, l.bps, l.net_pps, l.net_syn_pps, l.net_bps];
    if thresholds.contains(&0) {
        return (StatusCode::BAD_REQUEST, "all thresholds must be > 0").into_response();
    }
    if l.exit_pct == 0 || l.exit_pct >= 100 {
        return (StatusCode::BAD_REQUEST, "exit_pct must be 1..99").into_response();
    }
    *state.limits.write().unwrap() = l;
    state.limits_version.fetch_add(1, Ordering::Relaxed);
    StatusCode::NO_CONTENT.into_response()
}

async fn get_rules(State(state): State<Arc<SharedState>>) -> Json<RuleSet> {
    Json(state.rules.read().unwrap().clone())
}

async fn put_rules(
    State(state): State<Arc<SharedState>>,
    Json(new_rules): Json<RuleSet>,
) -> Response {
    // Reject malformed CIDRs up front so a bad push can't silently no-op.
    for c in &new_rules.protected {
        if parse_cidr(c).is_none() {
            return (StatusCode::BAD_REQUEST, format!("bad protected cidr: {c}")).into_response();
        }
    }
    for o in &new_rules.overrides {
        if parse_cidr(&o.cidr).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                format!("bad override cidr: {}", o.cidr),
            )
                .into_response();
        }
    }
    *state.rules.write().unwrap() = new_rules;
    state.bump_rules();
    StatusCode::NO_CONTENT.into_response()
}

async fn get_mitigations(State(state): State<Arc<SharedState>>) -> Json<Vec<Mitigation>> {
    Json(state.active.read().unwrap().clone())
}

async fn post_override(
    State(state): State<Arc<SharedState>>,
    Json(ov): Json<Override>,
) -> Response {
    if parse_cidr(&ov.cidr).is_none() {
        return (StatusCode::BAD_REQUEST, format!("bad cidr: {}", ov.cidr)).into_response();
    }
    {
        let mut rules = state.rules.write().unwrap();
        rules.overrides.retain(|o| o.cidr != ov.cidr);
        rules.overrides.push(ov);
    }
    state.bump_rules();
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, Deserialize)]
struct CidrQuery {
    cidr: String,
}

async fn delete_override(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<CidrQuery>,
) -> Response {
    let removed = {
        let mut rules = state.rules.write().unwrap();
        let before = rules.overrides.len();
        rules.overrides.retain(|o| o.cidr != q.cidr);
        before != rules.overrides.len()
    };
    if removed {
        state.bump_rules();
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Debug, Deserialize)]
struct SinceQuery {
    #[serde(default)]
    since: u64,
}

/// `GET /api/v1/events?since=<cursor>` — kept as a free item so the daemon can
/// register it without exposing the ring type.
async fn get_events(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<SinceQuery>,
) -> Json<EventsResponse> {
    let (events, cursor) = state.events.lock().unwrap().since(q.since);
    Json(EventsResponse { events, cursor })
}

/// Response for the events poll: the new events plus the cursor to poll from
/// next time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<Event>,
    pub cursor: u64,
}

/// A page of learned ports: `total` is the full (filtered) count, `items` is the
/// requested slice. Keeps the payload bounded even with tens of thousands of
/// learned ports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsPage {
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub items: Vec<LearnedPort>,
}

#[derive(Debug, Deserialize)]
struct PortsQuery {
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
    #[serde(default)]
    q: String,
}

/// TLS material for the HTTPS listener: PEM cert chain + private key.
pub struct TlsPem {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// True if this was freshly self-signed (for logging).
    pub self_signed: bool,
}

/// Load the configured cert/key, or generate a self-signed cert covering
/// `localhost` + the listen IP so HTTPS always works out of the box.
pub fn load_or_generate_tls(
    cert_path: Option<&std::path::Path>,
    key_path: Option<&std::path::Path>,
    listen_ip: IpAddr,
) -> anyhow::Result<TlsPem> {
    if let (Some(c), Some(k)) = (cert_path, key_path) {
        let cert_pem =
            std::fs::read(c).map_err(|e| anyhow::anyhow!("read tls cert {}: {e}", c.display()))?;
        let key_pem =
            std::fs::read(k).map_err(|e| anyhow::anyhow!("read tls key {}: {e}", k.display()))?;
        return Ok(TlsPem {
            cert_pem,
            key_pem,
            self_signed: false,
        });
    }
    // Self-sign for localhost + the listen address.
    let mut sans = vec!["localhost".to_string()];
    if !listen_ip.is_unspecified() {
        sans.push(listen_ip.to_string());
    }
    let cert = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| anyhow::anyhow!("self-signed cert generation failed: {e}"))?;
    Ok(TlsPem {
        cert_pem: cert.cert.pem().into_bytes(),
        key_pem: cert.key_pair.serialize_pem().into_bytes(),
        self_signed: true,
    })
}

/// Install the process-wide rustls crypto provider (ring) once. Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Self-contained internal dashboard: plain HTML + vanilla JS, no external
/// assets. Prompts once for the API token (kept in localStorage) and polls the
/// JSON API to render status, active mitigations, rules, and the event stream.
const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>lnvps_fw dashboard</title>
<style>
  :root { color-scheme: dark; }
  body { font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 0; background: #0e1116; color: #d6deeb; }
  header { display: flex; gap: .75rem; align-items: center; flex-wrap: wrap;
           padding: .75rem 1rem; background: #161b22; border-bottom: 1px solid #2b3138; }
  header h1 { font-size: 1rem; margin: 0; font-weight: 600; color: #7fd1ff; }
  .grow { flex: 1; }
  input { background: #0e1116; color: #d6deeb; border: 1px solid #2b3138;
          border-radius: 4px; padding: .35rem .5rem; font: inherit; }
  button { background: #1f6feb; color: #fff; border: 0; border-radius: 4px;
           padding: .3rem .6rem; font: inherit; cursor: pointer; }
  button:disabled { opacity: .4; cursor: default; }
  button.ghost { background: #21262d; }
  main { padding: 1rem; display: grid; gap: 1rem;
         grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); }
  section { background: #161b22; border: 1px solid #2b3138; border-radius: 8px;
            padding: .75rem 1rem; min-width: 0; }
  .wide { grid-column: 1 / -1; }
  section h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em;
               margin: 0 0 .6rem; color: #8b949e; display: flex; gap: .5rem; align-items: center; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .25rem .5rem; border-bottom: 1px solid #21262d; white-space: nowrap; }
  th { color: #8b949e; font-weight: 600; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .75rem; }
  .kv div:nth-child(odd) { color: #8b949e; }
  .flag { color: #f0b429; }
  .muted { color: #6b7684; }
  .err { color: #ff6b6b; }
  .pager { display: flex; gap: .5rem; align-items: center; margin-top: .5rem; }
  .scroll { max-height: 420px; overflow: auto; }
  .limits { display: flex; flex-wrap: wrap; gap: .6rem 1rem; align-items: flex-end; }
  .limits label { display: inline-flex; flex-direction: column; font-size: .72rem; color: #8b949e; gap: .2rem; }
  .limits input { width: 7.5rem; }
  .limits .act { display: flex; gap: .5rem; align-items: center; width: 100%; margin-top: .2rem; }
  .barwrap { display: inline-flex; align-items: center; gap: .4rem; }
  .bar { background: #21262d; border-radius: 4px; height: 10px; width: 120px; overflow: hidden; display: inline-block; }
  .bar .fill { display: block; height: 100%; }
</style>
</head>
<body>
<div id="app"></div>
<script type="module">
import { h, render } from 'https://esm.sh/preact@10.24.3';
import { useState, useEffect, useRef, useCallback } from 'https://esm.sh/preact@10.24.3/hooks';
import htm from 'https://esm.sh/htm@3.1.1';
const html = htm.bind(h);

const FLAGS = [[1,'PORT_FILTER'],[2,'SYN_PROXY'],[4,'RATE_CAPS'],[8,'SOURCE_BLOCK']];
const flagStr = f => { const o = FLAGS.filter(([b])=>f&b).map(([,n])=>n); return o.length?o.join('|'):'none'; };
const fmtn = n => n>=1e6 ? (n/1e6).toFixed(1)+'M' : n>=1e3 ? (n/1e3).toFixed(1)+'k' : ''+n;
const fmtbps = b => { const x=b*8; return x>=1e9?(x/1e9).toFixed(2)+' Gb/s':x>=1e6?(x/1e6).toFixed(1)+' Mb/s':x>=1e3?(x/1e3).toFixed(0)+' kb/s':x+' b/s'; };
const flagCell = f => html`<span class="flag">${flagStr(f)}</span>`;
const time = t => new Date(t*1000).toLocaleTimeString();
const loadColor = p => p>=100?'#ff6b6b':p>=80?'#f0b429':p>=50?'#7fd1ff':'#3fb950';
function LoadBar({ pct }) {
  const p = Math.min(pct, 100), c = loadColor(pct);
  return html`<span class="barwrap">
    <span class="bar"><span class="fill" style=${'width:'+p+'%;background:'+c}></span></span>
    <span style=${'color:'+c+';font-weight:600'}>${pct}%</span></span>`;
}


async function api(path, token) {
  const r = await fetch(path, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
  if (!r.ok) throw new Error(path.split('?')[0] + ' -> ' + r.status);
  return r.status === 204 ? null : r.json();
}

function Table({ cols, rows }) {
  if (!rows.length) return html`<div class="muted">none</div>`;
  return html`<table>
    <thead><tr>${cols.map(c => html`<th>${c}</th>`)}</tr></thead>
    <tbody>${rows.map(r => html`<tr>${r.map(c => html`<td>${c}</td>`)}</tr>`)}</tbody>
  </table>`;
}

function Pager({ page, pages, total, onPage }) {
  return html`<div class="pager">
    <button class="ghost" disabled=${page<=0} onClick=${()=>onPage(page-1)}>‹ prev</button>
    <span class="muted">page ${page+1}/${pages} · ${total} rows</span>
    <button class="ghost" disabled=${page>=pages-1} onClick=${()=>onPage(page+1)}>next ›</button>
  </div>`;
}

// Client-side paginated table (for bounded datasets).
function PagedTable({ cols, rows, pageSize = 50 }) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const p = Math.min(page, pages - 1);
  const slice = rows.slice(p * pageSize, p * pageSize + pageSize);
  return html`<div class="scroll"><${Table} cols=${cols} rows=${slice} /></div>
    ${rows.length > pageSize && html`<${Pager} page=${p} pages=${pages} total=${rows.length} onPage=${setPage} />`}`;
}

function Section({ title, extra, children, wide }) {
  return html`<section class=${wide?'wide':''}>
    <h2>${title}${extra?html`<span class="muted">${extra}</span>`:null}</h2>${children}</section>`;
}

// Live-editable detection thresholds. Seeds from GET /limits once so the 2s
// poll doesn't clobber edits; PUT on save.
function LimitsCard({ token }) {
  const [f, setF] = useState(null);
  const [msg, setMsg] = useState('');
  useEffect(() => { (async () => { try { setF(await api('/api/v1/limits', token)); } catch (e) {} })(); }, [token]);
  if (!f) return html`<div class="muted">…</div>`;
  const num = k => e => setF({ ...f, [k]: Math.max(0, Math.floor(+e.target.value || 0)) });
  const fld = (k, label) => html`<label>${label}<input type="number" min="1" value=${f[k]} onInput=${num(k)} /></label>`;
  const save = async () => {
    setMsg('saving…');
    try {
      const r = await fetch('/api/v1/limits', { method: 'PUT',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify(f) });
      setMsg(r.ok ? 'saved ✓' : 'error ' + r.status + ': ' + (await r.text()));
    } catch (e) { setMsg(e.message); }
  };
  const reload = async () => { setMsg(''); try { setF(await api('/api/v1/limits', token)); } catch (e) {} };
  return html`<div class="limits">
    ${fld('pps','IP pps')}${fld('syn_pps','IP syn/s')}${fld('bps','IP bytes/s')}
    ${fld('net_pps','prefix pps')}${fld('net_syn_pps','prefix syn/s')}${fld('net_bps','prefix bytes/s')}
    ${fld('exit_pct','exit %')}${fld('cooldown_secs','cooldown s')}
    <div class="act"><button onClick=${save}>save</button><button class="ghost" onClick=${reload}>reset</button>
      <span class="muted">${msg}</span></div>
  </div>`;
}

// Server-side paginated + filtered learned-ports table.
function PortsCard({ token }) {
  const PAGE = 50;
  const [q, setQ] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState({ total: 0, items: [] });
  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ offset: page*PAGE, limit: PAGE, q });
      const d = await api('/api/v1/ports?' + params, token);
      setData(d);
    } catch (e) { /* surfaced by the main poller */ }
  }, [token, q, page]);
  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id); }, [load]);
  const pages = Math.max(1, Math.ceil(data.total / PAGE));
  const rows = data.items.map(p => [p.ip, p.port, p.proto, p.age_secs + 's']);
  return html`<${Section} wide=true title="Learned open ports" extra=${'(' + data.total + ')'}>
    <input placeholder="filter ip/port/proto" value=${q}
      onInput=${e => { setPage(0); setQ(e.target.value); }} style="margin-bottom:.5rem" />
    <div class="scroll"><${Table} cols=${['ip','port','proto','age']} rows=${rows} /></div>
    ${data.total > PAGE && html`<${Pager} page=${Math.min(page,pages-1)} pages=${pages} total=${data.total} onPage=${setPage} />`}
  </${Section}>`;
}

function App() {
  const [token, setTokenState] = useState(localStorage.getItem('fwtoken') || '');
  const [auto, setAuto] = useState(true);
  const [d, setD] = useState({ status: null, tracked: [], prefixes: [], mitigations: [], rules: { protected: [], overrides: [] }, err: '' });
  const [events, setEvents] = useState([]);
  const cursor = useRef(0);
  const tokenRef = useRef(token);
  tokenRef.current = token;

  const refresh = useCallback(async () => {
    const t = tokenRef.current;
    try {
      const [status, tracked, prefixes, mitigations, rules] = await Promise.all([
        api('/api/v1/status', t), api('/api/v1/tracked', t), api('/api/v1/prefixes', t),
        api('/api/v1/mitigations', t), api('/api/v1/rules', t),
      ]);
      const ev = await api('/api/v1/events?since=' + cursor.current, t);
      if (ev.events.length) { cursor.current = ev.cursor; setEvents(e => [...ev.events.slice().reverse(), ...e].slice(0, 500)); }
      setD({ status, tracked, prefixes, mitigations, rules, err: '' });
    } catch (e) { setD(x => ({ ...x, err: e.message })); }
  }, []);

  useEffect(() => {
    refresh();
    if (!auto) return;
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, [auto, token, refresh]);

  const save = () => { localStorage.setItem('fwtoken', token); cursor.current = 0; setEvents([]); refresh(); };
  const s = d.status;
  const summary = d.err ? html`<span class="err">${d.err}</span>`
    : s ? html`<span class="muted">up ${s.uptime_secs}s · ${s.active_mitigations} active · ${s.learned_ports} ports</span>`
    : html`<span class="muted">disconnected</span>`;

  const trackedRows = d.tracked.map(t => [t.ip, fmtn(t.pps), fmtbps(t.bps), fmtn(t.syn_pps), fmtn(t.drop_pps),
    html`<${LoadBar} pct=${t.load_pct} />`, t.mitigating ? flagCell(t.flags) : 'ok']);
  const prefixRows = d.prefixes.map(p => [p.cidr, fmtn(p.pps), fmtbps(p.bps), fmtn(p.syn_pps),
    html`<${LoadBar} pct=${p.load_pct} />`, p.mitigating ? flagCell(p.flags) : 'ok']);
  const mitRows = d.mitigations.map(m => [m.cidr, flagCell(m.flags), time(m.since_unix), m.manual?'yes':'',
    fmtn(m.peak_pps), fmtbps(m.peak_bps), fmtn(m.peak_syn_pps)]);
  const evRows = events.map(e => [e.seq, time(e.ts_unix), e.kind, e.cidr, flagCell(e.flags), fmtn(e.pps), fmtn(e.syn_pps)]);

  return html`
    <header>
      <h1>lnvps_fw</h1>${summary}<span class="grow"></span>
      <input type="password" placeholder="API token" size="26" value=${token}
        onInput=${e => setTokenState(e.target.value)} onKeyDown=${e => e.key==='Enter' && save()} />
      <button onClick=${save}>connect</button>
      <label class="muted"><input type="checkbox" checked=${auto} onChange=${e => setAuto(e.target.checked)} /> auto</label>
      <button class="ghost" onClick=${refresh}>refresh</button>
    </header>
    <main>
      <${Section} title="Status">
        ${s ? html`<div class="kv">
          <div>version</div><div>${s.version}</div>
          <div>uptime</div><div>${s.uptime_secs}s</div>
          <div>interfaces</div><div>${s.interfaces.join(', ')||'—'}</div>
          <div>protected prefixes</div><div>${s.protected_prefixes}</div>
          <div>active mitigations</div><div>${s.active_mitigations}</div>
          <div>learned ports</div><div>${s.learned_ports}</div>
        </div>` : html`<div class="muted">enter token and connect</div>`}
      </${Section}>
      <${Section} wide=true title="Detection limits">
        <${LimitsCard} token=${token} />
      </${Section}>
      <${Section} wide=true title="Active mitigations" extra=${'('+d.mitigations.length+')'}>
        <${PagedTable} cols=${['cidr','flags','since','manual','peak pps','peak bps','peak syn/s']} rows=${mitRows} />
      </${Section}>
      <${Section} wide=true title="Live tracked IPs" extra=${'('+d.tracked.length+')'}>
        <${PagedTable} cols=${['ip','pps','bps','syn/s','drop/s','load','state']} rows=${trackedRows} />
      </${Section}>
      <${Section} wide=true title="Protected prefixes" extra=${'('+d.prefixes.length+')'}>
        <${PagedTable} cols=${['prefix','pps','bps','syn/s','load','state']} rows=${prefixRows} />
      </${Section}>
      <${Section} title="Manual overrides">
        <${Table} cols=${['cidr','flags']} rows=${d.rules.overrides.map(o=>[o.cidr, flagCell(o.flags)])} />
      </${Section}>
      <${PortsCard} token=${token} />
      <${Section} wide=true title="Events" extra=${'('+events.length+')'}>
        <${PagedTable} cols=${['seq','time','kind','cidr','flags','pps','syn/s']} rows=${evRows} />
      </${Section}>
    </main>`;
}

render(html`<${App} />`, document.getElementById('app'));
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_families_and_bare_addrs() {
        assert_eq!(
            parse_cidr("203.0.113.0/24"),
            Some(CidrKey::V4 {
                bits: 24,
                net: [203, 0, 113, 0]
            })
        );
        assert!(matches!(
            parse_cidr("2001:db8::/48"),
            Some(CidrKey::V6 { bits: 48, .. })
        ));
        // Bare address -> host route.
        assert_eq!(
            parse_cidr("10.0.0.1"),
            Some(CidrKey::V4 {
                bits: 32,
                net: [10, 0, 0, 1]
            })
        );
        assert!(parse_cidr("not-an-ip").is_none());
        assert!(parse_cidr("10.0.0.0/40").is_none());
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreu"));
        assert!(!constant_time_eq(b"secret", b"secre"));
    }

    #[test]
    fn event_ring_cursor_and_overflow() {
        let mut ring = EventRing::new(2);
        ring.push(EventKind::Start, "a/32".into(), 1, 0, 0, 0);
        ring.push(EventKind::Start, "b/32".into(), 1, 0, 0, 0);
        ring.push(EventKind::Start, "c/32".into(), 1, 0, 0, 0);
        // Cap 2 -> oldest (seq 1) dropped.
        let (evs, cursor) = ring.since(0);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].seq, 2);
        assert_eq!(cursor, 3);
        // Incremental poll from the returned cursor yields nothing new.
        let (evs2, cursor2) = ring.since(cursor);
        assert!(evs2.is_empty());
        assert_eq!(cursor2, 3);
    }

    #[test]
    fn tls_self_signed_generates_pem() {
        let tls =
            load_or_generate_tls(None, None, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).unwrap();
        assert!(tls.self_signed);
        assert!(
            String::from_utf8_lossy(&tls.cert_pem).contains("BEGIN CERTIFICATE"),
            "cert PEM present"
        );
        assert!(
            String::from_utf8_lossy(&tls.key_pem).contains("PRIVATE KEY"),
            "key PEM present"
        );
    }

    #[test]
    fn ip_allow_list_semantics() {
        let open = SharedState::new("t".into(), vec![], vec![], RuleSet::default(), 8);
        assert!(open.ip_allowed(None), "empty allow-list permits all");
        let restricted = SharedState::new(
            "t".into(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            vec![],
            RuleSet::default(),
            8,
        );
        assert!(restricted.ip_allowed(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))));
        assert!(!restricted.ip_allowed(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)))));
        assert!(!restricted.ip_allowed(None));
    }
}
