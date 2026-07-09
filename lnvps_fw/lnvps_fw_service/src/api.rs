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
    ports: RwLock<Vec<LearnedPort>>,
    events: Mutex<EventRing>,
    /// Bumped whenever the ruleset changes so the control loop reloads it.
    rules_version: AtomicU64,
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
            ports: RwLock::new(Vec::new()),
            events: Mutex::new(EventRing::new(events_cap)),
            rules_version: AtomicU64::new(1),
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

async fn get_ports(State(state): State<Arc<SharedState>>) -> Json<Vec<LearnedPort>> {
    Json(state.ports.read().unwrap().clone())
}

async fn get_tracked(State(state): State<Arc<SharedState>>) -> Json<Vec<TrackedIp>> {
    Json(state.tracked.read().unwrap().clone())
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
const DASHBOARD_HTML: &str = r#"<!doctype html>
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
  header .grow { flex: 1; }
  input { background: #0e1116; color: #d6deeb; border: 1px solid #2b3138;
          border-radius: 4px; padding: .35rem .5rem; font: inherit; }
  button { background: #1f6feb; color: #fff; border: 0; border-radius: 4px;
           padding: .35rem .7rem; font: inherit; cursor: pointer; }
  button.ghost { background: #21262d; }
  main { padding: 1rem; display: grid; gap: 1rem;
         grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); }
  section { background: #161b22; border: 1px solid #2b3138; border-radius: 8px;
            padding: .75rem 1rem; }
  section h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em;
               margin: 0 0 .6rem; color: #8b949e; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .25rem .5rem; border-bottom: 1px solid #21262d;
           white-space: nowrap; }
  th { color: #8b949e; font-weight: 600; }
  .kv { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .75rem; }
  .kv div:nth-child(odd) { color: #8b949e; }
  .pill { display: inline-block; padding: 0 .4rem; border-radius: 10px; font-size: .8em;
          background: #21262d; }
  .flag { color: #f0b429; }
  .err { color: #ff6b6b; }
  .muted { color: #6b7684; }
  #events td:first-child { color: #6b7684; }
</style>
</head>
<body>
<header>
  <h1>lnvps_fw</h1>
  <span id="summary" class="muted">disconnected</span>
  <span class="grow"></span>
  <input id="token" type="password" placeholder="API token" size="28">
  <button id="save">connect</button>
  <label class="muted"><input id="auto" type="checkbox" checked> auto</label>
  <button id="refresh" class="ghost">refresh</button>
</header>
<main>
  <section><h2>Status</h2><div id="status" class="kv"></div></section>
  <section style="grid-column: 1 / -1"><h2>Active mitigations</h2><div id="mit"></div></section>
  <section style="grid-column: 1 / -1"><h2>Live tracked IPs <span id="trackcount" class="muted"></span></h2>
    <div id="tracked" style="max-height: 340px; overflow: auto"></div></section>
  <section><h2>Protected prefixes</h2><div id="protected"></div></section>
  <section><h2>Manual overrides</h2><div id="overrides"></div></section>
  <section style="grid-column: 1 / -1"><h2>Learned open ports <span id="portcount" class="muted"></span></h2>
    <input id="portfilter" placeholder="filter ip/port/proto" size="22">
    <div id="ports" style="max-height: 340px; overflow: auto"></div></section>
  <section style="grid-column: 1 / -1"><h2>Events</h2><div id="events"></div></section>
</main>
<script>
const $ = s => document.querySelector(s);
let cursor = 0, evbuf = [], timer = null;
const FLAGS = [[1,'PORT_FILTER'],[2,'SYN_PROXY'],[4,'RATE_CAPS'],[8,'SOURCE_BLOCK']];
const flagStr = f => { const o = FLAGS.filter(([b])=>f&b).map(([,n])=>n); return o.length?o.join('|'):'none'; };
$('#token').value = localStorage.getItem('fwtoken') || '';
async function api(path) {
  const t = $('#token').value.trim();
  const r = await fetch(path, { headers: t ? { Authorization: 'Bearer ' + t } : {} });
  if (!r.ok) throw new Error(path + ' -> ' + r.status);
  return r.status === 204 ? null : r.json();
}
function table(cols, rows) {
  if (!rows.length) return '<div class="muted">none</div>';
  const h = '<tr>' + cols.map(c=>'<th>'+c+'</th>').join('') + '</tr>';
  const b = rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('');
  return '<table>'+h+b+'</table>';
}
function kv(obj) { return Object.entries(obj).map(([k,v])=>'<div>'+k+'</div><div>'+v+'</div>').join(''); }
function fmtn(n){ return n>=1e6 ? (n/1e6).toFixed(1)+'M' : n>=1e3 ? (n/1e3).toFixed(1)+'k' : ''+n; }
function fmtbps(b){ const bits=b*8; return bits>=1e9 ? (bits/1e9).toFixed(2)+' Gb/s' : bits>=1e6 ? (bits/1e6).toFixed(1)+' Mb/s' : bits>=1e3 ? (bits/1e3).toFixed(0)+' kb/s' : bits+' b/s'; }
async function refresh() {
  try {
    const st = await api('/api/v1/status');
    $('#status').innerHTML = kv({
      version: st.version, uptime: st.uptime_secs + 's',
      interfaces: st.interfaces.join(', ') || '—',
      'protected prefixes': st.protected_prefixes,
      'active mitigations': st.active_mitigations,
      'events cursor': st.events_cursor });
    $('#summary').textContent = 'up ' + st.uptime_secs + 's · ' + st.active_mitigations + ' active';
    $('#summary').className = '';
    const mit = await api('/api/v1/mitigations');
    $('#mit').innerHTML = table(['cidr','flags','since','manual','peak pps','peak bps','peak syn/s'],
      mit.map(m=>[m.cidr, '<span class=flag>'+flagStr(m.flags)+'</span>',
        new Date(m.since_unix*1000).toLocaleTimeString(), m.manual?'yes':'', m.peak_pps, m.peak_bps, m.peak_syn_pps]));
    const tracked = await api('/api/v1/tracked');
    $('#trackcount').textContent = '('+tracked.length+')';
    $('#tracked').innerHTML = table(['ip','pps','bps','syn/s','drop/s','state'],
      tracked.map(t=>[t.ip, fmtn(t.pps), fmtbps(t.bps), fmtn(t.syn_pps), fmtn(t.drop_pps),
        t.mitigating ? '<span class=flag>'+flagStr(t.flags)+'</span>' : 'ok']));
    const rules = await api('/api/v1/rules');
    $('#protected').innerHTML = table(['prefix'], rules.protected.map(p=>[p]));
    $('#overrides').innerHTML = table(['cidr','flags'], rules.overrides.map(o=>[o.cidr,'<span class=flag>'+flagStr(o.flags)+'</span>']));
    let ports = await api('/api/v1/ports');
    const f = $('#portfilter').value.trim().toLowerCase();
    if (f) ports = ports.filter(p => (p.ip+' '+p.port+' '+p.proto).toLowerCase().includes(f));
    ports.sort((a,b)=> a.ip.localeCompare(b.ip) || a.port-b.port);
    $('#portcount').textContent = '('+ports.length+')';
    $('#ports').innerHTML = table(['ip','port','proto','age'],
      ports.map(p=>[p.ip, p.port, p.proto, p.age_secs+'s']));
    const ev = await api('/api/v1/events?since=' + cursor);
    cursor = ev.cursor;
    if (ev.events.length) { evbuf = ev.events.concat(evbuf).slice(0, 200); }
    $('#events').innerHTML = table(['seq','time','kind','cidr','flags','pps','syn/s'],
      evbuf.map(e=>[e.seq, new Date(e.ts_unix*1000).toLocaleTimeString(), e.kind, e.cidr,
        '<span class=flag>'+flagStr(e.flags)+'</span>', e.pps, e.syn_pps]));
  } catch (e) {
    $('#summary').textContent = e.message; $('#summary').className = 'err';
  }
}
function schedule() { clearInterval(timer); if ($('#auto').checked) timer = setInterval(refresh, 2000); }
$('#save').onclick = () => { localStorage.setItem('fwtoken', $('#token').value.trim()); cursor=0; evbuf=[]; refresh(); };
$('#refresh').onclick = refresh;
$('#auto').onchange = schedule;
refresh(); schedule();
</script>
</body>
</html>
"#;

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
