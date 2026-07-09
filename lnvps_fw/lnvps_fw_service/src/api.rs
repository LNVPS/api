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
use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::{Json, Router, middleware};
use serde::{Deserialize, Serialize};

/// Maximum number of entries accepted in any one list of a pushed ruleset.
pub const MAX_RULESET_ENTRIES: usize = 100_000;

/// Maximum accepted request body size (bytes). Comfortably fits a full ruleset
/// of `MAX_RULESET_ENTRIES` CIDR strings while rejecting absurd payloads.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

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
            // Mask host bits so the key is canonical: `203.0.113.5/24` and
            // `203.0.113.0/24` parse to the same key (stable dedup/removal).
            Some(CidrKey::V4 {
                bits,
                net: crate::cidr::mask_v4(v4.octets(), bits),
            })
        }
        IpAddr::V6(v6) => {
            let bits = len.map_or(Some(128), |l| l.parse().ok())?;
            if bits > 128 {
                return None;
            }
            Some(CidrKey::V6 {
                bits,
                net: crate::cidr::mask_v6(v6.octets(), bits),
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
    /// Manual mitigation overrides (force-mitigate a destination).
    pub overrides: Vec<Override>,
    /// Manual source-CIDR blocks (drop an attacker range).
    pub source_blocks: Vec<String>,
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
    /// RX (ingress) packets/second into this IP.
    pub rx_pps: u64,
    /// RX (ingress) bytes/second into this IP.
    pub rx_bps: u64,
    /// RX (ingress) TCP SYNs/second into this IP.
    pub rx_syn_pps: u64,
    /// RX (ingress) packets/second dropped by protection.
    pub rx_drop_pps: u64,
    /// TX (egress) packets/second out of this IP (from the TC program).
    pub tx_pps: u64,
    /// TX (egress) bytes/second out of this IP.
    pub tx_bps: u64,
    /// Percentage of this IP's RX packets currently being dropped.
    pub rx_drop_pct: u32,
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
    /// RX (ingress) aggregate rates for this prefix.
    pub rx_pps: u64,
    pub rx_bps: u64,
    pub rx_syn_pps: u64,
    pub rx_drop_pps: u64,
    /// Aggregate TX (egress) rates for this prefix.
    pub tx_pps: u64,
    pub tx_bps: u64,
    /// Percentage of this prefix's RX packets currently being dropped.
    pub rx_drop_pct: u32,
    pub mitigating: bool,
    pub flags: u32,
    /// Aggregate load as a percentage of the network thresholds (>=100 =
    /// carpet-bomb mitigation trips for the whole prefix).
    pub load_pct: u32,
}

/// Top-level aggregate traffic across every tracked destination this tick.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Totals {
    /// RX (ingress) aggregate.
    pub rx_pps: u64,
    pub rx_bps: u64,
    pub rx_syn_pps: u64,
    pub rx_drop_pps: u64,
    /// Percentage of all RX packets currently being dropped.
    pub rx_drop_pct: u32,
    /// TX (egress) aggregate.
    pub tx_pps: u64,
    pub tx_bps: u64,
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

/// An active blocked source CIDR (from SOURCE_BLOCK escalation of a real,
/// bounded botnet).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceBlock {
    pub cidr: String,
    /// Seconds since this block was last refreshed (it decays after the TTL).
    /// Ignored for manual blocks (they are permanent).
    pub age_secs: u64,
    /// Current aggregate packets/second from sources under this CIDR (0 for
    /// manual blocks — their traffic is dropped before per-source counting).
    pub pps: u64,
    /// True = operator-pushed manual block (permanent); false = auto from the
    /// per-source state machine (released on hysteresis).
    pub manual: bool,
    /// For auto blocks: true if the block's sources have fallen below the exit
    /// threshold and are cooling down toward release (vs actively over-rate).
    /// Always false for manual blocks.
    #[serde(default)]
    pub cooling: bool,
}

/// A page of source blocks (bounded payload even with very large block sets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksPage {
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub items: Vec<SourceBlock>,
}

#[derive(Debug, Deserialize)]
struct BlocksQuery {
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
    #[serde(default)]
    q: String,
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
    /// Aggregate live traffic across all tracked destinations.
    pub totals: Totals,
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
    blocks: RwLock<Vec<SourceBlock>>,
    ports: RwLock<Vec<LearnedPort>>,
    totals: RwLock<Totals>,
    limits: RwLock<Limits>,
    upgrade: RwLock<crate::upgrade::UpgradeStatus>,
    /// GitHub owner/repo to check for self-upgrade releases.
    upgrade_repo: String,
    /// Whether `POST /upgrade` may install a release as root.
    allow_remote_upgrade: bool,
    /// Optional minisign public key gating upgrade signature verification.
    upgrade_pubkey: Option<String>,
    events: Mutex<EventRing>,
    /// Bumped whenever the ruleset changes so the control loop reloads it.
    rules_version: AtomicU64,
    /// Bumped whenever the limits are edited so the control loop reloads them.
    limits_version: AtomicU64,
}

impl SharedState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: String,
        allow_ips: Vec<IpAddr>,
        interfaces: Vec<String>,
        initial: RuleSet,
        events_cap: usize,
        upgrade_repo: String,
        allow_remote_upgrade: bool,
        upgrade_pubkey: Option<String>,
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
            blocks: RwLock::new(Vec::new()),
            ports: RwLock::new(Vec::new()),
            totals: RwLock::new(Totals::default()),
            limits: RwLock::new(Limits::default()),
            upgrade: RwLock::new(crate::upgrade::UpgradeStatus::default()),
            upgrade_repo,
            allow_remote_upgrade,
            upgrade_pubkey,
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

    /// Replace the active source-block snapshot.
    pub fn set_blocks(&self, blocks: Vec<SourceBlock>) {
        *self.blocks.write().unwrap() = blocks;
    }

    /// Replace the top-level aggregate traffic totals.
    pub fn set_totals(&self, totals: Totals) {
        *self.totals.write().unwrap() = totals;
    }

    /// Publish the detection thresholds (called at startup).
    pub fn set_limits(&self, limits: Limits) {
        *self.limits.write().unwrap() = limits;
    }

    /// GitHub owner/repo used for self-upgrade checks.
    pub fn upgrade_repo(&self) -> &str {
        &self.upgrade_repo
    }

    /// Publish the cached upgrade status (called by the periodic check task).
    pub fn set_upgrade(&self, status: crate::upgrade::UpgradeStatus) {
        *self.upgrade.write().unwrap() = status;
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
        .route(
            "/api/v1/blocks",
            get(get_blocks).post(post_block).delete(delete_block),
        )
        .route("/api/v1/limits", get(get_limits).put(put_limits))
        .route("/api/v1/upgrade", get(get_upgrade).post(post_upgrade))
        // Cap request bodies: the largest legitimate payload is a full ruleset
        // push, which is bounded by MAX_RULESET_ENTRIES short CIDR strings.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state.clone());

    let dashboard = Router::new()
        .route("/", get(dashboard))
        .route("/assets/{file}", get(asset))
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
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, DASHBOARD_CSP),
        ],
        DASHBOARD_HTML,
    )
        .into_response()
}

/// Serve a vendored front-end asset by name (same-origin only). Unknown names
/// 404. Every asset carries the strict dashboard CSP so an injected string
/// still cannot reach an external origin.
async fn asset(axum::extract::Path(file): axum::extract::Path<String>) -> Response {
    let (body, ctype): (&'static str, &str) = match file.as_str() {
        "app.js" => (ASSET_APP_JS, "text/javascript; charset=utf-8"),
        "preact.js" => (ASSET_PREACT_JS, "text/javascript; charset=utf-8"),
        "hooks.js" => (ASSET_HOOKS_JS, "text/javascript; charset=utf-8"),
        "htm.js" => (ASSET_HTM_JS, "text/javascript; charset=utf-8"),
        "app.css" => (ASSET_APP_CSS, "text/css; charset=utf-8"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, ctype),
            (header::CONTENT_SECURITY_POLICY, DASHBOARD_CSP),
        ],
        body,
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
        totals: *state.totals.read().unwrap(),
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

async fn get_blocks(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<BlocksQuery>,
) -> Json<BlocksPage> {
    // Manual blocks (from the pushed ruleset) + auto blocks (from the state
    // machine), filtered, sorted by pps (most active first), then paginated so
    // the payload stays bounded even with a very large block set.
    let mut all: Vec<SourceBlock> = state
        .rules
        .read()
        .unwrap()
        .source_blocks
        .iter()
        .map(|c| SourceBlock {
            cidr: c.clone(),
            age_secs: 0,
            pps: 0,
            manual: true,
            cooling: false,
        })
        .collect();
    all.extend(state.blocks.read().unwrap().iter().cloned());

    let needle = q.q.trim().to_lowercase();
    if !needle.is_empty() {
        all.retain(|b| b.cidr.to_lowercase().contains(&needle));
    }
    // Manual (permanent operator) blocks always pinned to the top; auto blocks
    // below, sorted by pps descending; stable cidr tiebreak.
    all.sort_by(|a, b| {
        b.manual
            .cmp(&a.manual)
            .then_with(|| b.pps.cmp(&a.pps))
            .then_with(|| a.cidr.cmp(&b.cidr))
    });
    let total = all.len();
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let items: Vec<SourceBlock> = all.into_iter().skip(q.offset).take(limit).collect();
    Json(BlocksPage {
        total,
        offset: q.offset,
        limit,
        items,
    })
}

#[derive(Debug, Deserialize)]
struct BlockReq {
    cidr: String,
}

async fn post_block(State(state): State<Arc<SharedState>>, Json(b): Json<BlockReq>) -> Response {
    let Some(key) = parse_cidr(&b.cidr) else {
        return (StatusCode::BAD_REQUEST, format!("bad cidr: {}", b.cidr)).into_response();
    };
    let cidr = key.to_cidr_string();
    {
        let mut rules = state.rules.write().unwrap();
        rules.source_blocks.retain(|c| c != &cidr);
        rules.source_blocks.push(cidr);
    }
    state.bump_rules();
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_block(
    State(state): State<Arc<SharedState>>,
    Query(q): Query<CidrQuery>,
) -> Response {
    // Canonicalize so a bare/non-masked query still matches the stored form.
    let cidr = parse_cidr(&q.cidr).map_or(q.cidr, |k| k.to_cidr_string());
    let removed = {
        let mut rules = state.rules.write().unwrap();
        let before = rules.source_blocks.len();
        rules.source_blocks.retain(|c| c != &cidr);
        before != rules.source_blocks.len()
    };
    if removed {
        state.bump_rules();
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn get_limits(State(state): State<Arc<SharedState>>) -> Json<Limits> {
    Json(*state.limits.read().unwrap())
}

async fn get_upgrade(State(state): State<Arc<SharedState>>) -> Json<crate::upgrade::UpgradeStatus> {
    Json(state.upgrade.read().unwrap().clone())
}

/// Trigger a self-upgrade: download the latest release `.deb` and install +
/// restart in a detached transient unit. Returns 202 immediately; the service
/// will restart shortly.
async fn post_upgrade(State(state): State<Arc<SharedState>>) -> Response {
    // Remote-triggered root install is opt-in only.
    if !state.allow_remote_upgrade {
        return (
            StatusCode::FORBIDDEN,
            "remote upgrade disabled (set api.allow-remote-upgrade)",
        )
            .into_response();
    }
    let (url, sha256, sig_url) = {
        let u = state.upgrade.read().unwrap();
        (u.deb_url.clone(), u.deb_sha256.clone(), u.deb_sig_url.clone())
    };
    let Some(url) = url else {
        return (StatusCode::BAD_REQUEST, "no upgrade available").into_response();
    };
    let repo = state.upgrade_repo.to_string();
    let pubkey = state.upgrade_pubkey.clone();
    tokio::spawn(async move {
        if let Err(e) =
            crate::upgrade::download_verify_install(&repo, &url, sha256, sig_url, pubkey).await
        {
            log::warn!("upgrade failed: {e}");
        }
    });
    StatusCode::ACCEPTED.into_response()
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
    Json(mut new_rules): Json<RuleSet>,
) -> Response {
    // Bound each list so a single push can't exhaust memory / spin the control
    // loop's per-tick reconciliation.
    if new_rules.protected.len() > MAX_RULESET_ENTRIES
        || new_rules.overrides.len() > MAX_RULESET_ENTRIES
        || new_rules.source_blocks.len() > MAX_RULESET_ENTRIES
    {
        return (
            StatusCode::BAD_REQUEST,
            format!("too many entries (max {MAX_RULESET_ENTRIES} per list)"),
        )
            .into_response();
    }
    // Reject malformed CIDRs up front so a bad push can't silently no-op, and
    // canonicalize (mask host bits) so dedup/removal by string is stable.
    for c in &mut new_rules.protected {
        match parse_cidr(c) {
            Some(k) => *c = k.to_cidr_string(),
            None => {
                return (StatusCode::BAD_REQUEST, format!("bad protected cidr: {c}"))
                    .into_response();
            }
        }
    }
    for o in &mut new_rules.overrides {
        match parse_cidr(&o.cidr) {
            Some(k) => o.cidr = k.to_cidr_string(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("bad override cidr: {}", o.cidr),
                )
                    .into_response();
            }
        }
    }
    for c in &mut new_rules.source_blocks {
        match parse_cidr(c) {
            Some(k) => *c = k.to_cidr_string(),
            None => {
                return (StatusCode::BAD_REQUEST, format!("bad source-block cidr: {c}"))
                    .into_response();
            }
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
    Json(mut ov): Json<Override>,
) -> Response {
    match parse_cidr(&ov.cidr) {
        Some(k) => ov.cidr = k.to_cidr_string(),
        None => return (StatusCode::BAD_REQUEST, format!("bad cidr: {}", ov.cidr)).into_response(),
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
    let cidr = parse_cidr(&q.cidr).map_or(q.cidr, |k| k.to_cidr_string());
    let removed = {
        let mut rules = state.rules.write().unwrap();
        let before = rules.overrides.len();
        rules.overrides.retain(|o| o.cidr != cidr);
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
<link rel="stylesheet" href="/assets/app.css">
<script type="importmap">
{"imports":{"preact":"/assets/preact.js","preact/hooks":"/assets/hooks.js","htm":"/assets/htm.js"}}
</script>
</head>
<body>
<div id="app"></div>
<script type="module" src="/assets/app.js"></script>
</body>
</html>
"##;

/// Vendored front-end assets, embedded at build time and served same-origin so
/// the token-entry dashboard never loads code from a third-party CDN. A strict
/// CSP (see `dashboard`/`asset` handlers) forbids any external origin.
const ASSET_APP_JS: &str = include_str!("../assets/app.js");
const ASSET_APP_CSS: &str = include_str!("../assets/app.css");
const ASSET_PREACT_JS: &str = include_str!("../assets/preact.js");
const ASSET_HOOKS_JS: &str = include_str!("../assets/hooks.js");
const ASSET_HTM_JS: &str = include_str!("../assets/htm.js");

/// Content-Security-Policy for the dashboard + assets: everything must come
/// from this origin; no external script/style/connect is permitted, so a token
/// typed into the page cannot be exfiltrated to an outside host even if one of
/// the vendored libraries were somehow malicious.
const DASHBOARD_CSP: &str = "default-src 'none'; script-src 'self' 'unsafe-inline'; \
style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; \
base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

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
    fn parse_cidr_masks_host_bits_for_canonical_dedup() {
        // Host bits are zeroed so non-canonical input collapses to one key.
        assert_eq!(
            parse_cidr("203.0.113.5/24"),
            parse_cidr("203.0.113.0/24"),
        );
        assert_eq!(
            parse_cidr("203.0.113.5/24").unwrap().to_cidr_string(),
            "203.0.113.0/24"
        );
        assert_eq!(
            parse_cidr("2001:db8::1/48").unwrap().to_cidr_string(),
            "2001:db8::/48"
        );
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
        let open = SharedState::new(
            "t".into(),
            vec![],
            vec![],
            RuleSet::default(),
            8,
            "r".into(),
            false,
            None,
        );
        assert!(open.ip_allowed(None), "empty allow-list permits all");
        let restricted = SharedState::new(
            "t".into(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            vec![],
            RuleSet::default(),
            8,
            "r".into(),
            false,
            None,
        );
        assert!(restricted.ip_allowed(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))));
        assert!(!restricted.ip_allowed(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)))));
        assert!(!restricted.ip_allowed(None));
    }
}
