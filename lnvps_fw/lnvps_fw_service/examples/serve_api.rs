//! Standalone demo of the control API + dashboard, without the eBPF datapath
//! (so it needs no root). A tiny traffic simulator mutates the shared state
//! once a second — baseline legit traffic with noise, a periodic attack that
//! ramps up on one IP (escalating PORT_FILTER -> SYN_PROXY -> SOURCE_BLOCK),
//! live drop%, aggregate totals, transition events, decaying auto-blocks and
//! aging learned ports — so the dashboard shows moving numbers.
//!
//!   cargo run -p lnvps_fw_service --example serve_api
//!   curl -k -H 'Authorization: Bearer devtoken' https://127.0.0.1:8899/api/v1/status
//!   open https://127.0.0.1:8899/   (dashboard; paste token `devtoken`)

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lnvps_fw_common::{DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, DEST_MODE_SYN_PROXY};
use lnvps_fw_service::api::{
    self, EventKind, InterfaceInfo, LearnedPort, Limits, Mitigation, Override, PrefixLoad, RuleSet,
    SharedState, SourceBlock, Totals, TrackedIp, TrackedSource,
};

// --- detection limits used by the simulator (mirrors the real defaults) ---
const LIM: Limits = Limits {
    pps: 100_000,
    syn_pps: 10_000,
    bps: 1_000_000_000,
    net_pps: 500_000,
    net_syn_pps: 50_000,
    net_bps: 5_000_000_000,
    exit_pct: 50,
    cooldown_secs: 30,
    src_rate_pps: 10_000,
    src_cooldown_secs: 10,
    syn_proxy_pps: 5_000,
    learn_leak_pps: 100,
};
const SYN_PROXY_PPS: u64 = 5_000;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Tiny dependency-free xorshift PRNG for traffic noise.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// `base` jittered by up to `pct`% either way.
    fn jitter(&mut self, base: u64, pct: u64) -> u64 {
        if base == 0 {
            return 0;
        }
        let d = base * pct / 100;
        base - d + self.next() % (2 * d + 1)
    }
}

fn load_pct(pps: u64, syn: u64, bps: u64) -> u32 {
    let r = |v: u64, t: u64| {
        if t == 0 {
            0
        } else {
            (v.saturating_mul(100) / t) as u32
        }
    };
    r(pps, LIM.pps)
        .max(r(syn, LIM.syn_pps))
        .max(r(bps, LIM.bps))
}

fn net_load_pct(pps: u64, syn: u64, bps: u64) -> u32 {
    let r = |v: u64, t: u64| {
        if t == 0 {
            0
        } else {
            (v.saturating_mul(100) / t) as u32
        }
    };
    r(pps, LIM.net_pps)
        .max(r(syn, LIM.net_syn_pps))
        .max(r(bps, LIM.net_bps))
}

fn drop_pct(drop_pps: u64, pps: u64) -> u32 {
    if pps == 0 {
        0
    } else {
        (drop_pps.saturating_mul(100) / pps).min(100) as u32
    }
}

/// A simulated destination and its baseline (steady-state) rates.
struct Host {
    ip: &'static str,
    v6: bool,
    base_pps: u64,
    base_bps: u64,
    base_syn: u64,
    /// True if this host is the periodic attack target.
    target: bool,
}

/// Rates produced for one host on one tick.
struct Sample {
    pps: u64,
    bps: u64,
    syn: u64,
    drop_pps: u64,
    tx_pps: u64,
    tx_bps: u64,
    flags: u32,
}

/// Attack intensity in [0.0, 1.0] on tick `t`, as a triangle over a 90s cycle
/// (rise 10..30, hold-ish peak, fall 30..50, quiet otherwise). The longer,
/// less frequent window reads more like a real incident than a constant flap.
fn attack_intensity(t: u64) -> f64 {
    let w = t % 90;
    if (10..50).contains(&w) {
        let x = w - 10; // 0..40
        if x < 20 {
            x as f64 / 20.0
        } else {
            (40 - x) as f64 / 20.0
        }
    } else {
        0.0
    }
}

/// Slow "day/night" breathing applied to every host's baseline so the numbers
/// drift over minutes instead of only jittering tick-to-tick. ~3min period,
/// swinging between ~0.55x (quiet hours) and ~1.25x (peak).
fn diurnal(t: u64) -> f64 {
    let phase = (t % 180) as f64 / 180.0 * std::f64::consts::TAU;
    0.9 + 0.35 * phase.cos()
}

fn sample_host(h: &Host, t: u64, day: f64, rng: &mut Rng) -> Sample {
    // Effective baseline for this tick, after the diurnal drift.
    let base_pps = (h.base_pps as f64 * day) as u64;
    let base_bps = (h.base_bps as f64 * day) as u64;
    let base_syn = (h.base_syn as f64 * day) as u64;
    let mut pps = rng.jitter(base_pps, 15);
    let mut bps = rng.jitter(base_bps, 15);
    let mut syn = rng.jitter(base_syn, 25);
    let mut drop_pps = 0;
    let mut flags = 0;

    if h.target {
        let i = attack_intensity(t);
        if i > 0.0 {
            let atk_pps = (330_000.0 * i) as u64;
            let atk_syn = (70_000.0 * i) as u64;
            let atk_bps = (2_600_000_000.0 * i) as u64;
            pps += atk_pps;
            syn += atk_syn;
            bps += atk_bps;
            // Escalation ladder, driven by the same thresholds the daemon uses.
            if pps >= LIM.pps {
                flags |= DEST_MODE_PORT_FILTER;
            }
            if syn >= SYN_PROXY_PPS {
                flags |= DEST_MODE_SYN_PROXY;
            }
            if i >= 0.6 {
                flags |= DEST_MODE_SOURCE_BLOCK;
            }
            // Under the port filter, the attack traffic (everything above the
            // legit baseline) is dropped.
            if flags & DEST_MODE_PORT_FILTER != 0 {
                drop_pps = pps.saturating_sub(base_pps);
            }
        }
    }
    // TX (egress) is the host serving legit replies: roughly proportional to
    // its baseline RX (not the attack flood, which generates no real replies),
    // with larger response packets.
    let tx_pps = rng.jitter(base_pps * 7 / 10 + 1, 20);
    let tx_bps = rng.jitter(base_bps * 3 + 1, 20);
    Sample {
        pps,
        bps,
        syn,
        drop_pps,
        tx_pps,
        tx_bps,
        flags,
    }
}

/// Tracks active mitigations across ticks to synthesise Start/Flags/Stop events
/// and stable since/peak values — mirroring what the real control loop does.
#[derive(Default)]
struct MitBook {
    since: HashMap<String, u64>,
    peak: HashMap<String, (u64, u64, u64)>,
    prev: HashMap<String, u32>,
}

struct ActiveInput {
    cidr: String,
    flags: u32,
    pps: u64,
    bps: u64,
    syn: u64,
    manual: bool,
}

impl MitBook {
    fn step(&mut self, state: &SharedState, cur: Vec<ActiveInput>, now: u64) -> Vec<Mitigation> {
        let mut out = Vec::with_capacity(cur.len());
        let mut seen: HashSet<String> = HashSet::new();
        for m in &cur {
            seen.insert(m.cidr.clone());
            let since = *self.since.entry(m.cidr.clone()).or_insert(now);
            let peak = self.peak.entry(m.cidr.clone()).or_insert((0, 0, 0));
            peak.0 = peak.0.max(m.pps);
            peak.1 = peak.1.max(m.bps);
            peak.2 = peak.2.max(m.syn);
            // Auto mitigations emit transition events (manual ones are pushed
            // by the operator and don't).
            if !m.manual {
                match self.prev.get(&m.cidr) {
                    None => state.record_event(
                        EventKind::Start,
                        m.cidr.clone(),
                        m.flags,
                        m.pps,
                        m.bps,
                        m.syn,
                    ),
                    Some(&pf) if pf != m.flags => state.record_event(
                        EventKind::Flags,
                        m.cidr.clone(),
                        m.flags,
                        m.pps,
                        m.bps,
                        m.syn,
                    ),
                    _ => {}
                }
                self.prev.insert(m.cidr.clone(), m.flags);
            }
            out.push(Mitigation {
                cidr: m.cidr.clone(),
                flags: m.flags,
                since_unix: since,
                manual: m.manual,
                peak_pps: peak.0,
                peak_bps: peak.1,
                peak_syn_pps: peak.2,
                // Demo: surface the peak values as the "live" rates too.
                rx_pps: peak.0,
                rx_bps: peak.1,
                rx_syn_pps: peak.2,
                ..Default::default()
            });
        }
        // Anything auto that vanished -> Stop.
        let gone: Vec<String> = self
            .prev
            .keys()
            .filter(|c| !seen.contains(*c))
            .cloned()
            .collect();
        for c in gone {
            let flags = self.prev.remove(&c).unwrap_or(0);
            // Report the episode's peak rates on Stop (matches the real loop).
            let (pps, bps, syn) = self.peak.remove(&c).unwrap_or((0, 0, 0));
            state.record_event(EventKind::Stop, c.clone(), flags, pps, bps, syn);
            self.since.remove(&c);
        }
        out
    }
}

fn learned_ports(t: u64) -> Vec<LearnedPort> {
    // The open ports the daemon has passively learned per protected IP — one
    // per real service on each host. Ages advance with the tick; a couple of
    // ports flap in/out to show churn.
    let p = |ip: &str, port: u16, proto: &str, age: u64| LearnedPort {
        ip: ip.into(),
        port,
        proto: proto.into(),
        age_secs: age,
    };
    let mut v = vec![
        // Web edge.
        p("203.0.113.10", 443, "tcp", t % 300),
        p("203.0.113.10", 80, "tcp", t % 300),
        // Authoritative DNS (UDP + TCP fallback).
        p("203.0.113.20", 53, "udp", t % 240),
        p("203.0.113.20", 53, "tcp", t % 240),
        // Game server.
        p("203.0.113.53", 27015, "udp", t % 180),
        // Mail: SMTP, submission, IMAPS.
        p("203.0.113.30", 25, "tcp", t % 600),
        p("203.0.113.30", 587, "tcp", t % 600),
        p("203.0.113.30", 993, "tcp", t % 600),
        // WireGuard VPN.
        p("203.0.113.90", 51820, "udp", t % 120),
        // SSH bastion.
        p("203.0.113.7", 22, "tcp", t % 600),
        // Dual-stack web host.
        p("2001:db8:1::10", 443, "tcp", t % 300),
    ];
    // A short-lived HTTPS alt port on the web edge that flaps to show churn.
    if (t / 11) % 2 == 0 {
        v.push(p("203.0.113.10", 8443, "tcp", t % 30));
    }
    v
}

async fn run_sim(state: Arc<SharedState>) {
    // A realistic tenant mix behind the protected /24: a public web edge
    // (the DDoS target), an authoritative DNS box, a mail server, a game
    // server, a WireGuard VPN gateway and an SSH bastion, plus a dual-stack
    // web host on the protected /48.
    let hosts = [
        // Public web/CDN edge — busy, and the target of the periodic flood.
        Host {
            ip: "203.0.113.10",
            v6: false,
            base_pps: 84_000,
            base_bps: 390_000_000,
            base_syn: 210,
            target: true,
        },
        // Authoritative DNS — small UDP packets, high pps, negligible SYNs.
        Host {
            ip: "203.0.113.20",
            v6: false,
            base_pps: 26_000,
            base_bps: 42_000_000,
            base_syn: 4,
            target: false,
        },
        // Game server — chatty UDP, medium pps.
        Host {
            ip: "203.0.113.53",
            v6: false,
            base_pps: 38_000,
            base_bps: 210_000_000,
            base_syn: 20,
            target: false,
        },
        // Mail server (SMTP/submission/IMAPS) — modest, bursty SYNs.
        Host {
            ip: "203.0.113.30",
            v6: false,
            base_pps: 3_400,
            base_bps: 24_000_000,
            base_syn: 45,
            target: false,
        },
        // WireGuard VPN gateway — steady UDP tunnel.
        Host {
            ip: "203.0.113.90",
            v6: false,
            base_pps: 1_500,
            base_bps: 11_000_000,
            base_syn: 2,
            target: false,
        },
        // SSH bastion — tiny, mostly idle.
        Host {
            ip: "203.0.113.7",
            v6: false,
            base_pps: 180,
            base_bps: 900_000,
            base_syn: 6,
            target: false,
        },
        // Dual-stack web host on the protected /48.
        Host {
            ip: "2001:db8:1::10",
            v6: true,
            base_pps: 14_500,
            base_bps: 105_000_000,
            base_syn: 40,
            target: false,
        },
    ];

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ now_unix().wrapping_mul(2_654_435_761));
    let mut book = MitBook::default();
    let mut block_started: Option<u64> = None;
    let mut t: u64 = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;
        t += 1;
        let now = now_unix();

        let mut tracked = Vec::new();
        let mut actives: Vec<ActiveInput> = Vec::new();
        // Per-family aggregate for the two protected prefixes.
        let (mut a4, mut a6) = (Sample4::default(), Sample4::default());
        let (mut tot_pps, mut tot_bps, mut tot_syn, mut tot_drop) = (0u64, 0u64, 0u64, 0u64);
        let (mut tot_tx_pps, mut tot_tx_bps) = (0u64, 0u64);
        let mut source_block_active = false;

        let day = diurnal(t);
        for h in &hosts {
            let s = sample_host(h, t, day, &mut rng);
            let agg = if h.v6 { &mut a6 } else { &mut a4 };
            agg.pps += s.pps;
            agg.bps += s.bps;
            agg.syn += s.syn;
            agg.drop += s.drop_pps;
            agg.tx_pps += s.tx_pps;
            agg.tx_bps += s.tx_bps;
            tot_pps += s.pps;
            tot_bps += s.bps;
            tot_syn += s.syn;
            tot_drop += s.drop_pps;
            tot_tx_pps += s.tx_pps;
            tot_tx_bps += s.tx_bps;

            tracked.push(TrackedIp {
                ip: h.ip.into(),
                rx_pps: s.pps,
                rx_bps: s.bps,
                rx_syn_pps: s.syn,
                rx_drop_pps: s.drop_pps,
                tx_pps: s.tx_pps,
                tx_bps: s.tx_bps,
                rx_drop_pct: drop_pct(s.drop_pps, s.pps),
                mitigating: s.flags != 0,
                flags: s.flags,
                load_pct: load_pct(s.pps, s.syn, s.bps),
                geo: Default::default(),
            });
            if s.flags != 0 {
                let bits = if h.v6 { 128 } else { 32 };
                actives.push(ActiveInput {
                    cidr: format!("{}/{bits}", h.ip),
                    flags: s.flags,
                    pps: s.pps,
                    bps: s.bps,
                    syn: s.syn,
                    manual: false,
                });
                if s.flags & DEST_MODE_SOURCE_BLOCK != 0 {
                    source_block_active = true;
                }
            }
        }
        tracked.sort_by(|a, b| b.load_pct.cmp(&a.load_pct));

        // Manual override from the pushed ruleset: a small steady drop the
        // operator pinned (the real daemon appends these live too).
        {
            let pps = rng.jitter(2_000, 20);
            actives.push(ActiveInput {
                cidr: "192.0.2.9/32".into(),
                flags: DEST_MODE_PORT_FILTER | DEST_MODE_SYN_PROXY,
                pps,
                bps: pps * 800,
                syn: rng.jitter(400, 30),
                manual: true,
            });
            tracked.push(TrackedIp {
                ip: "192.0.2.9".into(),
                rx_pps: pps,
                rx_bps: pps * 800,
                rx_syn_pps: rng.jitter(400, 30),
                rx_drop_pps: pps,
                tx_pps: 0,
                tx_bps: 0,
                rx_drop_pct: 100,
                mitigating: true,
                flags: DEST_MODE_PORT_FILTER | DEST_MODE_SYN_PROXY,
                load_pct: load_pct(pps, 0, 0),
                geo: Default::default(),
            });
        }

        let prefixes = vec![
            PrefixLoad {
                cidr: "203.0.113.0/24".into(),
                rx_pps: a4.pps,
                rx_bps: a4.bps,
                rx_syn_pps: a4.syn,
                rx_drop_pps: a4.drop,
                tx_pps: a4.tx_pps,
                tx_bps: a4.tx_bps,
                rx_drop_pct: drop_pct(a4.drop, a4.pps),
                mitigating: false,
                flags: 0,
                load_pct: net_load_pct(a4.pps, a4.syn, a4.bps),
                geo: Default::default(),
            },
            PrefixLoad {
                cidr: "2001:db8:1::/48".into(),
                rx_pps: a6.pps,
                rx_bps: a6.bps,
                rx_syn_pps: a6.syn,
                rx_drop_pps: a6.drop,
                tx_pps: a6.tx_pps,
                tx_bps: a6.tx_bps,
                rx_drop_pct: drop_pct(a6.drop, a6.pps),
                mitigating: false,
                flags: 0,
                load_pct: net_load_pct(a6.pps, a6.syn, a6.bps),
                geo: Default::default(),
            },
        ];

        // Auto source-block: present while the target is escalated, then decays.
        if source_block_active {
            block_started = Some(now);
        }
        let blocks = match block_started {
            Some(started) if now.saturating_sub(started) < 60 => vec![
                SourceBlock {
                    cidr: "185.220.101.0/24".into(),
                    age_secs: now.saturating_sub(started),
                    pps: rng.jitter(48_000, 20),
                    manual: false,
                    cooling: false,
                    geo: Default::default(),
                },
                SourceBlock {
                    cidr: "193.32.162.7/32".into(),
                    age_secs: now.saturating_sub(started),
                    pps: rng.jitter(9_000, 25),
                    manual: false,
                    cooling: true,
                    geo: Default::default(),
                },
            ],
            _ => {
                block_started = None;
                Vec::new()
            }
        };

        state.set_tracked(tracked);
        state.set_prefixes(prefixes);
        state.set_totals(Totals {
            rx_pps: tot_pps,
            rx_bps: tot_bps,
            rx_syn_pps: tot_syn,
            rx_drop_pps: tot_drop,
            rx_drop_pct: drop_pct(tot_drop, tot_pps),
            tx_pps: tot_tx_pps,
            tx_bps: tot_tx_bps,
        });
        state.set_active(book.step(&state, actives, now));
        // Unified source list the dashboard now reads: the auto blocks as
        // dropping/cooling rows, plus a couple of NORMAL tracked sources so the
        // preview shows every state at once.
        let mut sources: Vec<TrackedSource> = blocks
            .iter()
            .map(|b| TrackedSource {
                ip: b.cidr.trim_end_matches("/32").to_string(),
                pps: b.pps,
                state: if b.cooling { "cooling" } else { "dropping" }.to_string(),
                manual: false,
                age_secs: b.age_secs,
                geo: Default::default(),
            })
            .collect();
        if block_started.is_some() {
            sources.push(TrackedSource {
                ip: "91.198.174.192".into(),
                pps: rng.jitter(120, 30),
                state: "normal".into(),
                manual: false,
                age_secs: 0,
                geo: Default::default(),
            });
        }
        state.set_blocks(blocks);
        state.set_sources(sources);
        if t % 5 == 1 {
            state.set_ports(learned_ports(t));
        }
    }
}

/// Per-family running aggregate for a protected prefix.
#[derive(Default)]
struct Sample4 {
    pps: u64,
    bps: u64,
    syn: u64,
    drop: u64,
    tx_pps: u64,
    tx_bps: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Bind address and API token are overridable via env so the same demo can
    // run locally (default 127.0.0.1) or inside a container (BIND_ADDR=0.0.0.0:8899).
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:8899".parse().unwrap());
    let token = std::env::var("API_TOKEN").unwrap_or_else(|_| "devtoken".into());
    let state = SharedState::new(
        token.clone(),
        vec![],
        vec!["demo0".into()],
        RuleSet {
            protected: vec!["203.0.113.0/24".into(), "2001:db8:1::/48".into()],
            overrides: vec![Override {
                cidr: "192.0.2.9/32".into(),
                flags: DEST_MODE_PORT_FILTER | DEST_MODE_SYN_PROXY,
            }],
            source_blocks: vec!["45.134.26.0/24".into()],
        },
        1024,
        "LNVPS/api".into(),
        false,
        None,
    );
    state.set_limits(LIM);
    // Demo NIC so the dashboard shows the link-speed + bps-vs-line-rate hint
    // (the 40 Gbit/s prefix bps limit exceeds this 10G link on purpose).
    state.set_nics(vec![InterfaceInfo {
        name: "demo0".into(),
        speed_mbps: Some(10_000),
        role: "host".into(),
    }]);
    state.set_ports(learned_ports(0));

    let sim_state = state.clone();
    tokio::spawn(async move { run_sim(sim_state).await });

    let tls = api::load_or_generate_tls(None, None, addr.ip(), None)?;
    println!("serving https://{addr}  (token: {token})  — simulated live traffic");
    api::serve(state, addr, tls).await
}
