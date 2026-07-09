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
    self, EventKind, LearnedPort, Limits, Mitigation, Override, PrefixLoad, RuleSet, SharedState,
    SourceBlock, Totals, TrackedIp,
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
    let r = |v: u64, t: u64| if t == 0 { 0 } else { (v.saturating_mul(100) / t) as u32 };
    r(pps, LIM.pps).max(r(syn, LIM.syn_pps)).max(r(bps, LIM.bps))
}

fn net_load_pct(pps: u64, syn: u64, bps: u64) -> u32 {
    let r = |v: u64, t: u64| if t == 0 { 0 } else { (v.saturating_mul(100) / t) as u32 };
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

/// Attack intensity in [0.0, 1.0] on tick `t`, as a triangle over a 45s cycle
/// (rise 5..15, hold-ish peak, fall 15..25, quiet otherwise).
fn attack_intensity(t: u64) -> f64 {
    let w = t % 45;
    if (5..25).contains(&w) {
        let x = w - 5; // 0..20
        if x < 10 { x as f64 / 10.0 } else { (20 - x) as f64 / 10.0 }
    } else {
        0.0
    }
}

fn sample_host(h: &Host, t: u64, rng: &mut Rng) -> Sample {
    let mut pps = rng.jitter(h.base_pps, 15);
    let mut bps = rng.jitter(h.base_bps, 15);
    let mut syn = rng.jitter(h.base_syn, 25);
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
                drop_pps = pps.saturating_sub(h.base_pps);
            }
        }
    }
    // TX (egress) is the host serving legit replies: roughly proportional to
    // its baseline RX (not the attack flood, which generates no real replies),
    // with larger response packets.
    let tx_pps = rng.jitter(h.base_pps * 7 / 10 + 1, 20);
    let tx_bps = rng.jitter(h.base_bps * 3 + 1, 20);
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
            state.record_event(EventKind::Stop, c.clone(), flags, 0, 0, 0);
            self.since.remove(&c);
            self.peak.remove(&c);
        }
        out
    }
}

fn learned_ports(t: u64) -> Vec<LearnedPort> {
    // Ages advance with the tick; one port flaps in/out to show churn.
    let mut v = vec![
        LearnedPort {
            ip: "203.0.113.42".into(),
            port: 443,
            proto: "tcp".into(),
            age_secs: t % 300,
        },
        LearnedPort {
            ip: "203.0.113.42".into(),
            port: 80,
            proto: "tcp".into(),
            age_secs: t % 300,
        },
        LearnedPort {
            ip: "203.0.113.90".into(),
            port: 51820,
            proto: "udp".into(),
            age_secs: t % 120,
        },
        LearnedPort {
            ip: "203.0.113.7".into(),
            port: 22,
            proto: "tcp".into(),
            age_secs: t % 600,
        },
    ];
    if (t / 7) % 2 == 0 {
        v.push(LearnedPort {
            ip: "203.0.113.42".into(),
            port: 8443,
            proto: "tcp".into(),
            age_secs: t % 30,
        });
    }
    v
}

async fn run_sim(state: Arc<SharedState>) {
    let hosts = [
        Host { ip: "203.0.113.7", v6: false, base_pps: 1_200, base_bps: 9_800_000, base_syn: 5, target: true },
        Host { ip: "203.0.113.42", v6: false, base_pps: 82_500, base_bps: 380_000_000, base_syn: 180, target: false },
        Host { ip: "203.0.113.90", v6: false, base_pps: 1_200, base_bps: 9_800_000, base_syn: 5, target: false },
        Host { ip: "2001:db8:1::7", v6: true, base_pps: 12_000, base_bps: 90_000_000, base_syn: 30, target: false },
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

        for h in &hosts {
            let s = sample_host(h, t, &mut rng);
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
                },
                SourceBlock {
                    cidr: "193.32.162.7/32".into(),
                    age_secs: now.saturating_sub(started),
                    pps: rng.jitter(9_000, 25),
                    manual: false,
                    cooling: true,
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
        state.set_blocks(blocks);
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
    let addr: SocketAddr = "127.0.0.1:8899".parse().unwrap();
    let state = SharedState::new(
        "devtoken".into(),
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
    state.set_ports(learned_ports(0));

    let sim_state = state.clone();
    tokio::spawn(async move { run_sim(sim_state).await });

    let tls = api::load_or_generate_tls(None, None, addr.ip())?;
    println!("serving https://{addr}  (token: devtoken)  — simulated live traffic");
    api::serve(state, addr, tls).await
}
