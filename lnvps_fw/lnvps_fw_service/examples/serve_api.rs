//! Standalone demo of the control API + dashboard, without the eBPF datapath
//! (so it needs no root). Seeds some fake state and serves HTTPS with a
//! self-signed cert.
//!
//!   cargo run -p lnvps_fw_service --example serve_api
//!   curl -k -H 'Authorization: Bearer devtoken' https://127.0.0.1:8899/api/v1/status
//!   open https://127.0.0.1:8899/   (dashboard; paste token `devtoken`)

use std::net::SocketAddr;

use lnvps_fw_service::api::{
    self, EventKind, LearnedPort, Limits, Mitigation, Override, PrefixLoad, RuleSet, SharedState,
    SourceBlock, TrackedIp,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = "127.0.0.1:8899".parse().unwrap();
    let state = SharedState::new(
        "devtoken".into(),
        vec![],
        vec!["demo0".into()],
        RuleSet {
            protected: vec!["203.0.113.0/24".into()],
            overrides: vec![Override {
                cidr: "192.0.2.9/32".into(),
                flags: 3,
            }],
            source_blocks: vec!["45.134.26.0/24".into()],
        },
        128,
        "LNVPS/api".into(),
    );
    state.set_active(vec![Mitigation {
        cidr: "203.0.113.7/32".into(),
        flags: 0b0011,
        since_unix: 1_720_000_000,
        manual: false,
        peak_pps: 250_000,
        peak_bps: 3_000_000_000,
        peak_syn_pps: 40_000,
    }]);
    state.record_event(
        EventKind::Start,
        "203.0.113.7/32".into(),
        1,
        120_000,
        900_000,
        8_000,
    );
    state.record_event(
        EventKind::Flags,
        "203.0.113.7/32".into(),
        3,
        250_000,
        3_000_000_000,
        40_000,
    );
    state.set_limits(Limits {
        pps: 100_000,
        syn_pps: 10_000,
        bps: 1_000_000_000,
        net_pps: 500_000,
        net_syn_pps: 50_000,
        net_bps: 5_000_000_000,
        exit_pct: 50,
        cooldown_secs: 30,
    });
    state.set_tracked(vec![
        TrackedIp {
            ip: "203.0.113.7".into(),
            pps: 250_000,
            bps: 3_000_000_000,
            syn_pps: 40_000,
            drop_pps: 210_000,
            mitigating: true,
            flags: 0b0011,
            load_pct: 250,
        },
        TrackedIp {
            ip: "203.0.113.42".into(),
            pps: 82_500,
            bps: 380_000_000,
            syn_pps: 180,
            drop_pps: 0,
            mitigating: false,
            flags: 0,
            load_pct: 82,
        },
        TrackedIp {
            ip: "203.0.113.90".into(),
            pps: 1_200,
            bps: 9_800_000,
            syn_pps: 5,
            drop_pps: 0,
            mitigating: false,
            flags: 0,
            load_pct: 1,
        },
    ]);
    state.set_prefixes(vec![
        PrefixLoad {
            cidr: "203.0.113.0/24".into(),
            pps: 335_000,
            bps: 3_400_000_000,
            syn_pps: 41_000,
            mitigating: false,
            flags: 0,
            load_pct: 82,
        },
        PrefixLoad {
            cidr: "2001:db8:1::/48".into(),
            pps: 12_000,
            bps: 90_000_000,
            syn_pps: 30,
            mitigating: false,
            flags: 0,
            load_pct: 2,
        },
    ]);
    state.set_blocks(vec![
        SourceBlock {
            cidr: "91.219.236.0/24".into(),
            age_secs: 21,
            pps: 0,
            manual: false,
        },
        SourceBlock {
            cidr: "193.32.162.7/32".into(),
            age_secs: 3,
            pps: 0,
            manual: false,
        },
    ]);
    state.set_ports(vec![
        LearnedPort {
            ip: "203.0.113.42".into(),
            port: 443,
            proto: "tcp".into(),
            age_secs: 3,
        },
        LearnedPort {
            ip: "203.0.113.42".into(),
            port: 80,
            proto: "tcp".into(),
            age_secs: 3,
        },
        LearnedPort {
            ip: "203.0.113.90".into(),
            port: 51820,
            proto: "udp".into(),
            age_secs: 47,
        },
        LearnedPort {
            ip: "203.0.113.7".into(),
            port: 22,
            proto: "tcp".into(),
            age_secs: 120,
        },
    ]);

    let tls = api::load_or_generate_tls(None, None, addr.ip())?;
    println!("serving https://{addr}  (token: devtoken)");
    api::serve(state, addr, tls).await
}
