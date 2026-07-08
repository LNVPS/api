//! Standalone demo of the control API + dashboard, without the eBPF datapath
//! (so it needs no root). Seeds some fake state and serves HTTPS with a
//! self-signed cert.
//!
//!   cargo run -p lnvps_fw_service --example serve_api
//!   curl -k -H 'Authorization: Bearer devtoken' https://127.0.0.1:8899/api/v1/status
//!   open https://127.0.0.1:8899/   (dashboard; paste token `devtoken`)

use std::net::SocketAddr;

use lnvps_fw_service::api::{self, EventKind, Mitigation, Override, RuleSet, SharedState};

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
        },
        128,
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

    let tls = api::load_or_generate_tls(None, None, addr.ip())?;
    println!("serving https://{addr}  (token: devtoken)");
    api::serve(state, addr, tls).await
}
