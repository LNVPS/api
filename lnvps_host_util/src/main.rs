//! `lnvps-host-info` — print this host's detected CPU/GPU capabilities as JSON.
//!
//! All detection lives in the library so the node daemon reports identical
//! facts; this binary only renders them.

fn main() {
    let info = lnvps_host_util::host_info();
    println!("{}", serde_json::to_string_pretty(&info).unwrap());
}
