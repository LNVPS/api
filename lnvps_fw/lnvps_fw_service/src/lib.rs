//! Library surface of `lnvps_fw_service`, shared between the daemon binary
//! (`main.rs`) and the integration test harness. Keeps the userspace logic
//! (config parsing, learned-port GC) unit-testable and reusable.

pub mod config;
pub mod gc;
