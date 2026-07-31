pub mod api;
pub mod data_migration;
pub mod fee_estimate;
pub mod notifications;
pub mod payment_factory;
pub mod payments;
pub mod provisioner;
pub mod referral;
pub mod refund;
pub mod router;
pub mod settings;
pub mod subscription;
pub mod worker;

#[cfg(test)]
pub mod mocks;

#[cfg(feature = "nostr-dvm")]
pub mod dvm;

// Re-export common types
pub use lnvps_api_common::{BTC_SATS, ExchangeRateService, GB, KB, MB, Nip98Auth, TB, alt_prices};

/// Hypervisor host clients. Moved to `lnvps_api_common` so that other crates
/// (notably `lnvps_agent`) can drive VM power actions; re-exported here so
/// existing `crate::host::*` paths keep working.
pub mod host {
    pub use lnvps_api_common::host::*;
}

#[cfg(any(feature = "proxmox", feature = "linux-ssh"))]
pub mod ssh_client {
    pub use lnvps_api_common::ssh_client::*;
}

pub mod exchange {
    pub use lnvps_api_common::{ExchangeRateService, alt_prices};
}

pub mod nip98 {
    pub use lnvps_api_common::Nip98Auth;
}
