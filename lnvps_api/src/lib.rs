pub mod api;
pub mod data_migration;
pub mod dns;
pub mod host;
pub mod json_api;
pub mod payment_factory;
pub mod payments;
pub mod provisioner;
pub mod router;
pub mod settings;
#[cfg(feature = "proxmox")]
pub mod ssh_client;
pub mod worker;

#[cfg(test)]
pub mod mocks;

#[cfg(feature = "nostr-dvm")]
pub mod dvm;

// Re-export common types
pub use lnvps_api_common::{BTC_SATS, ExchangeRateService, GB, KB, MB, Nip98Auth, TB, alt_prices};

pub mod exchange {
    pub use lnvps_api_common::{ExchangeRateService, alt_prices};
}

pub mod nip98 {
    pub use lnvps_api_common::Nip98Auth;
}
