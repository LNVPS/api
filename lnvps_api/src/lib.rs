pub mod api;
pub mod data_migration;
pub mod dns;
pub mod fiat;
pub mod host;
pub mod json_api;
pub mod lightning;
pub mod payments;
pub mod provisioner;
pub mod router;
pub mod settings;
#[cfg(feature = "proxmox")]
pub mod ssh_client;
pub mod status;
pub mod vm_history;
pub mod worker;

#[cfg(test)]
pub mod mocks;

#[cfg(feature = "nostr-dvm")]
pub mod dvm;

// Re-export common types  
pub use lnvps_api_common::{GB, MB, KB, TB, BTC_SATS, Nip98Auth, ExchangeRateService, alt_prices, CurrencyAmount, Currency};

pub mod exchange {
    pub use lnvps_api_common::{alt_prices, ExchangeRateService};
}

pub mod nip98 {
    pub use lnvps_api_common::Nip98Auth;
}
