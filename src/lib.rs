pub mod api;
pub mod cors;
pub mod data_migration;
pub mod dns;
pub mod exchange;
pub mod fiat;
pub mod host;
pub mod json_api;
pub mod lightning;
pub mod nip98;
pub mod payments;
pub mod provisioner;
pub mod router;
pub mod settings;
#[cfg(feature = "proxmox")]
pub mod ssh_client;
pub mod status;
pub mod worker;

#[cfg(test)]
pub mod mocks;


/// SATS per BTC
pub const BTC_SATS: f64 = 100_000_000.0;
pub const KB: u64 = 1024;
pub const MB: u64 = KB * 1024;
pub const GB: u64 = MB * 1024;
pub const TB: u64 = GB * 1024;