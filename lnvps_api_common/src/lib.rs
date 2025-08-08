mod capacity;
mod exchange;
mod mock;
mod model;
mod network;
mod nip98;
mod pricing;
mod routes;
mod status;
mod work;

pub use capacity::*;
pub use exchange::*;
pub use mock::*;
pub use model::*;
pub use network::*;
pub use nip98::*;
pub use pricing::*;
pub use routes::*;
pub use status::*;
pub use work::*;

/// SATS per BTC
pub const BTC_SATS: f64 = 100_000_000.0;
pub const KB: u64 = 1024;
pub const MB: u64 = KB * 1024;
pub const GB: u64 = MB * 1024;
pub const TB: u64 = GB * 1024;
