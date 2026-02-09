mod capacity;
mod exchange;
mod kv;
mod mock;
mod model;
mod network;
mod nip98;
mod pricing;
pub mod retry;
mod routes;
mod status;
mod vm_history;
mod work;

pub use capacity::*;
pub use exchange::*;
pub use kv::*;
pub use mock::*;
pub use model::*;
pub use network::*;
pub use nip98::*;
pub use pricing::*;
pub use routes::*;
use serde::Deserialize;
pub use status::*;
pub use vm_history::*;
pub use work::*;

/// SATS per BTC
pub const BTC_SATS: f64 = 100_000_000.0;
pub const KB: u64 = 1024;
pub const MB: u64 = KB * 1024;
pub const GB: u64 = MB * 1024;
pub const TB: u64 = GB * 1024;

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct PageQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    pub limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    pub offset: Option<u64>,
}

/// Deserialize an optional value from either a string or the actual type
/// Works with any type that implements FromStr + Deserialize
pub fn deserialize_from_str_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrValue<T> {
        String(String),
        Value(T),
    }

    match Option::<StringOrValue<T>>::deserialize(deserializer)? {
        Some(StringOrValue::String(s)) => {
            s.parse::<T>().map(Some).map_err(serde::de::Error::custom)
        }
        Some(StringOrValue::Value(v)) => Ok(Some(v)),
        None => Ok(None),
    }
}

/// Deserialize a required value from either a string or the actual type
/// Works with any type that implements FromStr + Deserialize
pub fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrValue<T> {
        String(String),
        Value(T),
    }

    match StringOrValue::<T>::deserialize(deserializer)? {
        StringOrValue::String(s) => s.parse::<T>().map_err(serde::de::Error::custom),
        StringOrValue::Value(v) => Ok(v),
    }
}
