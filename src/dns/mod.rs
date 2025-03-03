use anyhow::Result;
use lnvps_db::async_trait;
use std::net::IpAddr;

#[cfg(feature = "cloudflare")]
mod cloudflare;
#[cfg(feature = "cloudflare")]
pub use cloudflare::*;

#[async_trait]
pub trait DnsServer: Send + Sync {
    /// Add PTR record to the reverse zone
    async fn add_ptr_record(&self, key: &str, value: &str) -> Result<BasicRecord>;

    /// Delete PTR record from the reverse zone
    async fn delete_ptr_record(&self, key: &str) -> Result<()>;

    /// Add A/AAAA record onto the forward zone
    async fn add_a_record(&self, name: &str, ip: IpAddr) -> Result<BasicRecord>;

    /// Delete A/AAAA record from the forward zone
    async fn delete_a_record(&self, name: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct BasicRecord {
    pub name: String,
    pub value: String,
    pub id: String,
}