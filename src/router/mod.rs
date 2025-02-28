use anyhow::Result;
use rocket::async_trait;
use rocket::serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Router defines a network device used to access the hosts
///
/// In our infrastructure we use this to add static ARP entries on the router
/// for every IP assignment, this way we don't need to have a ton of ARP requests on the
/// VM network because of people doing IP scanning
///
/// It also prevents people from re-assigning their IP to another in the range,
#[async_trait]
pub trait Router: Send + Sync {
    async fn list_arp_entry(&self) -> Result<Vec<ArpEntry>>;
    async fn add_arp_entry(
        &self,
        ip: IpAddr,
        mac: &str,
        interface: &str,
        comment: Option<&str>,
    ) -> Result<()>;
    async fn remove_arp_entry(&self, id: &str) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArpEntry {
    #[serde(rename = ".id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "mac-address")]
    pub mac_address: Option<String>,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[cfg(feature = "mikrotik")]
mod mikrotik;
#[cfg(feature = "mikrotik")]
pub use mikrotik::*;