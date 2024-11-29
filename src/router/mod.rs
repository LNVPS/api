use anyhow::Result;
use rocket::async_trait;
use std::net::IpAddr;

/// Router defines a network device used to access the hosts
///
/// In our infrastructure we use this to add static ARP entries on the router
/// for every IP assignment, this way we don't need to have a ton of ARP requests on the
/// VM network because of people doing IP scanning
///
/// It also prevents people from re-assigning their IP to another in the range,
#[async_trait]
pub trait Router {
    async fn add_arp_entry(&self, ip: IpAddr, mac: &[u8; 6], comment: Option<&str>) -> Result<()>;
}

mod mikrotik;
pub use mikrotik::*;
