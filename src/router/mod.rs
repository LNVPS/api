use anyhow::Result;
use lnvps_db::{Vm, VmIpAssignment};
use rocket::async_trait;

/// Router defines a network device used to access the hosts
///
/// In our infrastructure we use this to add static ARP entries on the router
/// for every IP assignment, this way we don't need to have a ton of ARP requests on the
/// VM network because of people doing IP scanning
///
/// It also prevents people from re-assigning their IP to another in the range,
#[async_trait]
pub trait Router: Send + Sync {
    /// Generate mac address for a given IP address
    async fn generate_mac(&self, ip: &str, comment: &str) -> Result<Option<ArpEntry>>;
    async fn list_arp_entry(&self) -> Result<Vec<ArpEntry>>;
    async fn add_arp_entry(&self, entry: &ArpEntry) -> Result<ArpEntry>;
    async fn remove_arp_entry(&self, id: &str) -> Result<()>;
    async fn update_arp_entry(&self, entry: &ArpEntry) -> Result<ArpEntry>;
}

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub id: Option<String>,
    pub address: String,
    pub mac_address: String,
    pub interface: Option<String>,
    pub comment: Option<String>,
}

impl ArpEntry {
    pub fn new(vm: &Vm, ip: &VmIpAssignment, interface: Option<String>) -> Result<Self> {
        Ok(Self {
            id: ip.arp_ref.clone(),
            address: ip.ip.clone(),
            mac_address: vm.mac_address.clone(),
            interface,
            comment: Some(format!("VM{}", vm.id)),
        })
    }
}

#[cfg(feature = "mikrotik")]
mod mikrotik;
mod ovh;

#[cfg(feature = "mikrotik")]
pub use mikrotik::MikrotikRouter;
pub use ovh::OvhDedicatedServerVMacRouter;

