use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use lnvps_api_common::retry::OpResult;
use lnvps_db::{LNVpsDb, RouterKind, Vm, VmIpAssignment};
use std::sync::Arc;

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
    async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>>;
    async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry>;
    async fn remove_arp_entry(&self, id: &str) -> OpResult<()>;
    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry>;
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
        ensure!(
            vm.mac_address != "ff:ff:ff:ff:ff:ff",
            "MAC address is invalid because its blank"
        );
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

pub async fn get_router(db: &Arc<dyn LNVpsDb>, router_id: u64) -> OpResult<Arc<dyn Router>> {
    let cfg = db.get_router(router_id).await?;
    match cfg.kind {
        RouterKind::Mikrotik => {
            let mut t_split = cfg.token.as_str().split(":");
            let (username, password) = (
                t_split.next().context("Invalid username:password")?,
                t_split.next().context("Invalid username:password")?,
            );
            Ok(Arc::new(MikrotikRouter::new(&cfg.url, username, password)))
        }
        RouterKind::OvhAdditionalIp => Ok(Arc::new(
            OvhDedicatedServerVMacRouter::new(&cfg.url, &cfg.name, cfg.token.as_str()).await?,
        )),
        RouterKind::MockRouter => {
            #[cfg(test)]
            return Ok(Arc::new(crate::mocks::MockRouter::new()));
            #[cfg(not(test))]
            {
                panic!("Cant use mock router outside tests!")
            }
        }
    }
}
