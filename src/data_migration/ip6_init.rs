use crate::data_migration::DataMigration;
use crate::provisioner::{LNVpsProvisioner, NetworkProvisioner};
use ipnetwork::IpNetwork;
use lnvps_db::LNVpsDb;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use log::info;

pub struct Ip6InitDataMigration {
    db: Arc<dyn LNVpsDb>,
    provisioner: Arc<LNVpsProvisioner>,
}

impl Ip6InitDataMigration {
    pub fn new(db: Arc<dyn LNVpsDb>, provisioner: Arc<LNVpsProvisioner>) -> Ip6InitDataMigration {
        Self { db, provisioner }
    }
}

impl DataMigration for Ip6InitDataMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
        let db = self.db.clone();
        let provisioner = self.provisioner.clone();
        Box::pin(async move {
            let net = NetworkProvisioner::new(db.clone());
            let vms = db.list_vms().await?;
            for vm in vms {
                let host = db.get_host(vm.host_id).await?;
                let ips = db.list_vm_ip_assignments(vm.id).await?;
                // if no ipv6 address is picked already pick one
                if ips.iter().all(|i| {
                        IpNetwork::from_str(&i.ip)
                            .map(|i| i.is_ipv4())
                            .unwrap_or(false)
                    })
                {
                    let ips_pick = net.pick_ip_for_region(host.region_id).await?;
                    if let Some(mut v6) = ips_pick.ip6 {
                        info!("Assigning ip {} to vm {}", v6.ip, vm.id);
                        provisioner.assign_available_v6_to_vm(&vm, &mut v6).await?;
                    }
                }
            }
            Ok(())
        })
    }
}
