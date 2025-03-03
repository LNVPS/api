use anyhow::{bail, Result};
use ipnetwork::IpNetwork;
use lnvps_db::LNVpsDb;
use rand::prelude::IteratorRandom;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub enum ProvisionerMethod {
    Sequential,
    Random,
}

#[derive(Debug, Clone, Copy)]
pub struct AvailableIp {
    pub ip: IpAddr,
    pub gateway: IpNetwork,
    pub range_id: u64,
    pub region_id: u64,
}

/// Handles picking available IPs
#[derive(Clone)]
pub struct NetworkProvisioner {
    method: ProvisionerMethod,
    db: Arc<dyn LNVpsDb>,
}

impl NetworkProvisioner {
    pub fn new(method: ProvisionerMethod, db: Arc<dyn LNVpsDb>) -> Self {
        Self { method, db }
    }

    /// Pick an IP from one of the available ip ranges
    /// This method MUST return a free IP which can be used
    pub async fn pick_ip_for_region(&self, region_id: u64) -> Result<AvailableIp> {
        let ip_ranges = self.db.list_ip_range_in_region(region_id).await?;
        if ip_ranges.is_empty() {
            bail!("No ip range found in this region");
        }

        for range in ip_ranges {
            let range_cidr: IpNetwork = range.cidr.parse()?;
            let ips = self.db.list_vm_ip_assignments_in_range(range.id).await?;
            let mut ips: HashSet<IpAddr> = ips.iter().map_while(|i| i.ip.parse().ok()).collect();

            let gateway: IpNetwork = range.gateway.parse()?;

            // mark some IPS as always used
            // Namely:
            //  .0 & .255 of /24 (first and last)
            //  gateway ip of the range
            ips.insert(range_cidr.iter().next().unwrap());
            ips.insert(range_cidr.iter().last().unwrap());
            ips.insert(gateway.ip());

            // pick an IP at random
            let ip_pick = {
                match self.method {
                    ProvisionerMethod::Sequential => range_cidr.iter().find(|i| !ips.contains(i)),
                    ProvisionerMethod::Random => {
                        let mut rng = rand::rng();
                        loop {
                            if let Some(i) = range_cidr.iter().choose(&mut rng) {
                                if !ips.contains(&i) {
                                    break Some(i);
                                }
                            } else {
                                break None;
                            }
                        }
                    }
                }
            };

            if let Some(ip_pick) = ip_pick {
                return Ok(AvailableIp {
                    range_id: range.id,
                    gateway,
                    ip: ip_pick,
                    region_id,
                });
            }
        }
        bail!("No IPs available in this region");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::*;

    use lnvps_db::VmIpAssignment;
    use std::str::FromStr;

    #[tokio::test]
    async fn pick_seq_ip_for_region_test() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(ProvisionerMethod::Sequential, db.clone());

        let gateway = IpNetwork::from_str("10.0.0.1/8").unwrap();
        let first = IpAddr::from_str("10.0.0.2").unwrap();
        let second = IpAddr::from_str("10.0.0.3").unwrap();
        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(1, ip.region_id);
        assert_eq!(first, ip.ip);
        assert_eq!(gateway, ip.gateway);

        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(1, ip.region_id);
        assert_eq!(first, ip.ip);
        db.insert_vm_ip_assignment(&VmIpAssignment {
            id: 0,
            vm_id: 0,
            ip_range_id: ip.range_id,
            ip: ip.ip.to_string(),
            ..Default::default()
        })
        .await
        .expect("Could not insert vm ip");
        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(second, ip.ip);
    }

    #[tokio::test]
    async fn pick_rng_ip_for_region_test() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(ProvisionerMethod::Random, db);

        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(1, ip.region_id);
    }
}
