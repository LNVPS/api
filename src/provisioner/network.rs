use crate::settings::NetworkPolicy;
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
    pub range_id: u64,
    pub region_id: u64,
}

#[derive(Clone)]
pub struct NetworkProvisioner {
    method: ProvisionerMethod,
    settings: NetworkPolicy,
    db: Arc<dyn LNVpsDb>,
}

impl NetworkProvisioner {
    pub fn new(method: ProvisionerMethod, settings: NetworkPolicy, db: Arc<dyn LNVpsDb>) -> Self {
        Self {
            method,
            settings,
            db,
        }
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
            let ips: HashSet<IpAddr> = ips.iter().map_while(|i| i.ip.parse().ok()).collect();

            // pick an IP at random
            let ip_pick = {
                let first_ip = range_cidr.iter().next().unwrap();
                let last_ip = range_cidr.iter().last().unwrap();
                match self.method {
                    ProvisionerMethod::Sequential => range_cidr
                        .iter()
                        .find(|i| *i != first_ip && *i != last_ip && !ips.contains(i)),
                    ProvisionerMethod::Random => {
                        let mut rng = rand::rng();
                        loop {
                            if let Some(i) = range_cidr.iter().choose(&mut rng) {
                                if i != first_ip && i != last_ip && !ips.contains(&i) {
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
    use crate::settings::NetworkAccessPolicy;
    use lnvps_db::VmIpAssignment;
    use std::str::FromStr;

    #[tokio::test]
    async fn pick_seq_ip_for_region_test() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(
            ProvisionerMethod::Sequential,
            NetworkPolicy {
                access: NetworkAccessPolicy::Auto,
            },
            db.clone(),
        );

        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(1, ip.region_id);
        assert_eq!(IpAddr::from_str("10.0.0.1").unwrap(), ip.ip);
        db.insert_vm_ip_assignment(&VmIpAssignment {
            id: 0,
            vm_id: 0,
            ip_range_id: ip.range_id,
            ip: ip.ip.to_string(),
            deleted: false,
        })
        .await
        .expect("Could not insert vm ip");
        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(IpAddr::from_str("10.0.0.2").unwrap(), ip.ip);
    }

    #[tokio::test]
    async fn pick_rng_ip_for_region_test() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(
            ProvisionerMethod::Random,
            NetworkPolicy {
                access: NetworkAccessPolicy::Auto,
            },
            db,
        );

        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        assert_eq!(1, ip.region_id);
    }
}
