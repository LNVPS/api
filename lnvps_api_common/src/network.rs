use anyhow::{Context, Result, bail};
use ipnetwork::IpNetwork;
use lnvps_db::{IpRange, IpRangeAllocationMode, LNVpsDb};
use log::warn;
use rand::Rng;
use rand::prelude::SliceRandom;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AvailableIps {
    pub ip4: Option<AvailableIp>,
    pub ip6: Option<AvailableIp>,
}

#[derive(Debug, Clone)]
pub struct AvailableIp {
    pub ip: IpNetwork,
    pub gateway: IpNetwork,
    pub range_id: u64,
    pub region_id: u64,
    pub mode: IpRangeAllocationMode,
}

/// Handles picking available IPs
#[derive(Clone)]
pub struct NetworkProvisioner {
    db: Arc<dyn LNVpsDb>,
}

#[derive(Clone)]
pub enum IpAddrKind {
    IPv4,
    IPv6,
}

impl NetworkProvisioner {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// Pick an IP from one of the available ip ranges
    /// This method MUST return a free IP which can be used
    pub async fn pick_ip_for_region(&self, region_id: u64) -> Result<AvailableIps> {
        self.pick_ip_kind_for_region(region_id, None).await
    }

    pub async fn pick_ip_kind_for_region(
        &self,
        region_id: u64,
        kind: Option<IpAddrKind>,
    ) -> Result<AvailableIps> {
        let mut ip_ranges = self.db.list_ip_range_in_region(region_id).await?;
        if ip_ranges.is_empty() {
            bail!("No ip range found in this region");
        }

        // filter by kind
        ip_ranges.retain(|r| {
                let net = r.cidr.parse();
                match (net, &kind) {
                    (Ok(IpNetwork::V4(_)), Some(IpAddrKind::IPv4)) => true,
                    (Ok(IpNetwork::V6(_)), Some(IpAddrKind::IPv6)) => true,
                    (Err(_), _) => false,
                    _ => true,
                }
            });

        // Randomize the order of IP ranges for even distribution
        ip_ranges.shuffle(&mut rand::rng());

        let mut ret = AvailableIps {
            ip4: None,
            ip6: None,
        };
        for range in ip_ranges {
            let range_cidr: IpNetwork = range.cidr.parse()?;
            if ret.ip4.is_none() && range_cidr.is_ipv4() {
                ret.ip4 = match self.pick_ip_from_range(&range).await {
                    Ok(i) => Some(i),
                    Err(e) => {
                        warn!("Failed to pick ip range: {} {}", range.cidr, e);
                        None
                    }
                }
            }
            if ret.ip6.is_none() && range_cidr.is_ipv6() {
                ret.ip6 = match self.pick_ip_from_range(&range).await {
                    Ok(i) => Some(i),
                    Err(e) => {
                        warn!("Failed to pick ip range: {} {}", range.cidr, e);
                        None
                    }
                }
            }
        }
        if ret.ip4.is_none() && ret.ip6.is_none() {
            bail!("No IPs available in this region");
        } else {
            Ok(ret)
        }
    }

    pub async fn pick_ip_from_range_id(&self, range_id: u64) -> Result<AvailableIp> {
        let range = self.db.get_ip_range(range_id).await?;
        self.pick_ip_from_range(&range).await
    }

    pub async fn pick_ip_from_range(&self, range: &IpRange) -> Result<AvailableIp> {
        let range_cidr: IpNetwork = range.cidr.parse()?;
        let ips = self.db.list_vm_ip_assignments_in_range(range.id).await?;
        let mut ips: HashSet<IpAddr> = ips.iter().map_while(|i| i.ip.parse().ok()).collect();

        let gateway: IpNetwork = range.gateway.parse()?;

        // mark some IPS as always used
        // Namely:
        //  .0 & .255 of /24 (first and last)
        //  gateway ip of the range
        if !range.use_full_range && range_cidr.is_ipv4() {
            ips.insert(range_cidr.iter().next().unwrap());
            ips.insert(range_cidr.iter().last().unwrap());
        }
        ips.insert(gateway.ip());

        // pick an IP from the range
        let ip_pick = {
            match &range.allocation_mode {
                IpRangeAllocationMode::Sequential => range_cidr
                    .iter()
                    .find(|i| !ips.contains(i))
                    .and_then(|i| IpNetwork::new(i, range_cidr.prefix()).ok()),
                IpRangeAllocationMode::Random => {
                    let mut rng = rand::rng();
                    match range_cidr {
                        IpNetwork::V4(v4) => loop {
                            let n = rng.random_range(0..v4.size());
                            let addr = IpAddr::V4(v4.nth(n).unwrap());
                            if !ips.contains(&addr) {
                                break IpNetwork::new(addr, range_cidr.prefix()).ok();
                            } else {
                                break None;
                            }
                        },
                        IpNetwork::V6(v6) => loop {
                            let n = rng.random_range(0..v6.size());
                            let addr = IpAddr::V6(v6.nth(n).unwrap());
                            if !ips.contains(&addr) {
                                break IpNetwork::new(addr, range_cidr.prefix()).ok();
                            } else {
                                break None;
                            }
                        },
                    }
                }
                IpRangeAllocationMode::SlaacEui64 => {
                    if range_cidr.network().is_ipv4() {
                        bail!("Cannot create EUI-64 from IPv4 address")
                    } else {
                        // basically always free ips here
                        Some(range_cidr)
                    }
                }
            }
        }
        .context("No ips available in range")?;

        Ok(AvailableIp {
            range_id: range.id,
            gateway,
            ip: ip_pick,
            region_id: range.region_id,
            mode: range.allocation_mode,
        })
    }

    pub fn calculate_eui64(mac: &[u8; 6], prefix: &IpNetwork) -> Result<IpAddr> {
        if prefix.is_ipv4() {
            bail!("Prefix must be IPv6".to_string())
        }

        let mut eui64 = [0u8; 8];
        eui64[0] = mac[0] ^ 0x02;
        eui64[1] = mac[1];
        eui64[2] = mac[2];
        eui64[3] = 0xFF;
        eui64[4] = 0xFE;
        eui64[5] = mac[3];
        eui64[6] = mac[4];
        eui64[7] = mac[5];

        // Combine prefix with EUI-64 interface identifier
        let mut prefix_bytes = match prefix.network() {
            IpAddr::V4(_) => bail!("Not supported"),
            IpAddr::V6(v6) => v6.octets(),
        };
        // copy EUI-64 into prefix
        prefix_bytes[8..16].copy_from_slice(&eui64);

        let ipv6_addr = Ipv6Addr::from(prefix_bytes);
        Ok(IpAddr::V6(ipv6_addr))
    }

    pub fn parse_mac(mac: &str) -> Result<[u8; 6]> {
        Ok(hex::decode(mac.replace(":", ""))?.as_slice().try_into()?)
    }

    pub fn ipv6_to_ptr(addr: &Ipv6Addr) -> Result<String> {
        let octets = addr.octets();
        let mut nibbles = Vec::new();
        for byte in octets.iter().rev() {
            let high_nibble = (byte >> 4) & 0x0Fu8;
            let low_nibble = byte & 0x0F;
            nibbles.push(format!("{:x}", low_nibble));
            nibbles.push(format!("{:x}", high_nibble));
        }
        Ok(format!("{}.ip6.arpa", nibbles.join(".")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::MockDb;
    use lnvps_db::VmIpAssignment;
    use std::str::FromStr;

    #[tokio::test]
    async fn pick_seq_ip_for_region_test() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(db.clone());

        let mac: [u8; 6] = [0xff, 0xff, 0xff, 0xfa, 0xfb, 0xfc];
        let gateway = IpNetwork::from_str("10.0.0.1/8").unwrap();
        let first = IpAddr::from_str("10.0.0.2").unwrap();
        let second = IpAddr::from_str("10.0.0.3").unwrap();
        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        let v4 = ip.ip4.unwrap();
        assert_eq!(v4.region_id, 1);
        assert_eq!(first, v4.ip.ip());
        assert_eq!(gateway, v4.gateway);

        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        let v4 = ip.ip4.unwrap();
        assert_eq!(1, v4.region_id);
        assert_eq!(first, v4.ip.ip());
        db.insert_vm_ip_assignment(&VmIpAssignment {
            id: 0,
            vm_id: 0,
            ip_range_id: v4.range_id,
            ip: v4.ip.ip().to_string(),
            ..Default::default()
        })
        .await
        .expect("Could not insert vm ip");
        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        let v4 = ip.ip4.unwrap();
        assert_eq!(second, v4.ip.ip());
    }

    #[tokio::test]
    async fn pick_rng_ip_for_region_test() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(db);

        let mac: [u8; 6] = [0xff, 0xff, 0xff, 0xfa, 0xfb, 0xfc];
        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        let v4 = ip.ip4.unwrap();
        let v6 = ip.ip6.unwrap();
        assert_eq!(1, v4.region_id);
    }
}
