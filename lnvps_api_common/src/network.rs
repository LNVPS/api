use anyhow::{Context, Result, bail};
use ipnetwork::{IpNetwork, NetworkSize};
use lnvps_db::{IpRange, IpRangeAllocationMode, LNVpsDb};
use log::warn;
use rand::Rng;
use rand::prelude::SliceRandom;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

/// Parse gateway string as IpNetwork, with backward compatibility for plain IP addresses.
/// If the string is a plain IP address without CIDR notation, it will be converted to:
/// - /32 for IPv4 addresses
/// - /128 for IPv6 addresses
///
/// This is a public function that can be used across the codebase for consistent gateway parsing.
pub fn parse_gateway(gateway: &str) -> Result<IpNetwork> {
    // Try parsing as IpNetwork first (CIDR notation)
    if let Ok(network) = gateway.parse::<IpNetwork>() {
        return Ok(network);
    }

    // Try parsing as plain IpAddr for backward compatibility
    if let Ok(ip) = gateway.parse::<IpAddr>() {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        return IpNetwork::new(ip, prefix)
            .with_context(|| format!("Failed to create network from IP {}", gateway));
    }

    bail!("Invalid gateway format: {}", gateway)
}

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
        // Parse stored IPs (stored as plain IP addresses)
        let mut ips: HashSet<IpAddr> = ips.iter().map_while(|i| i.ip.parse().ok()).collect();

        let gateway: IpNetwork = parse_gateway(&range.gateway)?;

        // Calculate the prefix to use: take the smallest prefix value (largest network)
        // between the allocation range and the gateway CIDR.
        // This allows VMs to reach gateways outside their allocation range.
        let max_net = range_cidr.prefix().min(gateway.prefix());

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
                    .and_then(|i| IpNetwork::new(i, max_net).ok()),
                IpRangeAllocationMode::Random => {
                    let mut rng = rand::rng();
                    match range_cidr {
                        IpNetwork::V4(v4) => loop {
                            let n = rng.random_range(0..v4.size());
                            let addr = IpAddr::V4(v4.nth(n).unwrap());
                            if !ips.contains(&addr) {
                                break IpNetwork::new(addr, max_net).ok();
                            } else {
                                continue;
                            }
                        },
                        IpNetwork::V6(v6) => loop {
                            let n = rng.random_range(0..v6.size());
                            let addr = IpAddr::V6(v6.nth(n).unwrap());
                            if !ips.contains(&addr) {
                                break IpNetwork::new(addr, max_net).ok();
                            } else {
                                continue;
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

    /// Count the number of available IPs in an IPv4 range.
    /// Returns None for IPv6 ranges.
    pub fn count_available_ips(range: &IpRange, assignment_count: u64) -> Option<u64> {
        let network: IpNetwork = range.cidr.parse().ok()?;

        // Only calculate for IPv4
        let total_ips = match network.size() {
            NetworkSize::V4(s) => s as u64,
            NetworkSize::V6(_) => return None,
        };

        // Reserved IPs: gateway is always reserved
        // If use_full_range is false, first and last IPs are also reserved (network + broadcast)
        let reserved = if range.use_full_range { 1 } else { 3 };

        let available = total_ips
            .saturating_sub(reserved)
            .saturating_sub(assignment_count);
        Some(available)
    }

    /// List all free (unassigned) IPs in an IPv4 range.
    ///
    /// Returns an error for IPv6 ranges since they're too large to enumerate.
    ///
    /// # Arguments
    /// * `range_id` - The ID of the IP range to list free IPs for
    ///
    /// # Returns
    /// * `Ok(Vec<IpAddr>)` - List of free IP addresses
    /// * `Err` - If the range is IPv6, doesn't exist, or has an invalid CIDR
    pub async fn list_free_ips_in_range(&self, range_id: u64) -> Result<Vec<IpAddr>> {
        let range = self.db.get_ip_range(range_id).await?;
        Self::compute_free_ips(&range, &self.db).await
    }

    /// Compute the list of free IPs for a given IP range.
    ///
    /// This is an internal method that takes the range and database reference.
    /// Only works for IPv4 ranges.
    async fn compute_free_ips(range: &IpRange, db: &Arc<dyn LNVpsDb>) -> Result<Vec<IpAddr>> {
        let network: IpNetwork = range
            .cidr
            .parse()
            .with_context(|| format!("Invalid CIDR format: {}", range.cidr))?;

        // Only allow IPv4 ranges
        if !network.is_ipv4() {
            bail!(
                "Free IP listing is only available for IPv4 ranges. IPv6 ranges are too large to enumerate."
            );
        }

        // Get all assigned IPs in this range (non-deleted)
        let assignments = db.list_vm_ip_assignments_in_range(range.id).await?;
        let assigned_ips: HashSet<IpAddr> = assignments
            .iter()
            .filter_map(|a| a.ip.parse().ok())
            .collect();

        // Parse gateway to get reserved IPs
        let gateway = parse_gateway(&range.gateway)?;

        // Build set of reserved IPs
        let mut reserved_ips: HashSet<IpAddr> = HashSet::new();
        reserved_ips.insert(gateway.ip());

        // If not using full range, reserve first and last IPs (network + broadcast)
        if !range.use_full_range {
            if let Some(first) = network.iter().next() {
                reserved_ips.insert(first);
            }
            if let Some(last) = network.iter().last() {
                reserved_ips.insert(last);
            }
        }

        // Collect free IPs
        let free_ips: Vec<IpAddr> = network
            .iter()
            .filter(|ip| !assigned_ips.contains(ip) && !reserved_ips.contains(ip))
            .collect();

        Ok(free_ips)
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
        env_logger::try_init().ok();
        let db = MockDb::default();
        if let Some(r) = db.ip_range.lock().await.get_mut(&1) {
            r.allocation_mode = IpRangeAllocationMode::Sequential;
        }
        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db.clone());

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
        env_logger::try_init().ok();
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(db);

        let ip = mgr.pick_ip_for_region(1).await.expect("No ip found in db");
        let v4 = ip.ip4.unwrap();
        let v6 = ip.ip6.unwrap();
        assert_eq!(1, v4.region_id);
        assert_eq!(1, v6.region_id);
    }

    #[tokio::test]
    async fn pick_rng_always_ok() {
        env_logger::try_init().ok();
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mgr = NetworkProvisioner::new(db);
        for _ in 0..1_000 {
            let ips = mgr.pick_ip_for_region(1).await.expect("No ips found in db");
            assert!(ips.ip4.is_some());
            assert!(ips.ip6.is_some());
        }
    }

    #[test]
    fn test_parse_gateway_cidr() {
        // Test parsing gateway with CIDR notation
        let gw = parse_gateway("10.0.0.1/24").unwrap();
        assert_eq!(gw.to_string(), "10.0.0.1/24");

        let gw = parse_gateway("185.18.221.1/24").unwrap();
        assert_eq!(gw.to_string(), "185.18.221.1/24");

        // Test IPv6 CIDR
        let gw = parse_gateway("2001:db8::1/64").unwrap();
        assert_eq!(gw.to_string(), "2001:db8::1/64");
    }

    #[test]
    fn test_parse_gateway_plain_ip() {
        // Test parsing plain IP addresses (backward compatibility)
        let gw = parse_gateway("10.0.0.1").unwrap();
        assert_eq!(gw.to_string(), "10.0.0.1/32");

        let gw = parse_gateway("185.18.221.1").unwrap();
        assert_eq!(gw.to_string(), "185.18.221.1/32");

        // Test IPv6 plain address
        let gw = parse_gateway("2001:db8::1").unwrap();
        assert_eq!(gw.to_string(), "2001:db8::1/128");
    }

    #[test]
    fn test_parse_gateway_invalid() {
        // Test invalid gateway formats
        assert!(parse_gateway("invalid").is_err());
        assert!(parse_gateway("").is_err());
        assert!(parse_gateway("10.0.0.256").is_err());
        assert!(parse_gateway("10.0.0.1/33").is_err());
    }

    #[tokio::test]
    async fn test_gateway_cidr_wider_than_range() {
        env_logger::try_init().ok();
        let db = MockDb::default();

        // Create an IP range with a smaller subnet but wider gateway
        // Example: allocation range is 185.18.221.64/26 but gateway is 185.18.221.1/24
        let range = IpRange {
            id: 99,
            cidr: "185.18.221.64/26".to_string(), // /26 = 64 IPs (185.18.221.64-127)
            gateway: "185.18.221.1/24".to_string(), // Gateway is in the broader /24 network
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::Sequential,
            use_full_range: false,
            ..Default::default()
        };

        db.ip_range.lock().await.insert(99, range.clone());

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db);

        // Pick an IP from this range
        let available = mgr
            .pick_ip_from_range_id(99)
            .await
            .expect("Failed to pick IP");

        // Verify the gateway is parsed correctly with /24 prefix
        assert_eq!(available.gateway.prefix(), 24);
        assert_eq!(available.gateway.ip().to_string(), "185.18.221.1");

        // Verify the allocated IP has the correct prefix (/24 from gateway, not /26 from range)
        assert_eq!(
            available.ip.prefix(),
            24,
            "IP should have /24 prefix from gateway"
        );

        // Verify the allocated IP address itself is from the /26 range
        let ip = available.ip.ip();
        let ip_str = ip.to_string();
        assert!(ip_str.starts_with("185.18.221."));

        // Parse the last octet to ensure it's in the /26 range (64-127)
        let last_octet: u8 = ip_str.split('.').last().unwrap().parse().unwrap();
        assert!(
            last_octet >= 64 && last_octet <= 127,
            "IP {} should be in range 185.18.221.64-127",
            ip_str
        );
    }

    #[tokio::test]
    async fn test_gateway_cidr_ipv6() {
        env_logger::try_init().ok();
        let db = MockDb::default();

        // Create an IPv6 range with a smaller subnet but wider gateway
        let range = IpRange {
            id: 100,
            cidr: "2001:db8::/80".to_string(), // /80 allocation range
            gateway: "2001:db8::1/64".to_string(), // Gateway is in the broader /64 network
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::Sequential,
            use_full_range: false,
            ..Default::default()
        };

        db.ip_range.lock().await.insert(100, range.clone());

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db);

        // Pick an IP from this range
        let available = mgr
            .pick_ip_from_range_id(100)
            .await
            .expect("Failed to pick IPv6");

        // Verify the gateway is parsed correctly with /64 prefix
        assert_eq!(available.gateway.prefix(), 64);
        assert_eq!(available.gateway.ip().to_string(), "2001:db8::1");

        // Verify the allocated IP has /64 prefix (from gateway, not /80 from range)
        assert_eq!(
            available.ip.prefix(),
            64,
            "IP should have /64 prefix from gateway"
        );
    }

    #[tokio::test]
    async fn test_list_free_ips_basic() {
        env_logger::try_init().ok();
        let db = MockDb::default();

        // Create a small /30 range (4 IPs total)
        let range = IpRange {
            id: 101,
            cidr: "192.168.1.0/30".to_string(),
            gateway: "192.168.1.1".to_string(),
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::Sequential,
            use_full_range: false,
            ..Default::default()
        };

        db.ip_range.lock().await.insert(101, range);

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db);

        let free_ips = mgr.list_free_ips_in_range(101).await.unwrap();

        // /30 has 4 IPs: .0, .1, .2, .3
        // Reserved: .0 (network), .3 (broadcast), .1 (gateway)
        // Free: .2
        assert_eq!(free_ips.len(), 1);
        assert_eq!(free_ips[0].to_string(), "192.168.1.2");
    }

    #[tokio::test]
    async fn test_list_free_ips_with_assignments() {
        env_logger::try_init().ok();
        let db = MockDb::default();

        // Create a /29 range (8 IPs total)
        let range = IpRange {
            id: 102,
            cidr: "192.168.1.0/29".to_string(),
            gateway: "192.168.1.1".to_string(),
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::Sequential,
            use_full_range: false,
            ..Default::default()
        };

        db.ip_range.lock().await.insert(102, range);

        // Add some assignments
        db.ip_assignments.lock().await.insert(
            1,
            VmIpAssignment {
                id: 1,
                vm_id: 1,
                ip_range_id: 102,
                ip: "192.168.1.2".to_string(),
                ..Default::default()
            },
        );
        db.ip_assignments.lock().await.insert(
            2,
            VmIpAssignment {
                id: 2,
                vm_id: 2,
                ip_range_id: 102,
                ip: "192.168.1.4".to_string(),
                ..Default::default()
            },
        );

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db);

        let free_ips = mgr.list_free_ips_in_range(102).await.unwrap();

        // /29 has 8 IPs: .0, .1, .2, .3, .4, .5, .6, .7
        // Reserved: .0 (network), .7 (broadcast), .1 (gateway)
        // Assigned: .2, .4
        // Free: .3, .5, .6
        assert_eq!(free_ips.len(), 3);
        let free_ip_strs: Vec<String> = free_ips.iter().map(|ip| ip.to_string()).collect();
        assert!(free_ip_strs.contains(&"192.168.1.3".to_string()));
        assert!(free_ip_strs.contains(&"192.168.1.5".to_string()));
        assert!(free_ip_strs.contains(&"192.168.1.6".to_string()));
    }

    #[tokio::test]
    async fn test_list_free_ips_use_full_range() {
        env_logger::try_init().ok();
        let db = MockDb::default();

        // Create a /30 range with use_full_range=true
        let range = IpRange {
            id: 103,
            cidr: "192.168.1.0/30".to_string(),
            gateway: "192.168.1.1".to_string(),
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::Sequential,
            use_full_range: true,
            ..Default::default()
        };

        db.ip_range.lock().await.insert(103, range);

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db);

        let free_ips = mgr.list_free_ips_in_range(103).await.unwrap();

        // /30 has 4 IPs: .0, .1, .2, .3
        // Reserved: .1 (gateway only)
        // Free: .0, .2, .3
        assert_eq!(free_ips.len(), 3);
        let free_ip_strs: Vec<String> = free_ips.iter().map(|ip| ip.to_string()).collect();
        assert!(free_ip_strs.contains(&"192.168.1.0".to_string()));
        assert!(free_ip_strs.contains(&"192.168.1.2".to_string()));
        assert!(free_ip_strs.contains(&"192.168.1.3".to_string()));
    }

    #[tokio::test]
    async fn test_list_free_ips_ipv6_error() {
        env_logger::try_init().ok();
        let db = MockDb::default();

        // Create an IPv6 range
        let range = IpRange {
            id: 104,
            cidr: "2001:db8::/64".to_string(),
            gateway: "2001:db8::1".to_string(),
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::Sequential,
            use_full_range: false,
            ..Default::default()
        };

        db.ip_range.lock().await.insert(104, range);

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let mgr = NetworkProvisioner::new(db);

        let result = mgr.list_free_ips_in_range(104).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("IPv4 ranges"));
    }
}
