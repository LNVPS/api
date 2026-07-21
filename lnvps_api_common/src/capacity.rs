use crate::Template;
use crate::network::parse_gateway;
use anyhow::Result;
use chrono::Utc;
use futures::future::join_all;
use ipnetwork::{IpNetwork, NetworkSize};
use lnvps_db::{
    CpuArch, CpuMfg, DbResult, DiskInterface, DiskType, IpRange, LNVpsDb, VmCustomTemplate, VmHost,
    VmHostDisk, VmIpAssignment, VmTemplate,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Errors related to host capacity that should be surfaced to the user rather
/// than logged as an opaque internal server error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityError {
    /// No host in the region can accommodate the requested configuration.
    NoAvailableHosts,
}

impl std::fmt::Display for CapacityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapacityError::NoAvailableHosts => write!(
                f,
                "No hosts with enough capacity are currently available in this region for the selected configuration"
            ),
        }
    }
}

impl std::error::Error for CapacityError {}

/// Simple capacity management
#[derive(Clone)]
pub struct HostCapacityService {
    /// Database
    db: Arc<dyn LNVpsDb>,
}

impl HostCapacityService {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// List templates which can be sold, based on available capacity
    pub async fn list_available_vm_templates(&self) -> Result<Vec<VmTemplate>> {
        let templates = self.db.list_vm_templates().await?;

        // TODO: list hosts in regions where templates are active?
        // use all hosts since we dont expect there to be many
        let hosts = self.db.list_hosts().await?;
        let caps: Vec<Result<HostCapacity>> =
            join_all(hosts.iter().map(|h| self.get_host_capacity(h, None, None))).await;
        let caps: Vec<HostCapacity> = caps.into_iter().filter_map(Result::ok).collect();

        Ok(templates
            .into_iter()
            .filter(|t| {
                caps.iter()
                    .filter(|c| c.host.region_id == t.region_id)
                    .any(|c| c.can_accommodate(t))
            })
            .collect())
    }

    /// Pick a host for the purposes of provisioning a new VM
    pub async fn get_host_for_template(
        &self,
        region_id: u64,
        template: &impl Template,
    ) -> Result<HostCapacity> {
        let hosts = self.db.list_hosts().await?;
        let caps: Vec<Result<HostCapacity>> =
            join_all(hosts.iter().filter(|h| h.region_id == region_id).map(|h| {
                self.get_host_capacity(
                    h,
                    Some(template.disk_type()),
                    Some(template.disk_interface()),
                )
            }))
            .await;
        let mut host_cap: Vec<HostCapacity> = caps
            .into_iter()
            .filter_map(|v| v.ok())
            .filter(|v| v.can_accommodate(template))
            .collect();

        host_cap.sort_by(|a, b| a.load().partial_cmp(&b.load()).unwrap());

        if let Some(f) = host_cap.into_iter().next() {
            Ok(f)
        } else {
            Err(CapacityError::NoAvailableHosts.into())
        }
    }

    /// Calculate and apply host capacity limits to custom pricing templates
    /// Processes all regions efficiently and modifies the vector in place
    pub async fn apply_host_capacity_limits(
        &self,
        templates: &Vec<crate::ApiCustomTemplateParams>,
    ) -> Result<Vec<crate::ApiCustomTemplateParams>> {
        if templates.is_empty() {
            return Ok(Vec::new());
        }

        // make a copy for modification
        let mut templates = templates.clone();

        // Get distinct region IDs from the templates
        let region_ids: HashSet<u64> = templates.iter().map(|t| t.region.id).collect();

        let hosts = self.db.list_hosts().await?;
        let caps: Vec<Result<HostCapacity>> = join_all(
            hosts
                .iter()
                .filter(|h| region_ids.contains(&h.region_id))
                .map(|h| self.get_host_capacity(h, None, None)),
        )
        .await;
        let caps: Vec<HostCapacity> = caps.into_iter().filter_map(|v| v.ok()).collect();

        // Now apply the calculated limits to each template in place
        for template in &mut templates {
            // Filter hosts by region and CPU requirements
            let hosts_in_region = caps.iter().filter(|c| {
                if c.host.region_id != template.region.id {
                    return false;
                }
                // Check CPU manufacturer match (None means any)
                if let Some(ref mfg) = template.cpu_mfg {
                    if c.host.cpu_mfg != CpuMfg::Unknown && c.host.cpu_mfg.to_string() != *mfg {
                        return false;
                    }
                }
                // Check CPU architecture match (None means any)
                if let Some(ref arch) = template.cpu_arch {
                    if c.host.cpu_arch != CpuArch::Unknown && c.host.cpu_arch.to_string() != *arch {
                        return false;
                    }
                }
                // Check CPU features (empty list means any)
                if !template.cpu_features.is_empty() {
                    let has_all = template
                        .cpu_features
                        .iter()
                        .all(|f| c.host.cpu_features.iter().any(|hf| hf.to_string() == *f));
                    if !has_all {
                        return false;
                    }
                }
                true
            });
            let min_cpu = template.min_cpu;
            let min_memory = template.min_memory;

            // Whether a host has a free IPv4 slot (required for every order).
            let host_has_ipv4 = |h: &&HostCapacity| {
                h.ranges
                    .iter()
                    .any(|r| r.is_ipv4() && r.available_capacity() >= 1)
            };

            // Limit disk maximums based on actual host capacity.
            //
            // CPU, memory, an IPv4 address and a matching disk must all be
            // satisfiable on the *same* host, otherwise we would advertise a
            // configuration (e.g. HDD storage) whose disk only exists on a host
            // that has no spare CPU. Only consider disks on hosts that can also
            // provide the minimum CPU/memory and a free IPv4 address.
            for disk in &mut template.disks {
                let dt: DiskType = disk.disk_type.into();
                let di: DiskInterface = disk.disk_interface.into();
                let max_disk_size = hosts_in_region
                    .clone()
                    .filter(host_has_ipv4)
                    .filter(|h| h.available_cpu() >= min_cpu && h.available_memory() >= min_memory)
                    .flat_map(|h| {
                        h.disks
                            .iter()
                            .filter(|c| c.disk.kind == dt && c.disk.interface == di)
                    })
                    .map(|d| d.available_capacity())
                    .max()
                    .unwrap_or(0);
                disk.max_disk = disk.max_disk.min(max_disk_size);
            }

            // Remove disks that can no longer fit their minimum size on any
            // capable host.
            template.disks = template
                .disks
                .iter()
                .filter(|d| d.max_disk >= d.min_disk && d.max_disk > 0)
                .cloned()
                .collect();

            // Limit the template CPU/memory maximums to hosts that can serve at
            // least one of the remaining disk options (same-host requirement).
            let servable_max = |select: &dyn Fn(&HostCapacity) -> u64| -> u64 {
                hosts_in_region
                    .clone()
                    .filter(host_has_ipv4)
                    .filter(|h| {
                        h.available_cpu() >= min_cpu
                            && h.available_memory() >= min_memory
                            && template.disks.iter().any(|disk| {
                                let dt: DiskType = disk.disk_type.into();
                                let di: DiskInterface = disk.disk_interface.into();
                                h.disks.iter().any(|c| {
                                    c.disk.kind == dt
                                        && c.disk.interface == di
                                        && c.available_capacity() >= disk.min_disk
                                })
                            })
                    })
                    .map(|h| select(h))
                    .max()
                    .unwrap_or(0)
            };
            let max_cpu = servable_max(&|h| h.available_cpu() as u64) as u16;
            let max_memory = servable_max(&|h| h.available_memory());
            template.max_cpu = template.max_cpu.min(max_cpu);
            template.max_memory = template.max_memory.min(max_memory);
        }

        // remove templates with 0 max cpu/ram/disk
        Ok(templates
            .into_iter()
            .filter(|t| t.max_cpu > 0 && t.max_memory > 0 && !t.disks.is_empty())
            .collect())
    }

    /// Get available capacity of a given host
    pub async fn get_host_capacity(
        &self,
        host: &VmHost,
        disk_type: Option<DiskType>,
        disk_interface: Option<DiskInterface>,
    ) -> Result<HostCapacity> {
        let all_vms = self.db.list_vms_on_host(host.id).await?;
        // Only count VMs that have been paid for (subscription is_setup = true)
        let mut vms = Vec::new();
        for vm in all_vms {
            if vm.deleted {
                continue;
            }
            let is_paid = self
                .db
                .get_subscription_by_line_item_id(vm.subscription_line_item_id)
                .await
                .map(|s| s.is_setup)
                .unwrap_or(false);
            if is_paid {
                vms.push(vm);
            }
        }

        // load ip ranges
        let ip_ranges = self.db.list_ip_range_in_region(host.region_id).await?;
        // TODO: handle very large number of assignments, maybe just count assignments
        let ip_range_assigned: Vec<VmIpAssignment> = join_all(
            ip_ranges
                .iter()
                .map(|r| self.db.list_vm_ip_assignments_in_range(r.id)),
        )
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect();

        // TODO: filter disks from DB? Should be very few disks anyway
        let storage = self.db.list_host_disks(host.id).await?;

        // load templates
        let templates = self.db.list_vm_templates().await?;
        let custom_templates: Vec<DbResult<VmCustomTemplate>> = join_all(
            vms.iter()
                .filter(|v| v.custom_template_id.is_some())
                .map(|v| {
                    self.db
                        .get_custom_vm_template(v.custom_template_id.unwrap())
                }),
        )
        .await;
        let custom_templates: HashMap<u64, VmCustomTemplate> = custom_templates
            .into_iter()
            .filter_map(|r| r.ok())
            .map(|v| (v.id, v))
            .collect();

        struct VmResources {
            vm_id: u64,
            cpu: u16,
            memory: u64,
            disk: u64,
            disk_id: u64,
        }
        // a mapping between vm_id and resources
        let vm_resources: HashMap<u64, VmResources> = vms
            .iter()
            .filter_map(|v| {
                if let Some(x) = v.template_id {
                    templates.iter().find(|t| t.id == x).map(|t| VmResources {
                        vm_id: v.id,
                        cpu: t.cpu,
                        memory: t.memory,
                        disk: t.disk_size,
                        disk_id: v.disk_id,
                    })
                } else if let Some(x) = v.custom_template_id {
                    custom_templates.get(&x).map(|t| VmResources {
                        vm_id: v.id,
                        cpu: t.cpu,
                        memory: t.memory,
                        disk: t.disk_size,
                        disk_id: v.disk_id,
                    })
                } else {
                    None
                }
            })
            .map(|m| (m.vm_id, m))
            .collect();

        let mut storage_disks: Vec<DiskCapacity> = storage
            .iter()
            .filter(|d| {
                disk_type.as_ref().map(|t| d.kind == *t).unwrap_or(true)
                    && disk_interface
                        .as_ref()
                        .map(|i| d.interface == *i)
                        .unwrap_or(true)
            })
            .map(|s| {
                let usage = vm_resources
                    .iter()
                    .filter(|(_k, v)| s.id == v.disk_id)
                    .fold(0, |acc, (_k, v)| acc + v.disk);
                DiskCapacity {
                    load_factor: host.load_disk,
                    disk: s.clone(),
                    usage,
                }
            })
            .collect();

        storage_disks.sort_by(|a, b| a.load_factor.partial_cmp(&b.load_factor).unwrap());

        let cpu_consumed = vm_resources.values().fold(0, |acc, vm| acc + vm.cpu);
        let memory_consumed = vm_resources.values().fold(0, |acc, vm| acc + vm.memory);

        Ok(HostCapacity {
            load_factor: LoadFactors {
                cpu: host.load_cpu,
                memory: host.load_memory,
                disk: host.load_disk,
            },
            host: host.clone(),
            cpu: cpu_consumed,
            memory: memory_consumed,
            disks: storage_disks,
            ranges: ip_ranges
                .into_iter()
                .map(|r| IPRangeCapacity {
                    usage: ip_range_assigned
                        .iter()
                        .filter(|z| z.ip_range_id == r.id)
                        .count() as u128,
                    range: r,
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LoadFactors {
    pub cpu: f32,
    pub memory: f32,
    pub disk: f32,
}

#[derive(Debug, Clone)]
pub struct HostCapacity {
    /// Load factor applied to resource consumption
    pub load_factor: LoadFactors,
    /// The host
    pub host: VmHost,
    /// Number of consumed CPU cores
    pub cpu: u16,
    /// Number of consumed bytes of memory
    pub memory: u64,
    /// List of disks on the host and its used space
    pub disks: Vec<DiskCapacity>,
    /// List of IP ranges and its usage
    pub ranges: Vec<IPRangeCapacity>,
}

impl HostCapacity {
    /// Total average usage as a percentage
    pub fn load(&self) -> f32 {
        (self.cpu_load() + self.memory_load() + self.disk_load()) / 3.0
    }

    /// CPU usage as a percentage
    pub fn cpu_load(&self) -> f32 {
        self.cpu as f32 / (self.host.cpu as f32 * self.load_factor.cpu)
    }

    /// Total number of available CPUs
    pub fn available_cpu(&self) -> u16 {
        let loaded_host_cpu = (self.host.cpu as f32 * self.load_factor.cpu).floor() as u16;
        loaded_host_cpu.saturating_sub(self.cpu)
    }

    /// Memory usage as a percentage
    pub fn memory_load(&self) -> f32 {
        self.memory as f32 / (self.host.memory as f32 * self.load_factor.memory)
    }

    /// Total available bytes of memory
    pub fn available_memory(&self) -> u64 {
        let loaded_host_memory =
            (self.host.memory as f64 * self.load_factor.memory as f64).floor() as u64;
        loaded_host_memory.saturating_sub(self.memory)
    }

    /// Disk usage as a percentage (average over all disks)
    pub fn disk_load(&self) -> f32 {
        self.disks.iter().fold(0.0, |acc, disk| acc + disk.load()) / self.disks.len() as f32
    }

    /// Can this host and its available capacity accommodate the given template
    pub fn can_accommodate(&self, template: &impl Template) -> bool {
        // Check cpu manufacturer match (Unknown means any)
        let mfg_ok =
            template.cpu_mfg() == CpuMfg::Unknown || self.host.cpu_mfg == template.cpu_mfg();
        // Check cpu architecture match (Unknown means any)
        let arch_ok =
            template.cpu_arch() == CpuArch::Unknown || self.host.cpu_arch == template.cpu_arch();
        // Check that the host has all required CPU features (empty list means any)
        let features_ok = template.cpu_features().is_empty()
            || template
                .cpu_features()
                .iter()
                .all(|f| self.host.cpu_features.contains(f));

        mfg_ok
            && arch_ok
            && features_ok
            && self.available_cpu() >= template.cpu()
            && self.available_memory() >= template.memory()
            && self
                .disks
                .iter()
                .any(|d| d.available_capacity() >= template.disk_size())
            && self
                .ranges
                .iter()
                .any(|r| r.is_ipv4() && r.available_capacity() >= 1)
    }
}

#[derive(Debug, Clone)]
pub struct DiskCapacity {
    /// Load factor applied to resource consumption
    pub load_factor: f32,
    /// Disk ID
    pub disk: VmHostDisk,
    /// Space consumed by VMs
    pub usage: u64,
}

impl DiskCapacity {
    /// Total available bytes of disk space
    pub fn available_capacity(&self) -> u64 {
        let loaded_disk_size = (self.disk.size as f64 * self.load_factor as f64).floor() as u64;
        loaded_disk_size.saturating_sub(self.usage)
    }

    /// Disk usage as percentage
    pub fn load(&self) -> f32 {
        (self.usage as f32 / self.disk.size as f32) * (1.0 / self.load_factor)
    }
}

#[derive(Debug, Clone)]
pub struct IPRangeCapacity {
    /// IP Range
    pub range: IpRange,
    /// Number of allocated IPs
    pub usage: u128,
}

impl IPRangeCapacity {
    /// Total number of IPs free
    pub fn available_capacity(&self) -> u128 {
        let net: IpNetwork = self.range.cidr.parse().unwrap();

        let total = match net.size() {
            NetworkSize::V4(s) => s as u128,
            NetworkSize::V6(s) => s,
        };

        // Only count the gateway as reserved if it actually falls within the CIDR.
        // Gateways may be outside the range (e.g. a shared upstream gateway), in
        // which case they do not consume a slot in this range.
        let gw_reserved: u128 = if let Ok(gw) = parse_gateway(&self.range.gateway) {
            if net.contains(gw.ip()) { 1 } else { 0 }
        } else {
            0
        };

        // If not using the full range, network and broadcast addresses are reserved.
        let boundary_reserved: u128 = if self.range.use_full_range { 0 } else { 2 };

        total
            .saturating_sub(self.usage)
            .saturating_sub(gw_reserved)
            .saturating_sub(boundary_reserved)
    }

    /// Returns true if this range is an IPv4 range
    pub fn is_ipv4(&self) -> bool {
        self.range
            .cidr
            .parse::<IpNetwork>()
            .map(|n| n.is_ipv4())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GB;
    use crate::mock::MockDb;
    use lnvps_db::{CpuFeature, DiskInterface, DiskType, LNVpsDbBase};

    #[test]
    fn loads() {
        let cap = HostCapacity {
            load_factor: LoadFactors {
                cpu: 2.0,
                memory: 3.0,
                disk: 4.0,
            },
            host: VmHost {
                cpu: 100,
                memory: 100,
                ..Default::default()
            },
            cpu: 8,
            memory: 8,
            disks: vec![DiskCapacity {
                load_factor: 4.0,
                disk: VmHostDisk {
                    size: 100,
                    ..Default::default()
                },
                usage: 8,
            }],
            ranges: vec![IPRangeCapacity {
                range: IpRange {
                    id: 1,
                    cidr: "10.0.0.0/24".to_string(),
                    gateway: "10.0.0.1".to_string(),
                    enabled: true,
                    region_id: 1,
                    ..Default::default()
                },
                usage: 69,
            }],
        };

        // load factor halves load values 8/100 * (1/load_factor)
        assert_eq!(cap.cpu_load(), 8.0 / 200.0);
        assert_eq!(cap.memory_load(), 8.0 / 300.0);
        assert_eq!(cap.disk_load(), 8.0 / 400.0);
        assert_eq!(
            cap.load(),
            ((8.0 / 200.0) + (8.0 / 300.0) + (8.0 / 400.0)) / 3.0
        );
        // load factor doubles memory to 300, 300 - 8
        assert_eq!(cap.available_memory(), 292);
        assert_eq!(cap.available_cpu(), 192);
        for r in cap.ranges {
            assert_eq!(r.usage, 69);
            assert_eq!(r.available_capacity(), 256 - 3 - 69);
        }
    }

    #[tokio::test]
    async fn empty_available_capacity() -> Result<()> {
        let db = Arc::new(MockDb::default());

        let hc = HostCapacityService::new(db.clone());
        let host = db.get_host(1).await?;
        let cap = hc.get_host_capacity(&host, None, None).await?;
        let disks = db.list_host_disks(1).await?;
        /// check all resources are available
        assert_eq!(cap.cpu, 0);
        assert_eq!(cap.memory, 0);
        assert_eq!(cap.disks.len(), disks.len());
        assert_eq!(cap.load(), 0.0);
        for disk in cap.disks {
            assert_eq!(0, disk.usage);
            assert_eq!(disk.load(), 0.0);
        }

        let template = db.get_vm_template(1).await?;
        let host = hc
            .get_host_for_template(template.region_id, &template)
            .await?;
        assert_eq!(host.host.id, 1);

        // all templates should be available
        let templates = hc.list_available_vm_templates().await?;
        assert_eq!(templates.len(), db.list_vm_templates().await?.len());

        Ok(())
    }

    #[tokio::test]
    async fn expired_doesnt_count() -> Result<()> {
        let db = MockDb::default();
        {
            let mut v = db.vms.lock().await;
            v.insert(1, MockDb::mock_vm());
        }

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        let hc = HostCapacityService::new(db.clone());
        let host = db.get_host(1).await?;
        let cap = hc.get_host_capacity(&host, None, None).await?;

        assert_eq!(cap.load(), 0.0);
        assert_eq!(cap.cpu, 0);
        assert_eq!(cap.memory, 0);
        for disk in cap.disks {
            assert_eq!(0, disk.usage);
        }
        Ok(())
    }

    // ── CPU filtering tests ──────────────────────────────────────────────────

    /// Helper to create a minimal VmTemplate for testing CPU filtering
    fn make_template(
        cpu_mfg: CpuMfg,
        cpu_arch: CpuArch,
        cpu_features: Vec<CpuFeature>,
    ) -> VmTemplate {
        VmTemplate {
            id: 99,
            name: "test-template".to_string(),
            enabled: true,
            cpu: 1,
            cpu_mfg,
            cpu_arch,
            cpu_features: cpu_features.into(),
            memory: GB,
            disk_size: GB,
            disk_type: DiskType::SSD,
            disk_interface: DiskInterface::PCIe,
            region_id: 1,
            ..Default::default()
        }
    }

    /// Helper to create a HostCapacity with specific CPU fields
    fn make_host_capacity(
        cpu_mfg: CpuMfg,
        cpu_arch: CpuArch,
        cpu_features: Vec<CpuFeature>,
    ) -> HostCapacity {
        HostCapacity {
            load_factor: LoadFactors {
                cpu: 1.0,
                memory: 1.0,
                disk: 1.0,
            },
            host: VmHost {
                id: 1,
                region_id: 1,
                cpu: 4,
                cpu_mfg,
                cpu_arch,
                cpu_features: cpu_features.into(),
                memory: 8 * GB,
                enabled: true,
                ..Default::default()
            },
            cpu: 0,
            memory: 0,
            disks: vec![DiskCapacity {
                load_factor: 1.0,
                disk: VmHostDisk {
                    id: 1,
                    host_id: 1,
                    size: 100 * GB,
                    kind: DiskType::SSD,
                    interface: DiskInterface::PCIe,
                    ..Default::default()
                },
                usage: 0,
            }],
            ranges: vec![IPRangeCapacity {
                range: IpRange {
                    id: 1,
                    cidr: "10.0.0.0/24".to_string(),
                    gateway: "10.0.0.1".to_string(),
                    enabled: true,
                    region_id: 1,
                    ..Default::default()
                },
                usage: 0,
            }],
        }
    }

    /// Template with Unknown cpu_mfg should match any host
    #[test]
    fn can_accommodate_unknown_mfg_matches_any() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![]);
        let template = make_template(CpuMfg::Unknown, CpuArch::Unknown, vec![]);
        assert!(cap.can_accommodate(&template));
    }

    /// Template requesting Intel should match Intel host
    #[test]
    fn can_accommodate_matching_mfg() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![]);
        let template = make_template(CpuMfg::Intel, CpuArch::Unknown, vec![]);
        assert!(cap.can_accommodate(&template));
    }

    /// Template requesting AMD should NOT match Intel host
    #[test]
    fn can_accommodate_mismatched_mfg() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![]);
        let template = make_template(CpuMfg::Amd, CpuArch::Unknown, vec![]);
        assert!(!cap.can_accommodate(&template));
    }

    /// Template requesting X86_64 should match X86_64 host
    #[test]
    fn can_accommodate_matching_arch() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![]);
        let template = make_template(CpuMfg::Unknown, CpuArch::X86_64, vec![]);
        assert!(cap.can_accommodate(&template));
    }

    /// Template requesting ARM64 should NOT match X86_64 host
    #[test]
    fn can_accommodate_mismatched_arch() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![]);
        let template = make_template(CpuMfg::Unknown, CpuArch::ARM64, vec![]);
        assert!(!cap.can_accommodate(&template));
    }

    /// Template with no required features should match any host
    #[test]
    fn can_accommodate_empty_features_matches_any() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![CpuFeature::AVX2]);
        let template = make_template(CpuMfg::Unknown, CpuArch::Unknown, vec![]);
        assert!(cap.can_accommodate(&template));
    }

    /// Template requiring AVX2 should match host with AVX2
    #[test]
    fn can_accommodate_matching_features() {
        let cap = make_host_capacity(
            CpuMfg::Intel,
            CpuArch::X86_64,
            vec![CpuFeature::AVX, CpuFeature::AVX2],
        );
        let template = make_template(CpuMfg::Unknown, CpuArch::Unknown, vec![CpuFeature::AVX2]);
        assert!(cap.can_accommodate(&template));
    }

    /// Template requiring AVX512F should NOT match host with only AVX2
    #[test]
    fn can_accommodate_missing_features() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![CpuFeature::AVX2]);
        let template = make_template(CpuMfg::Unknown, CpuArch::Unknown, vec![CpuFeature::AVX512F]);
        assert!(!cap.can_accommodate(&template));
    }

    /// Template requiring multiple features should match host with all of them
    #[test]
    fn can_accommodate_multiple_features_all_present() {
        let cap = make_host_capacity(
            CpuMfg::Intel,
            CpuArch::X86_64,
            vec![CpuFeature::AVX, CpuFeature::AVX2, CpuFeature::AES],
        );
        let template = make_template(
            CpuMfg::Unknown,
            CpuArch::Unknown,
            vec![CpuFeature::AVX, CpuFeature::AES],
        );
        assert!(cap.can_accommodate(&template));
    }

    /// Template requiring multiple features should NOT match host missing one
    #[test]
    fn can_accommodate_multiple_features_one_missing() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![CpuFeature::AVX]);
        let template = make_template(
            CpuMfg::Unknown,
            CpuArch::Unknown,
            vec![CpuFeature::AVX, CpuFeature::AES],
        );
        assert!(!cap.can_accommodate(&template));
    }

    /// Combined: Intel + X86_64 + AVX2 should match when all requirements met
    #[test]
    fn can_accommodate_combined_requirements_match() {
        let cap = make_host_capacity(
            CpuMfg::Intel,
            CpuArch::X86_64,
            vec![CpuFeature::AVX, CpuFeature::AVX2],
        );
        let template = make_template(CpuMfg::Intel, CpuArch::X86_64, vec![CpuFeature::AVX2]);
        assert!(cap.can_accommodate(&template));
    }

    /// Combined: AMD + X86_64 should NOT match Intel host even with correct arch
    #[test]
    fn can_accommodate_combined_requirements_mfg_mismatch() {
        let cap = make_host_capacity(CpuMfg::Intel, CpuArch::X86_64, vec![CpuFeature::AVX2]);
        let template = make_template(CpuMfg::Amd, CpuArch::X86_64, vec![]);
        assert!(!cap.can_accommodate(&template));
    }

    // ── IP range capacity tests ──────────────────────────────────────────────

    /// Gateway outside CIDR must NOT be counted as a reserved slot.
    /// Previously the capacity was always decremented by 1 for the gateway
    /// regardless of whether the gateway IP fell inside the range.
    #[test]
    fn ip_range_capacity_external_gateway_not_counted() {
        // /30 has 4 IPs total; with use_full_range=false, 2 are reserved (network+broadcast).
        // Gateway 192.168.1.1 is outside 10.0.0.0/30, so it does NOT consume a slot.
        // Available = 4 - 2 (network/broadcast) - 0 (gateway outside range) - 0 (usage) = 2
        let cap = IPRangeCapacity {
            range: IpRange {
                id: 1,
                cidr: "10.0.0.0/30".to_string(),
                gateway: "192.168.1.1".to_string(),
                enabled: true,
                region_id: 1,
                use_full_range: false,
                ..Default::default()
            },
            usage: 0,
        };
        assert_eq!(cap.available_capacity(), 2);
    }

    /// Gateway inside CIDR must still be counted as a reserved slot.
    #[test]
    fn ip_range_capacity_internal_gateway_counted() {
        // /30 has 4 IPs total; with use_full_range=false, 2 are reserved (network+broadcast).
        // Gateway 10.0.0.1 is inside 10.0.0.0/30, so it consumes a slot.
        // Available = 4 - 2 (network/broadcast) - 1 (gateway inside range) - 0 (usage) = 1
        let cap = IPRangeCapacity {
            range: IpRange {
                id: 1,
                cidr: "10.0.0.0/30".to_string(),
                gateway: "10.0.0.1".to_string(),
                enabled: true,
                region_id: 1,
                use_full_range: false,
                ..Default::default()
            },
            usage: 0,
        };
        assert_eq!(cap.available_capacity(), 1);
    }

    /// When all IPv4 addresses are exhausted but IPv6 still has space,
    /// can_accommodate must return false — not true because of IPv6 capacity.
    /// This was the root cause of regions showing capacity when IPv4 was gone.
    #[test]
    fn can_accommodate_false_when_ipv4_exhausted_ipv6_available() {
        let template = make_template(CpuMfg::Unknown, CpuArch::Unknown, vec![]);

        // /30: 4 total, 2 reserved (network+broadcast), gateway outside => 2 usable.
        // usage=2 means both IPv4 slots are taken.
        let cap = HostCapacity {
            load_factor: LoadFactors {
                cpu: 1.0,
                memory: 1.0,
                disk: 1.0,
            },
            host: VmHost {
                id: 1,
                region_id: 1,
                cpu: 4,
                memory: 8 * GB,
                enabled: true,
                ..Default::default()
            },
            cpu: 0,
            memory: 0,
            disks: vec![DiskCapacity {
                load_factor: 1.0,
                disk: VmHostDisk {
                    id: 1,
                    host_id: 1,
                    size: 100 * GB,
                    kind: DiskType::SSD,
                    interface: DiskInterface::PCIe,
                    ..Default::default()
                },
                usage: 0,
            }],
            ranges: vec![
                // IPv4 range — fully exhausted
                IPRangeCapacity {
                    range: IpRange {
                        id: 1,
                        cidr: "10.0.0.0/30".to_string(),
                        gateway: "192.168.1.1".to_string(), // external gateway
                        enabled: true,
                        region_id: 1,
                        use_full_range: false,
                        ..Default::default()
                    },
                    usage: 2, // all 2 usable IPv4 slots consumed
                },
                // IPv6 range — still has space
                IPRangeCapacity {
                    range: IpRange {
                        id: 2,
                        cidr: "fd00::/64".to_string(),
                        gateway: "fd00::1".to_string(),
                        enabled: true,
                        region_id: 1,
                        use_full_range: true,
                        ..Default::default()
                    },
                    usage: 0,
                },
            ],
        };

        assert_eq!(
            cap.ranges[0].available_capacity(),
            0,
            "IPv4 range should be fully exhausted"
        );
        assert!(
            cap.ranges[1].available_capacity() > 0,
            "IPv6 range should have capacity"
        );
        assert!(
            !cap.can_accommodate(&template),
            "should not accommodate when IPv4 is exhausted, even with IPv6 space"
        );
    }

    // ── apply_host_capacity_limits tests ────────────────────────────────────

    /// Helper to build a minimal ApiCustomTemplateParams for region 1
    fn make_custom_template_params(
        max_cpu: u16,
        max_memory: u64,
    ) -> crate::ApiCustomTemplateParams {
        use crate::model::{
            ApiCustomTemplateDiskParam, ApiDiskInterface, ApiDiskType, ApiVmHostRegion,
        };
        crate::ApiCustomTemplateParams {
            id: 1,
            name: "test".to_string(),
            region: ApiVmHostRegion {
                id: 1,
                name: "test-region".to_string(),
                company_id: 1,
            },
            cpu_features: vec![],
            cpu_mfg: None,
            cpu_arch: None,
            max_cpu,
            min_cpu: 1,
            min_memory: GB,
            max_memory,
            disks: vec![ApiCustomTemplateDiskParam {
                min_disk: GB,
                max_disk: 100 * GB,
                disk_type: ApiDiskType::SSD,
                disk_interface: ApiDiskInterface::PCIe,
            }],
        }
    }

    /// When IPv4 is exhausted, apply_host_capacity_limits must remove the
    /// custom template (set max_cpu=0 so it is filtered out).
    #[tokio::test]
    async fn apply_host_capacity_limits_removes_template_when_ipv4_exhausted() -> Result<()> {
        use lnvps_db::VmIpAssignment;

        let db = Arc::new(MockDb::default());

        // The default MockDb has a /24 IPv4 range (id=1) with 253 usable slots.
        // Fill all of them so available_capacity() == 0.
        {
            let mut assignments = db.ip_assignments.lock().await;
            for i in 0u64..253 {
                assignments.insert(
                    i + 1,
                    VmIpAssignment {
                        id: i + 1,
                        vm_id: 1,
                        ip_range_id: 1,
                        ip: format!("10.0.0.{}", i + 2),
                        ..Default::default()
                    },
                );
            }
        }

        let hc = HostCapacityService::new(db.clone() as Arc<dyn LNVpsDb>);
        let template = make_custom_template_params(16, 64 * GB);

        let result = hc.apply_host_capacity_limits(&vec![template]).await?;

        assert!(
            result.is_empty(),
            "custom template should be removed when IPv4 is exhausted"
        );
        Ok(())
    }

    /// When IPv4 has capacity, apply_host_capacity_limits must keep the template.
    #[tokio::test]
    async fn apply_host_capacity_limits_keeps_template_when_ipv4_available() -> Result<()> {
        let db = Arc::new(MockDb::default());
        // No IP assignments — full IPv4 capacity available.

        let hc = HostCapacityService::new(db.clone() as Arc<dyn LNVpsDb>);
        let template = make_custom_template_params(4, 8 * GB);

        let result = hc.apply_host_capacity_limits(&vec![template]).await?;

        assert_eq!(
            result.len(),
            1,
            "custom template should be kept when IPv4 is available"
        );
        Ok(())
    }

    /// Regression (Dublin scenario): a disk type (HDD) that only exists on a
    /// host with no spare CPU must NOT be offered, even though another host in
    /// the region has free CPU (but only SSD). CPU and disk must be satisfiable
    /// on the same host.
    #[tokio::test]
    async fn apply_host_capacity_limits_drops_disk_only_on_cpu_full_host() -> Result<()> {
        use crate::model::{ApiCustomTemplateDiskParam, ApiDiskInterface, ApiDiskType};
        use lnvps_db::VmHostKind;

        let db = Arc::new(MockDb::default());

        // Default host 1: SSD/PCIe, cpu=4 (has free CPU), region 1.
        // Add host 2: HDD/SATA only, but with zero schedulable CPU.
        {
            let mut hosts = db.hosts.lock().await;
            hosts.insert(
                2,
                VmHost {
                    id: 2,
                    kind: VmHostKind::Dummy,
                    region_id: 1,
                    name: "hdd-full-host".to_string(),
                    ip: "https://localhost".to_string(),
                    cpu: 0, // no schedulable CPU -> available_cpu() == 0
                    cpu_mfg: CpuMfg::Intel,
                    cpu_arch: CpuArch::X86_64,
                    cpu_features: Default::default(),
                    memory: 8 * GB,
                    enabled: true,
                    api_token: "".into(),
                    load_cpu: 1.0,
                    load_memory: 1.0,
                    load_disk: 1.0,
                    vlan_id: Some(100),
                    mtu: None,
                    ssh_user: None,
                    ssh_key: None,
                    sunset_date: None,
                },
            );
            let mut disks = db.host_disks.lock().await;
            disks.insert(
                2,
                VmHostDisk {
                    id: 2,
                    host_id: 2,
                    name: "hdd-disk".to_string(),
                    size: crate::TB * 10,
                    kind: DiskType::HDD,
                    interface: DiskInterface::SATA,
                    enabled: true,
                },
            );
        }

        let hc = HostCapacityService::new(db.clone() as Arc<dyn LNVpsDb>);

        // Template offers both SSD/PCIe and HDD/SATA.
        let mut template = make_custom_template_params(4, 8 * GB);
        template.disks = vec![
            ApiCustomTemplateDiskParam {
                min_disk: GB,
                max_disk: 100 * GB,
                disk_type: ApiDiskType::SSD,
                disk_interface: ApiDiskInterface::PCIe,
            },
            ApiCustomTemplateDiskParam {
                min_disk: GB,
                max_disk: 100 * GB,
                disk_type: ApiDiskType::HDD,
                disk_interface: ApiDiskInterface::SATA,
            },
        ];

        let result = hc.apply_host_capacity_limits(&vec![template]).await?;

        assert_eq!(result.len(), 1, "SSD template must remain orderable");
        let disks = &result[0].disks;
        assert_eq!(
            disks.len(),
            1,
            "HDD disk (only on the CPU-full host) must be dropped"
        );
        assert!(
            matches!(disks[0].disk_type, ApiDiskType::SSD),
            "only the SSD option should remain"
        );
        assert!(result[0].max_cpu > 0, "SSD host still has schedulable CPU");
        Ok(())
    }
}
