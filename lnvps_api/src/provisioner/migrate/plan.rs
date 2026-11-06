use crate::host::VmResources;
use lnvps_api_common::{
    HostCapacity, IpPolicy, MIGRATION_ESTIMATE_BYTES_PER_SEC, MigrationIpChange, MigrationMethod,
    MigrationOptions, MigrationPlan,
};
use lnvps_db::{IpRange, OsDistribution, Vm, VmHost, VmHostDisk, VmHostKind, VmOsImage};
use std::net::IpAddr;

pub struct PlanInputs<'a> {
    pub vm: &'a Vm,
    pub resources: &'a VmResources,
    pub image: &'a VmOsImage,
    pub source_host: &'a VmHost,
    pub source_disk: &'a VmHostDisk,
    pub target_host: &'a VmHost,
    pub target_capacity: &'a HostCapacity,
    pub assigned_ranges: &'a [IpRange],
    pub assigned_ips: &'a [String],
    pub options: &'a MigrationOptions,
}

pub fn plan_vm_migration(input: &PlanInputs<'_>) -> MigrationPlan {
    let source = input.source_host;
    let target = input.target_host;
    let options = input.options;
    let method = migration_method(&source.kind, &target.kind);
    let disk_bytes = input.resources.disk_size;
    let mut plan = MigrationPlan {
        vm_id: input.vm.id,
        source_host_id: source.id,
        source_host_kind: source.kind.to_string(),
        source_region_id: source.region_id,
        target_host_id: target.id,
        target_host_kind: target.kind.to_string(),
        target_region_id: target.region_id,
        method,
        ip_policy: options.ip_policy,
        keep_source: options.keep_source,
        target_disk_id: None,
        target_storage: None,
        disk_bytes,
        estimated_seconds: Some(disk_bytes.div_ceil(MIGRATION_ESTIMATE_BYTES_PER_SEC)),
        transfer_timeout_seconds: options.transfer_timeout_secs(disk_bytes),
        ip_changes: vec![],
        warnings: vec![],
        refusals: vec![],
    };
    let refuse = |plan: &mut MigrationPlan, msg: String| plan.refusals.push(msg);

    if target.id == source.id {
        refuse(&mut plan, format!("VM is already on host {}", target.id));
    }
    if !target.enabled {
        refuse(&mut plan, format!("Target host {} is disabled", target.id));
    }
    if method.is_none() {
        refuse(
            &mut plan,
            format!(
                "Migrating from {} to {} hosts is not supported; supported pairs are \
                 proxmox to proxmox and libvirt or marketplace_node to proxmox",
                source.kind, target.kind
            ),
        );
    }
    if target.cpu_arch != source.cpu_arch {
        refuse(
            &mut plan,
            format!(
                "Target host CPU architecture ({}) does not match the source ({})",
                target.cpu_arch, source.cpu_arch
            ),
        );
    }
    if method == Some(MigrationMethod::CopyAndAdopt) && !is_linux(&input.image.distribution) {
        refuse(
            &mut plan,
            format!(
                "Only Linux cloud images can be copied between host kinds, this VM runs {:?}",
                input.image.distribution
            ),
        );
    }

    let cap = input.target_capacity;
    if cap.available_cpu() < input.resources.cpu {
        refuse(
            &mut plan,
            format!(
                "Target host {} has {} free cores, VM needs {}",
                target.id,
                cap.available_cpu(),
                input.resources.cpu
            ),
        );
    }
    if cap.available_memory() < input.resources.memory {
        refuse(
            &mut plan,
            format!(
                "Target host {} has {} bytes of free memory, VM needs {}",
                target.id,
                cap.available_memory(),
                input.resources.memory
            ),
        );
    }

    match pick_disk(input, method) {
        Ok((disk, storage)) => {
            plan.target_disk_id = Some(disk);
            plan.target_storage = storage;
        }
        Err(e) => refuse(&mut plan, e),
    }

    plan_ips(input, &mut plan);

    if source.kind == VmHostKind::MarketplaceNode {
        plan.warnings.push(format!(
            "Host {} is a marketplace node: its operator stops earning a share of this VM once \
             it moves, because the share follows the host the VM runs on",
            source.id
        ));
    }
    if method == Some(MigrationMethod::CopyAndAdopt) {
        plan.warnings.push(
            "The VM is stopped for the whole copy: downtime is about the estimated time"
                .to_string(),
        );
    }
    plan
}

fn is_linux(distribution: &OsDistribution) -> bool {
    !matches!(
        distribution,
        OsDistribution::FreeBSD | OsDistribution::OpenBSD | OsDistribution::NetBSD
    )
}

fn pick_disk(
    input: &PlanInputs<'_>,
    method: Option<MigrationMethod>,
) -> Result<(u64, Option<String>), String> {
    let need = input.resources.disk_size;
    let disks = &input.target_capacity.disks;
    let target_id = input.target_host.id;
    let storage_for = |name: &str| match method {
        Some(MigrationMethod::Hypervisor) if name == input.source_disk.name => None,
        _ => Some(name.to_string()),
    };

    if let Some(id) = input.options.target_disk_id {
        let d = disks
            .iter()
            .find(|d| d.disk.id == id && d.disk.host_id == target_id)
            .ok_or_else(|| {
                format!("Target disk {id} is not an enabled disk on host {target_id}")
            })?;
        if !d.disk.enabled {
            return Err(format!("Target disk {id} is disabled"));
        }
        if d.available_capacity() < need {
            return Err(format!(
                "Target disk {id} has {} bytes free, VM needs {need}",
                d.available_capacity()
            ));
        }
        return Ok((d.disk.id, storage_for(&d.disk.name)));
    }

    if method == Some(MigrationMethod::Hypervisor)
        && let Some(d) = disks.iter().find(|d| {
            d.disk.name == input.source_disk.name
                && d.disk.enabled
                && d.available_capacity() >= need
        })
    {
        return Ok((d.disk.id, None));
    }

    disks
        .iter()
        .filter(|d| d.disk.enabled && d.available_capacity() >= need)
        .max_by_key(|d| d.available_capacity())
        .map(|d| (d.disk.id, Some(d.disk.name.clone())))
        .ok_or_else(|| {
            format!("No enabled disk on host {target_id} has {need} bytes free for the VM")
        })
}

fn plan_ips(input: &PlanInputs<'_>, plan: &mut MigrationPlan) {
    let target_region = input.target_host.region_id;
    match input.options.ip_policy {
        IpPolicy::Keep => {
            for r in input
                .assigned_ranges
                .iter()
                .filter(|r| r.region_id != target_region)
            {
                plan.refusals.push(format!(
                    "Range {} (region {}) is not routed in the target region {}; \
                     the VM would come up unreachable. Use ip_policy=reassign",
                    r.cidr, r.region_id, target_region
                ));
            }
        }
        IpPolicy::Reassign => {
            let v4_needed = input
                .assigned_ips
                .iter()
                .filter(|ip| ip.parse::<IpAddr>().is_ok_and(|a| a.is_ipv4()))
                .count() as u128;
            let v4_free: u128 = input
                .target_capacity
                .ranges
                .iter()
                .filter(|r| r.range.region_id == target_region && r.range.enabled)
                .filter(|r| r.is_ipv4())
                .map(|r| r.available_capacity())
                .sum();
            if v4_free < v4_needed {
                plan.refusals.push(format!(
                    "Target region {target_region} has {v4_free} free IPv4 addresses, VM needs {v4_needed}"
                ));
            }
            plan.ip_changes = input
                .assigned_ips
                .iter()
                .map(|ip| MigrationIpChange {
                    old_ip: Some(ip.clone()),
                    new_ip: None,
                    range_id: None,
                })
                .collect();
            plan.warnings.push(
                "Every address of this VM changes: DNS, reverse DNS and the owner are updated"
                    .to_string(),
            );
        }
    }
}

pub fn migration_method(source: &VmHostKind, target: &VmHostKind) -> Option<MigrationMethod> {
    match (source, target) {
        (VmHostKind::Proxmox, VmHostKind::Proxmox) | (VmHostKind::Dummy, VmHostKind::Dummy) => {
            Some(MigrationMethod::Hypervisor)
        }
        (VmHostKind::LibVirt | VmHostKind::MarketplaceNode, VmHostKind::Proxmox) => {
            Some(MigrationMethod::CopyAndAdopt)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::{DiskCapacity, GB, IPRangeCapacity, LoadFactors};
    use lnvps_db::CpuArch;

    fn host(id: u64, kind: VmHostKind, region: u64) -> VmHost {
        VmHost {
            id,
            kind,
            region_id: region,
            name: format!("node-{id}"),
            cpu: 16,
            cpu_arch: CpuArch::X86_64,
            memory: 64 * GB,
            enabled: true,
            load_cpu: 1.0,
            load_memory: 1.0,
            load_disk: 1.0,
            ..Default::default()
        }
    }

    fn disk(id: u64, host_id: u64, name: &str, size: u64) -> VmHostDisk {
        VmHostDisk {
            id,
            host_id,
            name: name.to_string(),
            size,
            enabled: true,
            ..Default::default()
        }
    }

    fn range(id: u64, region: u64, cidr: &str) -> IpRange {
        IpRange {
            id,
            cidr: cidr.to_string(),
            gateway: "10.0.0.1".to_string(),
            enabled: true,
            region_id: region,
            ..Default::default()
        }
    }

    fn capacity(
        host: &VmHost,
        disks: Vec<(VmHostDisk, u64)>,
        ranges: Vec<IpRange>,
    ) -> HostCapacity {
        HostCapacity {
            load_factor: LoadFactors {
                cpu: 1.0,
                memory: 1.0,
                disk: 1.0,
            },
            host: host.clone(),
            cpu: 0,
            memory: 0,
            disks: disks
                .into_iter()
                .map(|(disk, usage)| DiskCapacity {
                    load_factor: 1.0,
                    disk,
                    usage,
                })
                .collect(),
            ranges: ranges
                .into_iter()
                .map(|range| IPRangeCapacity { range, usage: 0 })
                .collect(),
        }
    }

    fn image(distribution: OsDistribution) -> VmOsImage {
        VmOsImage {
            id: 1,
            distribution,
            flavour: "Server".to_string(),
            version: "24.04".to_string(),
            enabled: true,
            release_date: chrono::Utc::now(),
            url: "https://example.com/x.img".to_string(),
            cpu_arch: CpuArch::X86_64,
            default_username: None,
            sha2: None,
            sha2_url: None,
            encrypted: false,
        }
    }

    struct Case {
        vm: Vm,
        resources: VmResources,
        image: VmOsImage,
        source: VmHost,
        source_disk: VmHostDisk,
        target: VmHost,
        capacity: HostCapacity,
        ranges: Vec<IpRange>,
        ips: Vec<String>,
        options: MigrationOptions,
    }

    impl Case {
        fn marketplace_to_proxmox() -> Self {
            let source = host(1, VmHostKind::MarketplaceNode, 1);
            let target = host(2, VmHostKind::Proxmox, 1);
            let capacity = capacity(
                &target,
                vec![(disk(20, 2, "local-zfs", 4000 * GB), 0)],
                vec![range(5, 1, "10.0.0.0/24")],
            );
            Self {
                vm: Vm {
                    id: 9,
                    host_id: 1,
                    disk_id: 10,
                    ..Default::default()
                },
                resources: VmResources {
                    cpu: 4,
                    memory: 8 * GB,
                    disk_size: 100 * GB,
                },
                image: image(OsDistribution::Ubuntu),
                source,
                source_disk: disk(10, 1, "default", 1000 * GB),
                target,
                capacity,
                ranges: vec![range(5, 1, "10.0.0.0/24")],
                ips: vec!["10.0.0.7".to_string()],
                options: MigrationOptions::default(),
            }
        }

        fn plan(&self) -> MigrationPlan {
            plan_vm_migration(&PlanInputs {
                vm: &self.vm,
                resources: &self.resources,
                image: &self.image,
                source_host: &self.source,
                source_disk: &self.source_disk,
                target_host: &self.target,
                target_capacity: &self.capacity,
                assigned_ranges: &self.ranges,
                assigned_ips: &self.ips,
                options: &self.options,
            })
        }
    }

    fn refused_with(plan: &MigrationPlan, needle: &str) -> bool {
        !plan.allowed() && plan.refusals.iter().any(|r| r.contains(needle))
    }

    #[test]
    fn marketplace_to_proxmox_with_capacity_is_a_copy_and_adopt() {
        let plan = Case::marketplace_to_proxmox().plan();
        assert!(plan.allowed(), "{:?}", plan.refusals);
        assert_eq!(plan.method, Some(MigrationMethod::CopyAndAdopt));
        assert_eq!(plan.target_disk_id, Some(20));
        assert_eq!(plan.target_storage.as_deref(), Some("local-zfs"));
        assert_eq!(plan.disk_bytes, 100 * GB);
        assert!(plan.estimated_seconds.unwrap_or(0) > 0);
        assert!(plan.keep_source);
        assert!(plan.ip_changes.is_empty());
        assert_eq!(plan.vm_id, 9);
        assert_eq!(plan.source_host_kind, "marketplace_node");
        assert_eq!(plan.target_host_kind, "proxmox");
    }

    #[test]
    fn plain_libvirt_to_proxmox_is_supported() {
        let mut c = Case::marketplace_to_proxmox();
        c.source.kind = VmHostKind::LibVirt;
        assert_eq!(c.plan().method, Some(MigrationMethod::CopyAndAdopt));
    }

    #[test]
    fn unsupported_host_kind_pairs_are_refused_by_name() {
        for (from, to) in [
            (VmHostKind::Proxmox, VmHostKind::LibVirt),
            (VmHostKind::Proxmox, VmHostKind::MarketplaceNode),
            (VmHostKind::LibVirt, VmHostKind::MarketplaceNode),
            (VmHostKind::MarketplaceNode, VmHostKind::LibVirt),
            (VmHostKind::MarketplaceNode, VmHostKind::MarketplaceNode),
        ] {
            let mut c = Case::marketplace_to_proxmox();
            c.source.kind = from.clone();
            c.target.kind = to.clone();
            let plan = c.plan();
            assert!(
                refused_with(&plan, &format!("{from} to {to}")),
                "{from} -> {to}: {:?}",
                plan.refusals
            );
        }
    }

    #[test]
    fn proxmox_to_proxmox_stays_a_hypervisor_migration() {
        let mut c = Case::marketplace_to_proxmox();
        c.source.kind = VmHostKind::Proxmox;
        c.source_disk.name = "local-zfs".to_string();
        let plan = c.plan();
        assert_eq!(plan.method, Some(MigrationMethod::Hypervisor));
        assert_eq!(plan.target_storage, None);
    }

    #[test]
    fn cpu_architecture_mismatch_is_refused() {
        let mut c = Case::marketplace_to_proxmox();
        c.target.cpu_arch = CpuArch::ARM64;
        assert!(refused_with(&c.plan(), "architecture"));
    }

    #[test]
    fn non_linux_images_are_refused_for_copy_and_adopt() {
        let mut c = Case::marketplace_to_proxmox();
        c.image = image(OsDistribution::FreeBSD);
        assert!(refused_with(&c.plan(), "Linux"));
    }

    #[test]
    fn same_host_and_disabled_targets_are_refused() {
        let mut c = Case::marketplace_to_proxmox();
        c.target.enabled = false;
        assert!(refused_with(&c.plan(), "disabled"));
        let mut c = Case::marketplace_to_proxmox();
        c.target = c.source.clone();
        assert!(refused_with(&c.plan(), "already on host"));
    }

    #[test]
    fn capacity_shortfalls_are_refused() {
        let mut c = Case::marketplace_to_proxmox();
        c.capacity.cpu = 16;
        assert!(refused_with(&c.plan(), "free cores"));
        let mut c = Case::marketplace_to_proxmox();
        c.capacity.memory = 64 * GB;
        assert!(refused_with(&c.plan(), "free memory"));
        let mut c = Case::marketplace_to_proxmox();
        c.capacity.disks[0].usage = 3950 * GB;
        assert!(refused_with(&c.plan(), "bytes free"));
    }

    #[test]
    fn keep_is_refused_when_the_ranges_are_not_at_the_destination() {
        let mut c = Case::marketplace_to_proxmox();
        c.target.region_id = 2;
        let plan = c.plan();
        assert!(refused_with(&plan, "10.0.0.0/24"), "{:?}", plan.refusals);
        assert!(plan.refusals.iter().any(|r| r.contains("reassign")));
    }

    #[test]
    fn keep_is_allowed_across_regions_when_the_range_is_routed_at_the_destination() {
        let mut c = Case::marketplace_to_proxmox();
        c.target.region_id = 2;
        c.ranges[0].region_id = 2;
        assert!(c.plan().allowed());
    }

    #[test]
    fn reassign_lists_every_address_that_changes() {
        let mut c = Case::marketplace_to_proxmox();
        c.target.region_id = 2;
        c.capacity.ranges[0].range.region_id = 2;
        c.options.ip_policy = IpPolicy::Reassign;
        let plan = c.plan();
        assert!(plan.allowed(), "{:?}", plan.refusals);
        assert_eq!(plan.ip_policy, IpPolicy::Reassign);
        assert_eq!(plan.ip_changes.len(), 1);
        assert_eq!(plan.ip_changes[0].old_ip.as_deref(), Some("10.0.0.7"));
    }

    #[test]
    fn reassign_is_refused_when_the_destination_has_no_free_ipv4() {
        let mut c = Case::marketplace_to_proxmox();
        c.target.region_id = 2;
        c.capacity.ranges.clear();
        c.options.ip_policy = IpPolicy::Reassign;
        assert!(refused_with(&c.plan(), "IPv4"));
    }

    #[test]
    fn target_disk_must_belong_to_the_target_host_and_fit() {
        let mut c = Case::marketplace_to_proxmox();
        c.capacity.disks.push(DiskCapacity {
            load_factor: 1.0,
            disk: disk(21, 2, "ssd", 4000 * GB),
            usage: 0,
        });
        c.options.target_disk_id = Some(21);
        let plan = c.plan();
        assert_eq!(plan.target_disk_id, Some(21));
        assert_eq!(plan.target_storage.as_deref(), Some("ssd"));

        c.options.target_disk_id = Some(99);
        assert!(refused_with(&c.plan(), "disk 99"));
    }

    #[test]
    fn hypervisor_migration_prefers_the_same_named_pool() {
        let mut c = Case::marketplace_to_proxmox();
        c.source.kind = VmHostKind::Proxmox;
        c.source_disk.name = "local-lvm".to_string();
        c.capacity.disks = vec![
            DiskCapacity {
                load_factor: 1.0,
                disk: disk(20, 2, "slow", 4000 * GB),
                usage: 0,
            },
            DiskCapacity {
                load_factor: 1.0,
                disk: disk(21, 2, "local-lvm", 1000 * GB),
                usage: 0,
            },
        ];
        let plan = c.plan();
        assert_eq!(plan.target_disk_id, Some(21));
        assert_eq!(plan.target_storage, None);
    }

    #[test]
    fn copy_and_adopt_takes_the_emptiest_pool() {
        let mut c = Case::marketplace_to_proxmox();
        c.capacity.disks = vec![
            DiskCapacity {
                load_factor: 1.0,
                disk: disk(20, 2, "nvme-a", 1000 * GB),
                usage: 900 * GB,
            },
            DiskCapacity {
                load_factor: 1.0,
                disk: disk(21, 2, "nvme-b", 1000 * GB),
                usage: 100 * GB,
            },
        ];
        let plan = c.plan();
        assert_eq!(plan.target_disk_id, Some(21));
        assert_eq!(plan.target_storage.as_deref(), Some("nvme-b"));
    }

    #[test]
    fn dummy_hosts_migrate_like_proxmox() {
        assert_eq!(
            migration_method(&VmHostKind::Dummy, &VmHostKind::Dummy),
            Some(MigrationMethod::Hypervisor)
        );
    }
}
