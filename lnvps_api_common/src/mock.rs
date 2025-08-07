use crate::{ExchangeRateService, Ticker, TickerRate};
use anyhow::{anyhow, bail, Context};
use chrono::{TimeDelta, Utc};
use lnvps_db::{
    async_trait, AccessPolicy, AdminDb, AdminRole, AdminRoleAssignment, AdminUserInfo, Company, DiskInterface, DiskType, IpRange, IpRangeAllocationMode,
    LNVpsDbBase, NostrDomain, NostrDomainHandle, OsDistribution, RegionStats, Router, User, UserSshKey, Vm,
    VmCostPlan, VmCostPlanIntervalType, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHistory, VmHost, VmHostDisk, VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment,
    VmTemplate,
};
use lnvps_db::nostr::LNVPSNostrDb;
use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MockDb {
    pub regions: Arc<Mutex<HashMap<u64, VmHostRegion>>>,
    pub hosts: Arc<Mutex<HashMap<u64, VmHost>>>,
    pub host_disks: Arc<Mutex<HashMap<u64, VmHostDisk>>>,
    pub users: Arc<Mutex<HashMap<u64, User>>>,
    pub user_ssh_keys: Arc<Mutex<HashMap<u64, UserSshKey>>>,
    pub cost_plans: Arc<Mutex<HashMap<u64, VmCostPlan>>>,
    pub os_images: Arc<Mutex<HashMap<u64, VmOsImage>>>,
    pub templates: Arc<Mutex<HashMap<u64, VmTemplate>>>,
    pub vms: Arc<Mutex<HashMap<u64, Vm>>>,
    pub ip_range: Arc<Mutex<HashMap<u64, IpRange>>>,
    pub ip_assignments: Arc<Mutex<HashMap<u64, VmIpAssignment>>>,
    pub custom_pricing: Arc<Mutex<HashMap<u64, VmCustomPricing>>>,
    pub custom_pricing_disk: Arc<Mutex<HashMap<u64, VmCustomPricingDisk>>>,
    pub custom_template: Arc<Mutex<HashMap<u64, VmCustomTemplate>>>,
    pub payments: Arc<Mutex<Vec<VmPayment>>>,
    pub router: Arc<Mutex<HashMap<u64, Router>>>,
    pub access_policy: Arc<Mutex<HashMap<u64, AccessPolicy>>>,
    pub companies: Arc<Mutex<HashMap<u64, Company>>>,
    pub vm_history: Arc<Mutex<HashMap<u64, VmHistory>>>,
}

impl MockDb {
    pub fn empty() -> MockDb {
        Self {
            ..Default::default()
        }
    }

    pub fn mock_cost_plan() -> VmCostPlan {
        VmCostPlan {
            id: 1,
            name: "mock".to_string(),
            created: Utc::now(),
            amount: 1.32,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: VmCostPlanIntervalType::Month,
        }
    }

    pub fn mock_template() -> VmTemplate {
        VmTemplate {
            id: 1,
            name: "mock".to_string(),
            enabled: true,
            created: Utc::now(),
            expires: None,
            cpu: 2,
            memory: crate::GB * 2,
            disk_size: crate::GB * 64,
            disk_type: DiskType::SSD,
            disk_interface: DiskInterface::PCIe,
            cost_plan_id: 1,
            region_id: 1,
        }
    }

    pub fn mock_vm() -> Vm {
        let template = Self::mock_template();
        Vm {
            id: 1,
            host_id: 1,
            user_id: 1,
            image_id: 1,
            template_id: Some(template.id),
            custom_template_id: None,
            ssh_key_id: 1,
            created: Utc::now(),
            expires: Default::default(),
            disk_id: 1,
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            deleted: false,
            ref_code: None,
        }
    }
}

impl Default for MockDb {
    fn default() -> Self {
        let mut regions = HashMap::new();
        regions.insert(
            1,
            VmHostRegion {
                id: 1,
                name: "Mock".to_string(),
                enabled: true,
                company_id: None,
            },
        );
        let mut ip_ranges = HashMap::new();
        ip_ranges.insert(
            1,
            IpRange {
                id: 1,
                cidr: "10.0.0.0/24".to_string(),
                gateway: "10.0.0.1/8".to_string(),
                enabled: true,
                region_id: 1,
                ..Default::default()
            },
        );
        ip_ranges.insert(
            2,
            IpRange {
                id: 2,
                cidr: "fd00::/64".to_string(),
                gateway: "fd00::1".to_string(),
                enabled: true,
                region_id: 1,
                allocation_mode: IpRangeAllocationMode::SlaacEui64,
                ..Default::default()
            },
        );
        let mut hosts = HashMap::new();
        hosts.insert(
            1,
            VmHost {
                id: 1,
                kind: VmHostKind::Proxmox,
                region_id: 1,
                name: "mock-host".to_string(),
                ip: "https://localhost".to_string(),
                cpu: 4,
                memory: 8 * crate::GB,
                enabled: true,
                api_token: "".to_string(),
                load_cpu: 1.5,
                load_memory: 2.0,
                load_disk: 3.0,
                vlan_id: Some(100),
            },
        );
        let mut host_disks = HashMap::new();
        host_disks.insert(
            1,
            VmHostDisk {
                id: 1,
                host_id: 1,
                name: "mock-disk".to_string(),
                size: crate::TB * 10,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                enabled: true,
            },
        );
        let mut cost_plans = HashMap::new();
        cost_plans.insert(1, Self::mock_cost_plan());
        let mut templates = HashMap::new();
        templates.insert(1, Self::mock_template());
        let mut os_images = HashMap::new();
        os_images.insert(
            1,
            VmOsImage {
                id: 1,
                distribution: OsDistribution::Debian,
                flavour: "server".to_string(),
                version: "12".to_string(),
                enabled: true,
                release_date: Utc::now(),
                url: "https://example.com/debian_12.img".to_string(),
                default_username: None,
            },
        );
        Self {
            regions: Arc::new(Mutex::new(regions)),
            ip_range: Arc::new(Mutex::new(ip_ranges)),
            hosts: Arc::new(Mutex::new(hosts)),
            host_disks: Arc::new(Mutex::new(host_disks)),
            cost_plans: Arc::new(Mutex::new(cost_plans)),
            templates: Arc::new(Mutex::new(templates)),
            os_images: Arc::new(Mutex::new(os_images)),
            users: Arc::new(Default::default()),
            vms: Arc::new(Default::default()),
            ip_assignments: Arc::new(Default::default()),
            custom_pricing: Arc::new(Default::default()),
            custom_pricing_disk: Arc::new(Default::default()),
            user_ssh_keys: Arc::new(Mutex::new(Default::default())),
            custom_template: Arc::new(Default::default()),
            payments: Arc::new(Default::default()),
            router: Arc::new(Default::default()),
            access_policy: Arc::new(Default::default()),
            companies: Arc::new(Default::default()),
            vm_history: Arc::new(Default::default()),
        }
    }
}

#[async_trait]
impl LNVpsDbBase for MockDb {
    async fn migrate(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn upsert_user(&self, pubkey: &[u8; 32]) -> anyhow::Result<u64> {
        let mut users = self.users.lock().await;
        if let Some(e) = users.iter().find(|(k, u)| u.pubkey == *pubkey) {
            Ok(*e.0)
        } else {
            let max = *users.keys().max().unwrap_or(&0);
            users.insert(
                max + 1,
                User {
                    id: max + 1,
                    pubkey: pubkey.to_vec(),
                    created: Utc::now(),
                    country_code: Some("USA".to_string()),
                    ..Default::default()
                },
            );
            Ok(max + 1)
        }
    }

    async fn get_user(&self, id: u64) -> anyhow::Result<User> {
        let users = self.users.lock().await;
        Ok(users.get(&id).ok_or(anyhow!("no user"))?.clone())
    }

    async fn update_user(&self, user: &User) -> anyhow::Result<()> {
        let mut users = self.users.lock().await;
        if let Some(u) = users.get_mut(&user.id) {
            u.email = user.email.clone();
            u.contact_email = user.contact_email;
            u.contact_nip17 = user.contact_nip17;
        }
        Ok(())
    }

    async fn delete_user(&self, id: u64) -> anyhow::Result<()> {
        let mut users = self.users.lock().await;
        users.remove(&id);
        Ok(())
    }

    async fn list_users(&self) -> anyhow::Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users.values().cloned().collect())
    }

    async fn list_users_paginated(&self, limit: u64, offset: u64) -> anyhow::Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users.values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn count_users(&self) -> anyhow::Result<u64> {
        let users = self.users.lock().await;
        Ok(users.len() as u64)
    }

    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> anyhow::Result<u64> {
        let mut ssh_keys = self.user_ssh_keys.lock().await;
        let max_keys = *ssh_keys.keys().max().unwrap_or(&0);
        ssh_keys.insert(
            max_keys + 1,
            UserSshKey {
                id: max_keys + 1,
                ..new_key.clone()
            },
        );
        Ok(max_keys + 1)
    }

    async fn get_user_ssh_key(&self, id: u64) -> anyhow::Result<UserSshKey> {
        let keys = self.user_ssh_keys.lock().await;
        Ok(keys.get(&id).ok_or(anyhow!("no key"))?.clone())
    }

    async fn delete_user_ssh_key(&self, id: u64) -> anyhow::Result<()> {
        let mut keys = self.user_ssh_keys.lock().await;
        keys.remove(&id);
        Ok(())
    }

    async fn list_user_ssh_key(&self, user_id: u64) -> anyhow::Result<Vec<UserSshKey>> {
        let keys = self.user_ssh_keys.lock().await;
        Ok(keys
            .values()
            .filter(|u| u.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_host_region(&self) -> anyhow::Result<Vec<VmHostRegion>> {
        let regions = self.regions.lock().await;
        Ok(regions.values().filter(|r| r.enabled).cloned().collect())
    }

    async fn get_host_region(&self, id: u64) -> anyhow::Result<VmHostRegion> {
        let regions = self.regions.lock().await;
        Ok(regions.get(&id).ok_or(anyhow!("no region"))?.clone())
    }

    async fn get_host_region_by_name(&self, name: &str) -> anyhow::Result<VmHostRegion> {
        let regions = self.regions.lock().await;
        Ok(regions
            .iter()
            .find(|(_, v)| v.name == name)
            .ok_or(anyhow!("no region"))?
            .1
            .clone())
    }

    async fn list_hosts(&self) -> anyhow::Result<Vec<VmHost>> {
        let hosts = self.hosts.lock().await;
        Ok(hosts.values().filter(|h| h.enabled).cloned().collect())
    }

    async fn list_hosts_paginated(&self, limit: u64, offset: u64) -> anyhow::Result<(Vec<VmHost>, u64)> {
        let hosts = self.hosts.lock().await;
        let filtered_hosts: Vec<VmHost> = hosts.values().filter(|h| h.enabled).cloned().collect();
        let total = filtered_hosts.len() as u64;
        let paginated: Vec<VmHost> = filtered_hosts
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((paginated, total))
    }

    async fn list_hosts_with_regions_paginated(&self, limit: u64, offset: u64) -> anyhow::Result<(Vec<(VmHost, VmHostRegion)>, u64)> {
        let hosts = self.hosts.lock().await;
        let regions = self.regions.lock().await;
        let filtered_hosts: Vec<VmHost> = hosts.values().filter(|h| h.enabled).cloned().collect();
        let total = filtered_hosts.len() as u64;
        
        let mut hosts_with_regions = Vec::new();
        for host in filtered_hosts.into_iter().skip(offset as usize).take(limit as usize) {
            if let Some(region) = regions.get(&host.region_id) {
                hosts_with_regions.push((host, region.clone()));
            }
        }
        Ok((hosts_with_regions, total))
    }

    async fn get_host(&self, id: u64) -> anyhow::Result<VmHost> {
        let hosts = self.hosts.lock().await;
        Ok(hosts.get(&id).ok_or(anyhow!("no host"))?.clone())
    }

    async fn update_host(&self, host: &VmHost) -> anyhow::Result<()> {
        let mut hosts = self.hosts.lock().await;
        if let Some(h) = hosts.get_mut(&host.id) {
            h.enabled = host.enabled;
            h.cpu = host.cpu;
            h.memory = host.memory;
        }
        Ok(())
    }

    async fn create_host(&self, host: &VmHost) -> anyhow::Result<u64> {
        let mut hosts = self.hosts.lock().await;
        let id = (hosts.len() as u64) + 1;
        let mut new_host = host.clone();
        new_host.id = id;
        hosts.insert(id, new_host);
        Ok(id)
    }

    async fn list_host_disks(&self, host_id: u64) -> anyhow::Result<Vec<VmHostDisk>> {
        let disks = self.host_disks.lock().await;
        Ok(disks.values().filter(|d| d.enabled).cloned().collect())
    }

    async fn get_host_disk(&self, disk_id: u64) -> anyhow::Result<VmHostDisk> {
        let disks = self.host_disks.lock().await;
        Ok(disks.get(&disk_id).ok_or(anyhow!("no disk"))?.clone())
    }

    async fn update_host_disk(&self, disk: &VmHostDisk) -> anyhow::Result<()> {
        let mut disks = self.host_disks.lock().await;
        if let Some(d) = disks.get_mut(&disk.id) {
            d.size = disk.size;
            d.kind = disk.kind;
            d.interface = disk.interface;
        }
        Ok(())
    }

    async fn get_os_image(&self, id: u64) -> anyhow::Result<VmOsImage> {
        let os_images = self.os_images.lock().await;
        Ok(os_images.get(&id).ok_or(anyhow!("no image"))?.clone())
    }

    async fn list_os_image(&self) -> anyhow::Result<Vec<VmOsImage>> {
        let os_images = self.os_images.lock().await;
        Ok(os_images.values().filter(|i| i.enabled).cloned().collect())
    }

    async fn get_ip_range(&self, id: u64) -> anyhow::Result<IpRange> {
        let ip_range = self.ip_range.lock().await;
        Ok(ip_range.get(&id).ok_or(anyhow!("no ip range"))?.clone())
    }

    async fn list_ip_range(&self) -> anyhow::Result<Vec<IpRange>> {
        let ip_range = self.ip_range.lock().await;
        Ok(ip_range.values().filter(|r| r.enabled).cloned().collect())
    }

    async fn list_ip_range_in_region(&self, region_id: u64) -> anyhow::Result<Vec<IpRange>> {
        let ip_range = self.ip_range.lock().await;
        Ok(ip_range
            .values()
            .filter(|r| r.enabled && r.region_id == region_id)
            .cloned()
            .collect())
    }

    async fn get_cost_plan(&self, id: u64) -> anyhow::Result<VmCostPlan> {
        let cost_plans = self.cost_plans.lock().await;
        Ok(cost_plans.get(&id).ok_or(anyhow!("no cost plan"))?.clone())
    }

    async fn list_cost_plans(&self) -> anyhow::Result<Vec<VmCostPlan>> {
        let cost_plans = self.cost_plans.lock().await;
        Ok(cost_plans.values().cloned().collect())
    }

    async fn insert_cost_plan(&self, cost_plan: &VmCostPlan) -> anyhow::Result<u64> {
        let mut cost_plans = self.cost_plans.lock().await;
        let max = *cost_plans.keys().max().unwrap_or(&0);
        let id = max + 1;
        let mut new_cost_plan = cost_plan.clone();
        new_cost_plan.id = id;
        cost_plans.insert(id, new_cost_plan);
        Ok(id)
    }

    async fn update_cost_plan(&self, cost_plan: &VmCostPlan) -> anyhow::Result<()> {
        let mut cost_plans = self.cost_plans.lock().await;
        if cost_plans.contains_key(&cost_plan.id) {
            cost_plans.insert(cost_plan.id, cost_plan.clone());
        }
        Ok(())
    }

    async fn delete_cost_plan(&self, id: u64) -> anyhow::Result<()> {
        let mut cost_plans = self.cost_plans.lock().await;
        cost_plans.remove(&id);
        Ok(())
    }

    async fn get_vm_template(&self, id: u64) -> anyhow::Result<VmTemplate> {
        let templates = self.templates.lock().await;
        Ok(templates.get(&id).ok_or(anyhow!("no template"))?.clone())
    }

    async fn list_vm_templates(&self) -> anyhow::Result<Vec<VmTemplate>> {
        let templates = self.templates.lock().await;
        Ok(templates
            .values()
            .filter(|t| t.enabled && t.expires.as_ref().map(|e| *e > Utc::now()).unwrap_or(true))
            .cloned()
            .collect())
    }

    async fn insert_vm_template(&self, template: &VmTemplate) -> anyhow::Result<u64> {
        let mut templates = self.templates.lock().await;
        let max_id = *templates.keys().max().unwrap_or(&0);
        templates.insert(
            max_id + 1,
            VmTemplate {
                id: max_id + 1,
                ..template.clone()
            },
        );
        Ok(max_id + 1)
    }

    async fn list_vms(&self) -> anyhow::Result<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms.values().filter(|v| !v.deleted).cloned().collect())
    }

    async fn list_vms_on_host(&self, host_id: u64) -> anyhow::Result<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.host_id == host_id)
            .cloned()
            .collect())
    }

    async fn count_active_vms_on_host(&self, host_id: u64) -> anyhow::Result<u64> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.host_id == host_id)
            .count() as u64)
    }

    async fn list_expired_vms(&self) -> anyhow::Result<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.expires >= Utc::now())
            .cloned()
            .collect())
    }

    async fn list_user_vms(&self, id: u64) -> anyhow::Result<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .values()
            .filter(|v| !v.deleted && v.user_id == id)
            .cloned()
            .collect())
    }

    async fn get_vm(&self, vm_id: u64) -> anyhow::Result<Vm> {
        let vms = self.vms.lock().await;
        Ok(vms.get(&vm_id).ok_or(anyhow!("no vm"))?.clone())
    }

    async fn insert_vm(&self, vm: &Vm) -> anyhow::Result<u64> {
        let mut vms = self.vms.lock().await;
        let max_id = *vms.keys().max().unwrap_or(&0);

        // lazy test FK
        self.get_host(vm.host_id).await?;
        self.get_user(vm.user_id).await?;
        self.get_os_image(vm.image_id).await?;
        if let Some(t) = vm.template_id {
            self.get_vm_template(t).await?;
        }
        if let Some(t) = vm.custom_template_id {
            self.get_custom_vm_template(t).await?;
        }
        self.get_user_ssh_key(vm.ssh_key_id).await?;
        self.get_host_disk(vm.disk_id).await?;

        vms.insert(
            max_id + 1,
            Vm {
                id: max_id + 1,
                ..vm.clone()
            },
        );
        Ok(max_id + 1)
    }

    async fn delete_vm(&self, vm_id: u64) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        vms.remove(&vm_id);
        Ok(())
    }

    async fn update_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(v) = vms.get_mut(&vm.id) {
            v.ssh_key_id = vm.ssh_key_id;
            v.mac_address = vm.mac_address.clone();
        }
        Ok(())
    }

    async fn insert_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> anyhow::Result<u64> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        let max = *ip_assignments.keys().max().unwrap_or(&0);
        ip_assignments.insert(
            max + 1,
            VmIpAssignment {
                id: max + 1,
                ..ip_assignment.clone()
            },
        );
        Ok(max + 1)
    }

    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> anyhow::Result<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        if let Some(i) = ip_assignments.get_mut(&ip_assignment.id) {
            i.arp_ref = ip_assignment.arp_ref.clone();
            i.dns_forward = ip_assignment.dns_forward.clone();
            i.dns_reverse = ip_assignment.dns_reverse.clone();
            i.dns_reverse_ref = ip_assignment.dns_reverse_ref.clone();
            i.dns_forward_ref = ip_assignment.dns_forward_ref.clone();
        }
        Ok(())
    }

    async fn list_vm_ip_assignments(&self, vm_id: u64) -> anyhow::Result<Vec<VmIpAssignment>> {
        let ip_assignments = self.ip_assignments.lock().await;
        Ok(ip_assignments
            .values()
            .filter(|a| a.vm_id == vm_id && !a.deleted)
            .cloned()
            .collect())
    }

    async fn list_vm_ip_assignments_in_range(
        &self,
        range_id: u64,
    ) -> anyhow::Result<Vec<VmIpAssignment>> {
        let ip_assignments = self.ip_assignments.lock().await;
        Ok(ip_assignments
            .values()
            .filter(|a| a.ip_range_id == range_id && !a.deleted)
            .cloned()
            .collect())
    }

    async fn delete_vm_ip_assignment(&self, vm_id: u64) -> anyhow::Result<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        for ip_assignment in ip_assignments.values_mut() {
            if ip_assignment.vm_id == vm_id {
                ip_assignment.deleted = true;
            }
        }
        Ok(())
    }

    async fn list_vm_payment(&self, vm_id: u64) -> anyhow::Result<Vec<VmPayment>> {
        let p = self.payments.lock().await;
        Ok(p.iter().filter(|p| p.vm_id == vm_id).cloned().collect())
    }

    async fn list_vm_payment_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> anyhow::Result<Vec<VmPayment>> {
        let p = self.payments.lock().await;
        let mut filtered: Vec<_> = p.iter().filter(|p| p.vm_id == vm_id).cloned().collect();
        filtered.sort_by(|a, b| b.created.cmp(&a.created));
        Ok(filtered.into_iter().skip(offset as usize).take(limit as usize).collect())
    }

    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> anyhow::Result<()> {
        let mut p = self.payments.lock().await;
        p.push(vm_payment.clone());
        Ok(())
    }

    async fn get_vm_payment(&self, id: &Vec<u8>) -> anyhow::Result<VmPayment> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .find(|p| p.id == *id)
            .context("no vm_payment")?
            .clone())
    }

    async fn get_vm_payment_by_ext_id(&self, id: &str) -> anyhow::Result<VmPayment> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .find(|p| p.external_id == Some(id.to_string()))
            .context("no vm_payment")?
            .clone())
    }

    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> anyhow::Result<()> {
        let mut p = self.payments.lock().await;
        if let Some(p) = p.iter_mut().find(|p| p.id == *vm_payment.id) {
            p.is_paid = vm_payment.is_paid;
        }
        Ok(())
    }

    async fn vm_payment_paid(&self, p: &VmPayment) -> anyhow::Result<()> {
        let mut v = self.vms.lock().await;
        self.update_vm_payment(p).await?;
        if let Some(v) = v.get_mut(&p.vm_id) {
            v.expires = v.expires.add(TimeDelta::seconds(p.time_value as i64));
        }
        Ok(())
    }

    async fn last_paid_invoice(&self) -> anyhow::Result<Option<VmPayment>> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .filter(|p| p.is_paid)
            .max_by(|a, b| a.created.cmp(&b.created)).cloned())
    }

    async fn get_payments_by_date_range(&self, start_date: chrono::DateTime<chrono::Utc>, end_date: chrono::DateTime<chrono::Utc>) -> anyhow::Result<Vec<VmPayment>> {
        let p = self.payments.lock().await;
        Ok(p.iter()
            .filter(|p| p.is_paid && p.created >= start_date && p.created < end_date)
            .cloned()
            .collect())
    }

    async fn list_custom_pricing(&self, region_id: u64) -> anyhow::Result<Vec<VmCustomPricing>> {
        let p = self.custom_pricing.lock().await;
        Ok(p.values().filter(|p| p.enabled).cloned().collect())
    }

    async fn get_custom_pricing(&self, id: u64) -> anyhow::Result<VmCustomPricing> {
        let p = self.custom_pricing.lock().await;
        Ok(p.get(&id).cloned().context("no custom pricing")?)
    }

    async fn get_custom_vm_template(&self, id: u64) -> anyhow::Result<VmCustomTemplate> {
        let t = self.custom_template.lock().await;
        Ok(t.get(&id).cloned().context("no custom template")?)
    }

    async fn insert_custom_vm_template(&self, template: &VmCustomTemplate) -> anyhow::Result<u64> {
        let mut t = self.custom_template.lock().await;
        let max_id = *t.keys().max().unwrap_or(&0);
        t.insert(
            max_id + 1,
            VmCustomTemplate {
                id: max_id + 1,
                ..template.clone()
            },
        );
        Ok(max_id + 1)
    }

    async fn list_custom_pricing_disk(
        &self,
        pricing_id: u64,
    ) -> anyhow::Result<Vec<VmCustomPricingDisk>> {
        let d = self.custom_pricing_disk.lock().await;
        Ok(d.values()
            .filter(|d| d.pricing_id == pricing_id)
            .cloned()
            .collect())
    }

    async fn get_router(&self, router_id: u64) -> anyhow::Result<Router> {
        let r = self.router.lock().await;
        Ok(r.get(&router_id).cloned().context("no router")?)
    }

    async fn list_routers(&self) -> anyhow::Result<Vec<Router>> {
        let routers = self.router.lock().await;
        Ok(routers.values().cloned().collect())
    }

    async fn get_vm_ip_assignment_by_ip(&self, ip: &str) -> anyhow::Result<VmIpAssignment> {
        let assignments = self.ip_assignments.lock().await;
        assignments
            .values()
            .find(|a| a.ip == ip)
            .cloned()
            .ok_or_else(|| anyhow!("IP assignment not found for {}", ip))
    }

    async fn get_access_policy(&self, access_policy_id: u64) -> anyhow::Result<AccessPolicy> {
        let p = self.access_policy.lock().await;
        Ok(p.get(&access_policy_id)
            .cloned()
            .context("no access policy")?)
    }

    async fn get_company(&self, company_id: u64) -> anyhow::Result<Company> {
        let companies = self.companies.lock().await;
        companies
            .get(&company_id)
            .cloned()
            .ok_or_else(|| anyhow!("Company with id {} not found", company_id))
    }

    async fn insert_vm_history(&self, history: &VmHistory) -> anyhow::Result<u64> {
        let mut vm_history_map = self.vm_history.lock().await;
        let id = (vm_history_map.len() + 1) as u64;
        let mut new_history = history.clone();
        new_history.id = id;
        vm_history_map.insert(id, new_history);
        Ok(id)
    }

    async fn list_vm_history(&self, vm_id: u64) -> anyhow::Result<Vec<VmHistory>> {
        let vm_history_map = self.vm_history.lock().await;
        let mut history: Vec<VmHistory> = vm_history_map
            .values()
            .filter(|h| h.vm_id == vm_id)
            .cloned()
            .collect();
        // Sort by timestamp descending (newest first)
        history.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(history)
    }

    async fn list_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> anyhow::Result<Vec<VmHistory>> {
        let all_history = self.list_vm_history(vm_id).await?;
        let start = offset as usize;
        let end = (start + limit as usize).min(all_history.len());
        if start >= all_history.len() {
            Ok(vec![])
        } else {
            Ok(all_history[start..end].to_vec())
        }
    }

    async fn get_vm_history(&self, id: u64) -> anyhow::Result<VmHistory> {
        let vm_history_map = self.vm_history.lock().await;
        vm_history_map
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("VM history not found: {}", id))
    }

}

pub struct MockExchangeRate {
    pub rate: Arc<Mutex<HashMap<Ticker, f32>>>,
}

impl Default for MockExchangeRate {
    fn default() -> Self {
        Self::new()
    }
}

impl MockExchangeRate {
    pub fn new() -> Self {
        Self {
            rate: Arc::new(Mutex::new(Default::default())),
        }
    }
}

#[async_trait]
impl ExchangeRateService for MockExchangeRate {
    async fn fetch_rates(&self) -> anyhow::Result<Vec<TickerRate>> {
        let r = self.rate.lock().await;
        Ok(r.iter().map(|(k, v)| TickerRate(*k, *v)).collect())
    }

    async fn set_rate(&self, ticker: Ticker, amount: f32) {
        let mut r = self.rate.lock().await;
        if let Some(v) = r.get_mut(&ticker) {
            *v += amount;
        } else {
            r.insert(ticker, amount);
        }
    }

    async fn get_rate(&self, ticker: Ticker) -> Option<f32> {
        let r = self.rate.lock().await;
        r.get(&ticker).cloned()
    }

    async fn list_rates(&self) -> anyhow::Result<Vec<TickerRate>> {
        self.fetch_rates().await
    }
}

// Admin trait implementation with stub methods
#[async_trait]
impl AdminDb for MockDb {
    async fn get_user_permissions(&self, _user_id: u64) -> anyhow::Result<std::collections::HashSet<(u16, u16)>> {
        Ok(std::collections::HashSet::new())
    }
    
    async fn get_user_roles(&self, _user_id: u64) -> anyhow::Result<Vec<u64>> {
        Ok(vec![])
    }
    
    async fn is_admin_user(&self, _user_id: u64) -> anyhow::Result<bool> {
        Ok(false)
    }
    
    async fn assign_user_role(&self, _user_id: u64, _role_id: u64, _assigned_by: u64) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn revoke_user_role(&self, _user_id: u64, _role_id: u64) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn create_role(&self, _name: &str, _description: Option<&str>) -> anyhow::Result<u64> {
        Ok(1)
    }
    
    async fn get_role(&self, _role_id: u64) -> anyhow::Result<AdminRole> {
        bail!("Mock implementation: get_role not implemented")
    }
    
    async fn get_role_by_name(&self, _name: &str) -> anyhow::Result<AdminRole> {
        bail!("Mock implementation: get_role_by_name not implemented")
    }
    
    async fn list_roles(&self) -> anyhow::Result<Vec<AdminRole>> {
        Ok(vec![])
    }
    
    async fn update_role(&self, _role: &AdminRole) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn delete_role(&self, _role_id: u64) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn add_role_permission(&self, _role_id: u64, _resource: u16, _action: u16) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn remove_role_permission(&self, _role_id: u64, _resource: u16, _action: u16) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn get_role_permissions(&self, _role_id: u64) -> anyhow::Result<Vec<(u16, u16)>> {
        Ok(vec![])
    }
    
    async fn get_user_role_assignments(&self, _user_id: u64) -> anyhow::Result<Vec<AdminRoleAssignment>> {
        Ok(vec![])
    }
    
    async fn count_role_users(&self, _role_id: u64) -> anyhow::Result<u64> {
        Ok(0)
    }
    
    async fn admin_list_users(&self, limit: u64, offset: u64, _search_pubkey: Option<&str>) -> anyhow::Result<(Vec<AdminUserInfo>, u64)> {
        let users = self.users.lock().await;
        let total = users.len() as u64;
        let paginated_users: Vec<AdminUserInfo> = users.values()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|u| AdminUserInfo {
                id: u.id,
                pubkey: u.pubkey.clone(),
                created: u.created,
                email: u.email.clone(),
                contact_nip17: u.contact_nip17,
                contact_email: u.contact_email,
                country_code: u.country_code.clone(),
                billing_name: u.billing_name.clone(),
                billing_address_1: u.billing_address_1.clone(),
                billing_address_2: u.billing_address_2.clone(),
                billing_city: u.billing_city.clone(),
                billing_state: u.billing_state.clone(),
                billing_postcode: u.billing_postcode.clone(),
                billing_tax_id: u.billing_tax_id.clone(),
                vm_count: 0,
                is_admin: false,
            })
            .collect();
        Ok((paginated_users, total))
    }
    
    async fn admin_list_regions(&self, limit: u64, offset: u64) -> anyhow::Result<(Vec<VmHostRegion>, u64)> {
        let regions = self.regions.lock().await;
        let total = regions.len() as u64;
        let paginated_regions: Vec<VmHostRegion> = regions.values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok((paginated_regions, total))
    }
    
    // Add stub implementations for all remaining AdminDb methods
    async fn admin_create_region(&self, _name: &str, _company_id: Option<u64>) -> anyhow::Result<u64> { Ok(1) }
    async fn admin_update_region(&self, _region: &VmHostRegion) -> anyhow::Result<()> { Ok(()) }
    async fn admin_delete_region(&self, _region_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn admin_count_region_hosts(&self, _region_id: u64) -> anyhow::Result<u64> { Ok(0) }
    async fn admin_get_region_stats(&self, _region_id: u64) -> anyhow::Result<RegionStats> { 
        bail!("Mock implementation: admin_get_region_stats not implemented")
    }
    async fn admin_list_vm_os_images(&self, _limit: u64, _offset: u64) -> anyhow::Result<(Vec<VmOsImage>, u64)> { Ok((vec![], 0)) }
    async fn admin_get_vm_os_image(&self, _image_id: u64) -> anyhow::Result<VmOsImage> { 
        bail!("Mock implementation: admin_get_vm_os_image not implemented")
    }
    async fn admin_create_vm_os_image(&self, _image: &VmOsImage) -> anyhow::Result<u64> { Ok(1) }
    async fn admin_update_vm_os_image(&self, _image: &VmOsImage) -> anyhow::Result<()> { Ok(()) }
    async fn admin_delete_vm_os_image(&self, _image_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn list_vm_templates_paginated(&self, limit: i64, offset: i64) -> anyhow::Result<(Vec<VmTemplate>, i64)> {
        let templates = self.templates.lock().await;
        let total = templates.len() as i64;
        let paginated: Vec<VmTemplate> = templates.values()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok((paginated, total))
    }
    async fn update_vm_template(&self, _template: &VmTemplate) -> anyhow::Result<()> { Ok(()) }
    async fn delete_vm_template(&self, _template_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn check_vm_template_usage(&self, _template_id: u64) -> anyhow::Result<i64> { Ok(0) }
    async fn admin_list_hosts_with_regions_paginated(&self, limit: u64, offset: u64) -> anyhow::Result<(Vec<(VmHost, VmHostRegion)>, u64)> {
        self.list_hosts_with_regions_paginated(limit, offset).await
    }
    async fn admin_list_companies(&self, _limit: u64, _offset: u64) -> anyhow::Result<(Vec<Company>, u64)> { Ok((vec![], 0)) }
    async fn admin_get_company(&self, company_id: u64) -> anyhow::Result<Company> { self.get_company(company_id).await }
    async fn admin_create_company(&self, _company: &Company) -> anyhow::Result<u64> { Ok(1) }
    async fn admin_update_company(&self, _company: &Company) -> anyhow::Result<()> { Ok(()) }
    async fn admin_delete_company(&self, _company_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn admin_count_company_regions(&self, _company_id: u64) -> anyhow::Result<u64> { Ok(0) }
    async fn admin_list_ip_ranges(&self, _limit: u64, _offset: u64, _region_id: Option<u64>) -> anyhow::Result<(Vec<IpRange>, u64)> { Ok((vec![], 0)) }
    async fn admin_get_ip_range(&self, ip_range_id: u64) -> anyhow::Result<IpRange> { self.get_ip_range(ip_range_id).await }
    async fn admin_create_ip_range(&self, _ip_range: &IpRange) -> anyhow::Result<u64> { Ok(1) }
    async fn admin_update_ip_range(&self, _ip_range: &IpRange) -> anyhow::Result<()> { Ok(()) }
    async fn admin_delete_ip_range(&self, _ip_range_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn admin_count_ip_range_assignments(&self, _ip_range_id: u64) -> anyhow::Result<u64> { Ok(0) }
    async fn admin_list_access_policies(&self) -> anyhow::Result<Vec<AccessPolicy>> { Ok(vec![]) }
    async fn admin_list_access_policies_paginated(&self, _limit: u64, _offset: u64) -> anyhow::Result<(Vec<AccessPolicy>, u64)> { Ok((vec![], 0)) }
    async fn admin_get_access_policy(&self, access_policy_id: u64) -> anyhow::Result<AccessPolicy> { self.get_access_policy(access_policy_id).await }
    async fn admin_create_access_policy(&self, _access_policy: &AccessPolicy) -> anyhow::Result<u64> { Ok(1) }
    async fn admin_update_access_policy(&self, _access_policy: &AccessPolicy) -> anyhow::Result<()> { Ok(()) }
    async fn admin_delete_access_policy(&self, _access_policy_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn admin_count_access_policy_ip_ranges(&self, _access_policy_id: u64) -> anyhow::Result<u64> { Ok(0) }
    async fn admin_list_routers(&self) -> anyhow::Result<Vec<Router>> { self.list_routers().await }
    async fn admin_list_routers_paginated(&self, _limit: u64, _offset: u64) -> anyhow::Result<(Vec<Router>, u64)> { Ok((vec![], 0)) }
    async fn admin_get_router(&self, router_id: u64) -> anyhow::Result<Router> { self.get_router(router_id).await }
    async fn admin_create_router(&self, _router: &Router) -> anyhow::Result<u64> { Ok(1) }
    async fn admin_update_router(&self, _router: &Router) -> anyhow::Result<()> { Ok(()) }
    async fn admin_delete_router(&self, _router_id: u64) -> anyhow::Result<()> { Ok(()) }
    async fn admin_count_router_access_policies(&self, _router_id: u64) -> anyhow::Result<u64> { Ok(0) }
    
    async fn insert_custom_pricing(&self, pricing: &VmCustomPricing) -> anyhow::Result<u64> {
        let mut pricing_map = self.custom_pricing.lock().await;
        let max_id = pricing_map.keys().max().unwrap_or(&0) + 1;
        let mut new_pricing = pricing.clone();
        new_pricing.id = max_id;
        pricing_map.insert(max_id, new_pricing);
        Ok(max_id)
    }

    async fn update_custom_pricing(&self, pricing: &VmCustomPricing) -> anyhow::Result<()> {
        let mut pricing_map = self.custom_pricing.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = pricing_map.entry(pricing.id) {
            e.insert(pricing.clone());
            Ok(())
        } else {
            bail!("Custom pricing not found: {}", pricing.id)
        }
    }

    async fn delete_custom_pricing(&self, id: u64) -> anyhow::Result<()> {
        let mut pricing_map = self.custom_pricing.lock().await;
        if pricing_map.remove(&id).is_some() {
            Ok(())
        } else {
            bail!("Custom pricing not found: {}", id)
        }
    }

    async fn insert_custom_pricing_disk(&self, disk: &VmCustomPricingDisk) -> anyhow::Result<u64> {
        let mut disk_map = self.custom_pricing_disk.lock().await;
        let max_id = disk_map.keys().max().unwrap_or(&0) + 1;
        let mut new_disk = disk.clone();
        new_disk.id = max_id;
        disk_map.insert(max_id, new_disk);
        Ok(max_id)
    }

    async fn delete_custom_pricing_disks(&self, pricing_id: u64) -> anyhow::Result<()> {
        let mut disk_map = self.custom_pricing_disk.lock().await;
        disk_map.retain(|_, disk| disk.pricing_id != pricing_id);
        Ok(())
    }

    async fn count_custom_templates_by_pricing(&self, pricing_id: u64) -> anyhow::Result<u64> {
        let template_map = self.custom_template.lock().await;
        let count = template_map
            .values()
            .filter(|template| template.pricing_id == pricing_id)
            .count();
        Ok(count as u64)
    }

    async fn list_custom_templates_by_pricing_paginated(
        &self,
        pricing_id: u64,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<VmCustomTemplate>, u64)> {
        let template_map = self.custom_template.lock().await;
        let filtered_templates: Vec<VmCustomTemplate> = template_map
            .values()
            .filter(|template| template.pricing_id == pricing_id)
            .cloned()
            .collect();
        let total = filtered_templates.len() as u64;
        let paginated: Vec<VmCustomTemplate> = filtered_templates
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((paginated, total))
    }

    async fn insert_custom_template(&self, template: &VmCustomTemplate) -> anyhow::Result<u64> {
        let mut template_map = self.custom_template.lock().await;
        let max_id = template_map.keys().max().unwrap_or(&0) + 1;
        let mut new_template = template.clone();
        new_template.id = max_id;
        template_map.insert(max_id, new_template);
        Ok(max_id)
    }

    async fn get_custom_template(&self, id: u64) -> anyhow::Result<VmCustomTemplate> {
        let template_map = self.custom_template.lock().await;
        template_map
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("Custom template not found: {}", id))
    }

    async fn update_custom_template(&self, template: &VmCustomTemplate) -> anyhow::Result<()> {
        let mut template_map = self.custom_template.lock().await;
        if let std::collections::hash_map::Entry::Occupied(mut e) = template_map.entry(template.id) {
            e.insert(template.clone());
            Ok(())
        } else {
            bail!("Custom template not found: {}", template.id)
        }
    }

    async fn delete_custom_template(&self, id: u64) -> anyhow::Result<()> {
        let mut template_map = self.custom_template.lock().await;
        if template_map.remove(&id).is_some() {
            Ok(())
        } else {
            bail!("Custom template not found: {}", id)
        }
    }

    async fn count_vms_by_custom_template(&self, template_id: u64) -> anyhow::Result<u64> {
        let vm_map = self.vms.lock().await;
        let count = vm_map
            .values()
            .filter(|vm| vm.custom_template_id == Some(template_id))
            .count();
        Ok(count as u64)
    }

    async fn admin_list_vms_filtered(
        &self,
        limit: u64,
        offset: u64,
        user_id: Option<u64>,
        host_id: Option<u64>,
        pubkey: Option<&str>,
        region_id: Option<u64>,
        include_deleted: Option<bool>,
    ) -> anyhow::Result<(Vec<Vm>, u64)> {
        let vms = self.vms.lock().await;
        let hosts = self.hosts.lock().await;
        
        // Resolve user_id from pubkey if provided
        let resolved_user_id = if let Some(pk) = pubkey {
            let pubkey_bytes = hex::decode(pk)
                .map_err(|_| anyhow!("Invalid pubkey format"))?;
            
            match self.get_user_by_pubkey(&pubkey_bytes).await {
                Ok(user) => Some(user.id),
                Err(_) => return Ok((vec![], 0)), // No user found, return empty
            }
        } else {
            user_id
        };

        // Filter VMs based on criteria
        let filtered_vms: Vec<Vm> = vms
            .values()
            .filter(|vm| {
                // Filter by user_id
                if let Some(uid) = resolved_user_id {
                    if vm.user_id != uid {
                        return false;
                    }
                }

                // Filter by host_id
                if let Some(hid) = host_id {
                    if vm.host_id != hid {
                        return false;
                    }
                }

                // Filter by region_id
                if let Some(rid) = region_id {
                    if let Some(host) = hosts.get(&vm.host_id) {
                        if host.region_id != rid {
                            return false;
                        }
                    } else {
                        return false; // VM without valid host when region filter applied
                    }
                }

                // Filter by deleted status
                match include_deleted {
                    Some(false) | None => {
                        // Exclude deleted VMs (default behavior)
                        if vm.deleted {
                            return false;
                        }
                    }
                    Some(true) => {
                        // Include both deleted and non-deleted VMs
                    }
                }

                true
            })
            .cloned()
            .collect();

        let total = filtered_vms.len() as u64;
        
        // Apply pagination
        let paginated: Vec<Vm> = filtered_vms
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        Ok((paginated, total))
    }

    async fn get_user_by_pubkey(&self, pubkey: &[u8]) -> anyhow::Result<User> {
        let users = self.users.lock().await;
        users
            .values()
            .find(|user| user.pubkey == pubkey)
            .cloned()
            .ok_or_else(|| anyhow!("User not found with provided pubkey"))
    }
}

// Nostr trait implementation with stub methods
#[async_trait]
impl LNVPSNostrDb for MockDb {
    async fn get_handle(&self, _handle_id: u64) -> anyhow::Result<NostrDomainHandle> {
        bail!("Mock implementation: get_handle not implemented")
    }
    
    async fn get_handle_by_name(&self, _domain_id: u64, _handle: &str) -> anyhow::Result<NostrDomainHandle> {
        bail!("Mock implementation: get_handle_by_name not implemented")
    }
    
    async fn insert_handle(&self, _handle: &NostrDomainHandle) -> anyhow::Result<u64> {
        Ok(1)
    }
    
    async fn update_handle(&self, _handle: &NostrDomainHandle) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn delete_handle(&self, _handle_id: u64) -> anyhow::Result<()> {
        Ok(())
    }
    
    async fn list_handles(&self, _domain_id: u64) -> anyhow::Result<Vec<NostrDomainHandle>> {
        Ok(vec![])
    }
    
    async fn get_domain(&self, _id: u64) -> anyhow::Result<NostrDomain> {
        bail!("Mock implementation: get_domain not implemented")
    }
    
    async fn get_domain_by_name(&self, _name: &str) -> anyhow::Result<NostrDomain> {
        bail!("Mock implementation: get_domain_by_name not implemented")
    }
    
    async fn list_domains(&self, _owner_id: u64) -> anyhow::Result<Vec<NostrDomain>> {
        Ok(vec![])
    }
    
    async fn insert_domain(&self, _domain: &NostrDomain) -> anyhow::Result<u64> {
        Ok(1)
    }
    
    async fn delete_domain(&self, _domain_id: u64) -> anyhow::Result<()> {
        Ok(())
    }
}
