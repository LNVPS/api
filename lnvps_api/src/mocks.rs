#![allow(unused)]
use crate::dns::{BasicRecord, DnsServer, RecordType};
use crate::exchange::{ExchangeRateService, Ticker, TickerRate};
use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostInfo,
};
use crate::lightning::{AddInvoiceRequest, AddInvoiceResult, InvoiceUpdate, LightningNode};
use crate::router::{ArpEntry, Router};
use crate::status::{VmRunningState, VmState};
use anyhow::{anyhow, bail, ensure, Context};
use chrono::{DateTime, TimeDelta, Utc};
use fedimint_tonic_lnd::tonic::codegen::tokio_stream::Stream;
use lnvps_db::{
    async_trait, AccessPolicy, Company, DiskInterface, DiskType, IpRange, IpRangeAllocationMode,
    LNVPSNostrDb, LNVpsDb, NostrDomain, NostrDomainHandle, OsDistribution, User, UserSshKey, Vm,
    VmCostPlan, VmCostPlanIntervalType, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHost, VmHostDisk, VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
use std::collections::HashMap;
use std::ops::Add;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
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
    pub router: Arc<Mutex<HashMap<u64, lnvps_db::Router>>>,
    pub access_policy: Arc<Mutex<HashMap<u64, AccessPolicy>>>,
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
        }
    }
}

#[async_trait]
impl LNVPSNostrDb for MockDb {
    async fn get_handle(&self, handle_id: u64) -> anyhow::Result<NostrDomainHandle> {
        todo!()
    }

    async fn get_handle_by_name(
        &self,
        domain_id: u64,
        handle: &str,
    ) -> anyhow::Result<NostrDomainHandle> {
        todo!()
    }

    async fn insert_handle(&self, handle: &NostrDomainHandle) -> anyhow::Result<u64> {
        todo!()
    }

    async fn update_handle(&self, handle: &NostrDomainHandle) -> anyhow::Result<()> {
        todo!()
    }

    async fn delete_handle(&self, handle_id: u64) -> anyhow::Result<()> {
        todo!()
    }

    async fn list_handles(&self, domain_id: u64) -> anyhow::Result<Vec<NostrDomainHandle>> {
        todo!()
    }

    async fn get_domain(&self, id: u64) -> anyhow::Result<NostrDomain> {
        todo!()
    }

    async fn get_domain_by_name(&self, name: &str) -> anyhow::Result<NostrDomain> {
        todo!()
    }

    async fn list_domains(&self, owner_id: u64) -> anyhow::Result<Vec<NostrDomain>> {
        todo!()
    }

    async fn insert_domain(&self, domain: &NostrDomain) -> anyhow::Result<u64> {
        todo!()
    }

    async fn delete_domain(&self, domain_id: u64) -> anyhow::Result<()> {
        todo!()
    }
}

#[async_trait]
impl LNVpsDb for MockDb {
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
            p.is_paid = vm_payment.is_paid.clone();
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
            .max_by(|a, b| a.created.cmp(&b.created))
            .map(|v| v.clone()))
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

    async fn get_router(&self, router_id: u64) -> anyhow::Result<lnvps_db::Router> {
        let r = self.router.lock().await;
        Ok(r.get(&router_id).cloned().context("no router")?)
    }

    async fn get_access_policy(&self, access_policy_id: u64) -> anyhow::Result<AccessPolicy> {
        let p = self.access_policy.lock().await;
        Ok(p.get(&access_policy_id)
            .cloned()
            .context("no access policy")?)
    }

    async fn get_company(&self, company_id: u64) -> anyhow::Result<Company> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct MockRouter {
    arp: Arc<Mutex<HashMap<u64, ArpEntry>>>,
}

impl MockRouter {
    pub fn new() -> Self {
        static LAZY_ARP: LazyLock<Arc<Mutex<HashMap<u64, ArpEntry>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

        Self {
            arp: LAZY_ARP.clone(),
        }
    }
}
#[async_trait]
impl Router for MockRouter {
    async fn generate_mac(&self, ip: &str, comment: &str) -> anyhow::Result<Option<ArpEntry>> {
        Ok(None)
    }

    async fn list_arp_entry(&self) -> anyhow::Result<Vec<ArpEntry>> {
        let arp = self.arp.lock().await;
        Ok(arp.values().cloned().collect())
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> anyhow::Result<ArpEntry> {
        let mut arp = self.arp.lock().await;
        if arp.iter().any(|(k, v)| v.address == entry.address) {
            bail!("Address is already in use");
        }
        let max_id = *arp.keys().max().unwrap_or(&0);
        let e = ArpEntry {
            id: Some((max_id + 1).to_string()),
            ..entry.clone()
        };
        arp.insert(max_id + 1, e.clone());
        Ok(e)
    }

    async fn remove_arp_entry(&self, id: &str) -> anyhow::Result<()> {
        let mut arp = self.arp.lock().await;
        arp.remove(&id.parse::<u64>()?);
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> anyhow::Result<ArpEntry> {
        ensure!(entry.id.is_some(), "id is missing");
        let mut arp = self.arp.lock().await;
        if let Some(mut a) = arp.get_mut(&entry.id.as_ref().unwrap().parse::<u64>()?) {
            a.mac_address = entry.mac_address.clone();
            a.address = entry.address.clone();
            a.interface = entry.interface.clone();
            a.comment = entry.comment.clone();
        }
        Ok(entry.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockNode {
    pub invoices: Arc<Mutex<HashMap<String, MockInvoice>>>,
}

#[derive(Debug, Clone)]
pub struct MockInvoice {
    pub pr: String,
    pub amount: u64,
    pub expiry: DateTime<Utc>,
    pub is_paid: bool,
}

impl MockNode {
    pub fn new() -> Self {
        static LAZY_INVOICES: LazyLock<Arc<Mutex<HashMap<String, MockInvoice>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            invoices: LAZY_INVOICES.clone(),
        }
    }
}

#[async_trait]
impl LightningNode for MockNode {
    async fn add_invoice(&self, req: AddInvoiceRequest) -> anyhow::Result<AddInvoiceResult> {
        let mut invoices = self.invoices.lock().await;
        let id: [u8; 32] = rand::random();
        let hex_id = hex::encode(id);
        invoices.insert(
            hex_id.clone(),
            MockInvoice {
                pr: format!("lnrt1{}", hex_id),
                amount: req.amount,
                expiry: Utc::now().add(TimeDelta::seconds(req.expire.unwrap_or(3600) as i64)),
                is_paid: false,
            },
        );
        Ok(AddInvoiceResult {
            pr: format!("lnrt1{}", hex_id),
            payment_hash: hex_id.clone(),
            external_id: None,
        })
    }

    async fn subscribe_invoices(
        &self,
        from_payment_hash: Option<Vec<u8>>,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct MockVmHost {
    vms: Arc<Mutex<HashMap<u64, MockVm>>>,
}

#[derive(Debug, Clone)]
struct MockVm {
    pub state: VmRunningState,
}

impl MockVmHost {
    pub fn new() -> Self {
        static LAZY_VMS: LazyLock<Arc<Mutex<HashMap<u64, MockVm>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            vms: LAZY_VMS.clone(),
        }
    }
}

#[async_trait]
impl VmHostClient for MockVmHost {
    async fn get_info(&self) -> anyhow::Result<VmHostInfo> {
        todo!()
    }

    async fn download_os_image(&self, image: &VmOsImage) -> anyhow::Result<()> {
        Ok(())
    }

    async fn generate_mac(&self, vm: &Vm) -> anyhow::Result<String> {
        Ok(format!(
            "ff:ff:ff:{}:{}:{}",
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningState::Running;
        }
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningState::Stopped;
        }
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        if let Some(mut vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningState::Running;
        }
        Ok(())
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        let max_id = *vms.keys().max().unwrap_or(&0);
        vms.insert(
            max_id + 1,
            MockVm {
                state: VmRunningState::Stopped,
            },
        );
        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        let mut vms = self.vms.lock().await;
        vms.remove(&vm.id);
        Ok(())
    }

    async fn reinstall_vm(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        todo!()
    }

    async fn get_vm_state(&self, vm: &Vm) -> anyhow::Result<VmState> {
        let vms = self.vms.lock().await;
        if let Some(vm) = vms.get(&vm.id) {
            Ok(VmState {
                timestamp: Utc::now().timestamp() as u64,
                state: vm.state.clone(),
                cpu_usage: 69.0,
                mem_usage: 69.0,
                uptime: 100,
                net_in: 69,
                net_out: 69,
                disk_write: 69,
                disk_read: 69,
            })
        } else {
            bail!("No vm with id {}", vm.id)
        }
    }

    async fn configure_vm(&self, vm: &FullVmInfo) -> anyhow::Result<()> {
        Ok(())
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        todo!()
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> anyhow::Result<Vec<TimeSeriesData>> {
        Ok(vec![])
    }

    async fn connect_terminal(&self, vm: &Vm) -> anyhow::Result<TerminalStream> {
        todo!()
    }
}

pub struct MockDnsServer {
    pub zones: Arc<Mutex<HashMap<String, HashMap<String, MockDnsEntry>>>>,
}

pub struct MockDnsEntry {
    pub name: String,
    pub value: String,
    pub kind: String,
}

impl MockDnsServer {
    pub fn new() -> Self {
        static LAZY_ZONES: LazyLock<Arc<Mutex<HashMap<String, HashMap<String, MockDnsEntry>>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            zones: LAZY_ZONES.clone(),
        }
    }
}
#[async_trait]
impl DnsServer for MockDnsServer {
    async fn add_record(&self, zone_id: &str, record: &BasicRecord) -> anyhow::Result<BasicRecord> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };

        if table
            .values()
            .any(|v| v.name == record.name && v.kind == record.kind.to_string())
        {
            bail!("Duplicate record with name {}", record.name);
        }

        let rnd_id: [u8; 12] = rand::random();
        let id = hex::encode(rnd_id);
        table.insert(
            id.clone(),
            MockDnsEntry {
                name: record.name.to_string(),
                value: record.value.to_string(),
                kind: record.kind.to_string(),
            },
        );
        Ok(BasicRecord {
            name: match record.kind {
                RecordType::PTR => format!("{}.X.Y.Z.addr.in-arpa", record.name),
                _ => format!("{}.lnvps.mock", record.name),
            },
            value: record.value.clone(),
            id: Some(id),
            kind: record.kind.clone(),
        })
    }

    async fn delete_record(&self, zone_id: &str, record: &BasicRecord) -> anyhow::Result<()> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };
        ensure!(record.id.is_some(), "Id is missing");
        table.remove(record.id.as_ref().unwrap());
        Ok(())
    }

    async fn update_record(
        &self,
        zone_id: &str,
        record: &BasicRecord,
    ) -> anyhow::Result<BasicRecord> {
        let mut zones = self.zones.lock().await;
        let table = if let Some(t) = zones.get_mut(zone_id) {
            t
        } else {
            zones.insert(zone_id.to_string(), HashMap::new());
            zones.get_mut(zone_id).unwrap()
        };
        ensure!(record.id.is_some(), "Id is missing");
        if let Some(mut r) = table.get_mut(record.id.as_ref().unwrap()) {
            r.name = record.name.clone();
            r.value = record.value.clone();
            r.kind = record.kind.to_string();
        }
        Ok(record.clone())
    }
}

pub struct MockExchangeRate {
    pub rate: Arc<Mutex<HashMap<Ticker, f32>>>,
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
        Ok(r.iter().map(|(k, v)| TickerRate(k.clone(), *v)).collect())
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
