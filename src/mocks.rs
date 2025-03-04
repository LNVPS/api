#![allow(unused)]
use crate::dns::{BasicRecord, DnsServer, RecordType};
use crate::host::{FullVmInfo, VmHostClient};
use crate::lightning::{AddInvoiceRequest, AddInvoiceResult, InvoiceUpdate, LightningNode};
use crate::router::{ArpEntry, Router};
use crate::settings::NetworkPolicy;
use crate::status::{VmRunningState, VmState};
use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use fedimint_tonic_lnd::tonic::codegen::tokio_stream::Stream;
use lnvps_db::{
    async_trait, DiskInterface, DiskType, IpRange, LNVpsDb, OsDistribution, User, UserSshKey, Vm,
    VmCostPlan, VmCostPlanIntervalType, VmHost, VmHostDisk, VmHostKind, VmHostRegion,
    VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
use std::collections::HashMap;
use std::net::IpAddr;
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
}

impl MockDb {
    pub fn empty() -> MockDb {
        Self {
            ..Default::default()
        }
    }
}

impl Default for MockDb {
    fn default() -> Self {
        const GB: u64 = 1024 * 1024 * 1024;
        const TB: u64 = GB * 1024;

        let mut regions = HashMap::new();
        regions.insert(
            1,
            VmHostRegion {
                id: 1,
                name: "Mock".to_string(),
                enabled: true,
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
                memory: 8192,
                enabled: true,
                api_token: "".to_string(),
            },
        );
        let mut host_disks = HashMap::new();
        host_disks.insert(
            1,
            VmHostDisk {
                id: 1,
                host_id: 1,
                name: "mock-disk".to_string(),
                size: TB * 10,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                enabled: true,
            },
        );
        let mut cost_plans = HashMap::new();
        cost_plans.insert(
            1,
            VmCostPlan {
                id: 1,
                name: "mock".to_string(),
                created: Utc::now(),
                amount: 1,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: VmCostPlanIntervalType::Month,
            },
        );
        let mut templates = HashMap::new();
        templates.insert(
            1,
            VmTemplate {
                id: 1,
                name: "mock".to_string(),
                enabled: true,
                created: Utc::now(),
                expires: None,
                cpu: 2,
                memory: GB * 2,
                disk_size: GB * 64,
                disk_type: DiskType::SSD,
                disk_interface: DiskInterface::PCIe,
                cost_plan_id: 1,
                region_id: 1,
            },
        );
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
            user_ssh_keys: Arc::new(Mutex::new(Default::default())),
        }
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
                    email: None,
                    contact_nip4: false,
                    contact_nip17: false,
                    contact_email: false,
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
            u.contact_nip4 = user.contact_nip4;
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
                name: new_key.name.clone(),
                user_id: new_key.user_id,
                created: Utc::now(),
                key_data: new_key.key_data.clone(),
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

    async fn get_host_region(&self, id: u64) -> anyhow::Result<VmHostRegion> {
        let regions = self.regions.lock().await;
        Ok(regions.get(&id).ok_or(anyhow!("no region"))?.clone())
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

    async fn list_vms(&self) -> anyhow::Result<Vec<Vm>> {
        let vms = self.vms.lock().await;
        Ok(vms.values().filter(|v| !v.deleted).cloned().collect())
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
        self.get_vm_template(vm.template_id).await?;
        self.get_user_ssh_key(vm.ssh_key_id).await?;
        self.get_host_disk(vm.disk_id).await?;

        vms.insert(
            max_id + 1,
            Vm {
                id: max_id + 1,
                host_id: vm.host_id,
                user_id: vm.user_id,
                image_id: vm.image_id,
                template_id: vm.template_id,
                ssh_key_id: vm.ssh_key_id,
                created: Utc::now(),
                expires: Utc::now(),
                disk_id: vm.disk_id,
                mac_address: vm.mac_address.clone(),
                deleted: false,
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
                vm_id: ip_assignment.vm_id,
                ip_range_id: ip_assignment.ip_range_id,
                ip: ip_assignment.ip.clone(),
                deleted: false,
                arp_ref: ip_assignment.arp_ref.clone(),
                dns_forward: ip_assignment.dns_forward.clone(),
                dns_forward_ref: ip_assignment.dns_forward_ref.clone(),
                dns_reverse: ip_assignment.dns_reverse.clone(),
                dns_reverse_ref: ip_assignment.dns_reverse_ref.clone(),
            },
        );
        Ok(max + 1)
    }

    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> anyhow::Result<()> {
        let mut ip_assignments = self.ip_assignments.lock().await;
        if let Some(i) = ip_assignments.get_mut(&ip_assignment.vm_id) {
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
        todo!()
    }

    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> anyhow::Result<()> {
        todo!()
    }

    async fn get_vm_payment(&self, id: &Vec<u8>) -> anyhow::Result<VmPayment> {
        todo!()
    }

    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> anyhow::Result<()> {
        todo!()
    }

    async fn vm_payment_paid(&self, id: &VmPayment) -> anyhow::Result<()> {
        todo!()
    }

    async fn last_paid_invoice(&self) -> anyhow::Result<Option<VmPayment>> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct MockRouter {
    pub policy: NetworkPolicy,
    arp: Arc<Mutex<HashMap<u64, ArpEntry>>>,
}

impl MockRouter {
    pub fn new(policy: NetworkPolicy) -> Self {
        static LAZY_ARP: LazyLock<Arc<Mutex<HashMap<u64, ArpEntry>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

        Self {
            policy,
            arp: LAZY_ARP.clone(),
        }
    }
}
#[async_trait]
impl Router for MockRouter {
    async fn list_arp_entry(&self) -> anyhow::Result<Vec<ArpEntry>> {
        let arp = self.arp.lock().await;
        Ok(arp.values().cloned().collect())
    }

    async fn add_arp_entry(
        &self,
        ip: IpAddr,
        mac: &str,
        interface: &str,
        comment: Option<&str>,
    ) -> anyhow::Result<ArpEntry> {
        let mut arp = self.arp.lock().await;
        if arp.iter().any(|(k, v)| v.address == ip.to_string()) {
            bail!("Address is already in use");
        }
        let max_id = *arp.keys().max().unwrap_or(&0);
        let e = ArpEntry {
            id: (max_id + 1).to_string(),
            address: ip.to_string(),
            mac_address: mac.to_string(),
            interface: Some(interface.to_string()),
            comment: comment.map(|s| s.to_string()),
        };
        arp.insert(max_id + 1, e.clone());
        Ok(e)
    }

    async fn remove_arp_entry(&self, id: &str) -> anyhow::Result<()> {
        let mut arp = self.arp.lock().await;
        arp.remove(&id.parse::<u64>()?);
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MockNode {
    invoices: Arc<Mutex<HashMap<String, MockInvoice>>>,
}

#[derive(Debug, Clone)]
struct MockInvoice {
    pr: String,
    expiry: DateTime<Utc>,
    settle_index: u64,
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
        todo!()
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

    async fn configure_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct MockDnsServer {
    pub forward: Arc<Mutex<HashMap<String, MockDnsEntry>>>,
    pub reverse: Arc<Mutex<HashMap<String, MockDnsEntry>>>,
}

pub struct MockDnsEntry {
    pub name: String,
    pub value: String,
    pub kind: String,
}

impl MockDnsServer {
    pub fn new() -> Self {
        static LAZY_FWD: LazyLock<Arc<Mutex<HashMap<String, MockDnsEntry>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        static LAZY_REV: LazyLock<Arc<Mutex<HashMap<String, MockDnsEntry>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            forward: LAZY_FWD.clone(),
            reverse: LAZY_REV.clone(),
        }
    }
}
#[async_trait]
impl DnsServer for MockDnsServer {
    async fn add_ptr_record(&self, key: &str, value: &str) -> anyhow::Result<BasicRecord> {
        let mut rev = self.reverse.lock().await;

        if rev.values().any(|v| v.name == key) {
            bail!("Duplicate record with name {}", key);
        }

        let rnd_id: [u8; 12] = rand::random();
        let id = hex::encode(rnd_id);
        rev.insert(
            id.clone(),
            MockDnsEntry {
                name: key.to_string(),
                value: value.to_string(),
                kind: "PTR".to_string(),
            },
        );
        Ok(BasicRecord {
            name: format!("{}.X.Y.Z.in-addr.arpa", key),
            value: value.to_string(),
            id: Some(id),
            kind: RecordType::PTR,
        })
    }

    async fn delete_ptr_record(&self, key: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn add_a_record(&self, name: &str, ip: IpAddr) -> anyhow::Result<BasicRecord> {
        let mut rev = self.forward.lock().await;

        if rev.values().any(|v| v.name == name) {
            bail!("Duplicate record with name {}", name);
        }

        let fqdn = format!("{}.lnvps.mock", name);
        let rnd_id: [u8; 12] = rand::random();
        let id = hex::encode(rnd_id);
        rev.insert(
            id.clone(),
            MockDnsEntry {
                name: fqdn.clone(),
                value: ip.to_string(),
                kind: "A".to_string(),
            },
        );
        Ok(BasicRecord {
            name: fqdn,
            value: ip.to_string(),
            id: Some(id),
            kind: RecordType::A,
        })
    }

    async fn delete_a_record(&self, name: &str) -> anyhow::Result<()> {
        todo!()
    }
}
