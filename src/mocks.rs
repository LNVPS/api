use crate::router::{ArpEntry, Router};
use crate::settings::NetworkPolicy;
use anyhow::anyhow;
use chrono::Utc;
use lnvps_db::{
    async_trait, IpRange, LNVpsDb, User, UserSshKey, Vm, VmCostPlan, VmHost, VmHostDisk,
    VmHostKind, VmHostRegion, VmIpAssignment, VmOsImage, VmPayment, VmTemplate,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct MockDb {
    pub regions: Arc<Mutex<HashMap<u64, VmHostRegion>>>,
    pub hosts: Arc<Mutex<HashMap<u64, VmHost>>>,
    pub users: Arc<Mutex<HashMap<u64, User>>>,
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
                cidr: "10.0.0.0/8".to_string(),
                gateway: "10.0.0.1".to_string(),
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
        Self {
            regions: Arc::new(Mutex::new(regions)),
            ip_range: Arc::new(Mutex::new(ip_ranges)),
            hosts: Arc::new(Mutex::new(hosts)),
            users: Arc::new(Default::default()),
            vms: Arc::new(Default::default()),
            ip_assignments: Arc::new(Default::default()),
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
        let mut users = self.users.lock().await;
        Ok(users.get(&id).ok_or(anyhow!("no user"))?.clone())
    }

    async fn update_user(&self, user: &User) -> anyhow::Result<()> {
        let mut users = self.users.lock().await;
        if let Some(u) = users.get_mut(&user.id) {
            u.email = user.email.clone();
            u.contact_email = user.contact_email.clone();
            u.contact_nip17 = user.contact_nip17.clone();
            u.contact_nip4 = user.contact_nip4.clone();
        }
        Ok(())
    }

    async fn delete_user(&self, id: u64) -> anyhow::Result<()> {
        let mut users = self.users.lock().await;
        users.remove(&id);
        Ok(())
    }

    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> anyhow::Result<u64> {
        todo!()
    }

    async fn get_user_ssh_key(&self, id: u64) -> anyhow::Result<UserSshKey> {
        todo!()
    }

    async fn delete_user_ssh_key(&self, id: u64) -> anyhow::Result<()> {
        todo!()
    }

    async fn list_user_ssh_key(&self, user_id: u64) -> anyhow::Result<Vec<UserSshKey>> {
        todo!()
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
        todo!()
    }

    async fn get_os_image(&self, id: u64) -> anyhow::Result<VmOsImage> {
        todo!()
    }

    async fn list_os_image(&self) -> anyhow::Result<Vec<VmOsImage>> {
        todo!()
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
        todo!()
    }

    async fn get_vm_template(&self, id: u64) -> anyhow::Result<VmTemplate> {
        todo!()
    }

    async fn list_vm_templates(&self) -> anyhow::Result<Vec<VmTemplate>> {
        todo!()
    }

    async fn list_vms(&self) -> anyhow::Result<Vec<Vm>> {
        todo!()
    }

    async fn list_expired_vms(&self) -> anyhow::Result<Vec<Vm>> {
        todo!()
    }

    async fn list_user_vms(&self, id: u64) -> anyhow::Result<Vec<Vm>> {
        todo!()
    }

    async fn get_vm(&self, vm_id: u64) -> anyhow::Result<Vm> {
        todo!()
    }

    async fn insert_vm(&self, vm: &Vm) -> anyhow::Result<u64> {
        todo!()
    }

    async fn delete_vm(&self, vm_id: u64) -> anyhow::Result<()> {
        todo!()
    }

    async fn update_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        todo!()
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
            },
        );
        Ok(max + 1)
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

struct MockRouter {
    pub policy: NetworkPolicy,
}

#[async_trait]
impl Router for MockRouter {
    async fn list_arp_entry(&self) -> anyhow::Result<Vec<ArpEntry>> {
        todo!()
    }

    async fn add_arp_entry(
        &self,
        ip: IpAddr,
        mac: &str,
        interface: &str,
        comment: Option<&str>,
    ) -> anyhow::Result<()> {
        todo!()
    }

    async fn remove_arp_entry(&self, id: &str) -> anyhow::Result<()> {
        todo!()
    }
}
