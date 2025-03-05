use crate::dns::{BasicRecord, DnsServer};
use crate::exchange::{ExchangeRateService, Ticker};
use crate::host::{get_host_client, FullVmInfo};
use crate::lightning::{AddInvoiceRequest, LightningNode};
use crate::provisioner::{
    HostCapacityService, NetworkProvisioner, ProvisionerMethod,
};
use crate::router::{ArpEntry, Router};
use crate::settings::{NetworkAccessPolicy, NetworkPolicy, ProvisionerConfig, Settings};
use anyhow::{bail, ensure, Context, Result};
use chrono::{Days, Months, Utc};
use lnvps_db::{LNVpsDb, Vm, VmCostPlanIntervalType, VmIpAssignment, VmPayment};
use log::{info, warn};
use nostr::util::hex;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;

/// Main provisioner class for LNVPS
///
/// Does all the hard work and logic for creating / expiring VM's
pub struct LNVpsProvisioner {
    read_only: bool,

    db: Arc<dyn LNVpsDb>,
    node: Arc<dyn LightningNode>,
    rates: Arc<dyn ExchangeRateService>,

    router: Option<Arc<dyn Router>>,
    dns: Option<Arc<dyn DnsServer>>,

    network_policy: NetworkPolicy,
    provisioner_config: ProvisionerConfig,
}

impl LNVpsProvisioner {
    pub fn new(
        settings: Settings,
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        rates: Arc<dyn ExchangeRateService>,
    ) -> Self {
        Self {
            db,
            node,
            rates,
            router: settings.get_router().expect("router config"),
            dns: settings.get_dns().expect("dns config"),
            network_policy: settings.network_policy,
            provisioner_config: settings.provisioner,
            read_only: settings.read_only,
        }
    }

    /// Create or Update access policy for a given ip assignment, does not save to database!
    pub async fn update_access_policy(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        // apply network policy
        if let NetworkAccessPolicy::StaticArp { interface } = &self.network_policy.access {
            if let Some(r) = self.router.as_ref() {
                let vm = self.db.get_vm(assignment.vm_id).await?;
                let entry = ArpEntry::new(&vm, assignment, Some(interface.clone()))?;
                let arp = if let Some(_id) = &assignment.arp_ref {
                    r.update_arp_entry(&entry).await?
                } else {
                    r.add_arp_entry(&entry).await?
                };
                ensure!(arp.id.is_some(), "ARP id was empty");
                assignment.arp_ref = arp.id;
            } else {
                bail!("No router found to apply static arp entry!")
            }
        }
        Ok(())
    }

    /// Remove an access policy for a given ip assignment, does not save to database!
    pub async fn remove_access_policy(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        // Delete access policy
        if let NetworkAccessPolicy::StaticArp { .. } = &self.network_policy.access {
            if let Some(r) = self.router.as_ref() {
                let id = if let Some(id) = &assignment.arp_ref {
                    Some(id.clone())
                } else {
                    warn!("ARP REF not found, using arp list");

                    let ent = r.list_arp_entry().await?;
                    if let Some(ent) = ent.iter().find(|e| e.address == assignment.ip) {
                        ent.id.clone()
                    } else {
                        warn!("ARP entry not found, skipping");
                        None
                    }
                };

                if let Some(id) = id {
                    if let Err(e) = r.remove_arp_entry(&id).await {
                        warn!("Failed to remove arp entry, skipping: {}", e);
                    }
                }
                assignment.arp_ref = None;
            }
        }
        Ok(())
    }

    /// Delete DNS on the dns server, does not save to database!
    pub async fn remove_ip_dns(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        // Delete forward/reverse dns
        if let Some(dns) = &self.dns {
            if let Some(_r) = &assignment.dns_reverse_ref {
                let rev = BasicRecord::reverse(assignment)?;
                if let Err(e) = dns.delete_record(&rev).await {
                    warn!("Failed to delete reverse record: {}", e);
                }
                assignment.dns_reverse_ref = None;
                assignment.dns_reverse = None;
            }
            if let Some(_r) = &assignment.dns_forward_ref {
                let rev = BasicRecord::forward(assignment)?;
                if let Err(e) = dns.delete_record(&rev).await {
                    warn!("Failed to delete forward record: {}", e);
                }
                assignment.dns_forward_ref = None;
                assignment.dns_forward = None;
            }
        }
        Ok(())
    }

    /// Update DNS on the dns server, does not save to database!
    pub async fn update_forward_ip_dns(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        if let Some(dns) = &self.dns {
            let fwd = BasicRecord::forward(assignment)?;
            let ret_fwd = if fwd.id.is_some() {
                dns.update_record(&fwd).await?
            } else {
                dns.add_record(&fwd).await?
            };
            assignment.dns_forward = Some(ret_fwd.name);
            assignment.dns_forward_ref = Some(ret_fwd.id.context("Record id is missing")?);
        }
        Ok(())
    }

    /// Update DNS on the dns server, does not save to database!
    pub async fn update_reverse_ip_dns(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        if let Some(dns) = &self.dns {
            let ret_rev = if assignment.dns_reverse_ref.is_some() {
                dns.update_record(&BasicRecord::reverse(assignment)?)
                    .await?
            } else {
                dns.add_record(&BasicRecord::reverse_to_fwd(assignment)?)
                    .await?
            };
            assignment.dns_reverse = Some(ret_rev.value);
            assignment.dns_reverse_ref = Some(ret_rev.id.context("Record id is missing")?);
        }
        Ok(())
    }

    /// Delete all ip assignments for a given vm
    pub async fn delete_ip_assignments(&self, vm_id: u64) -> Result<()> {
        let ips = self.db.list_vm_ip_assignments(vm_id).await?;
        for mut ip in ips {
            // remove access policy
            self.remove_access_policy(&mut ip).await?;
            // remove dns
            self.remove_ip_dns(&mut ip).await?;
            // save arp/dns changes
            self.db.update_vm_ip_assignment(&ip).await?;
        }
        // mark as deleted
        self.db.delete_vm_ip_assignment(vm_id).await?;

        Ok(())
    }

    async fn save_ip_assignment(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        // apply access policy
        self.update_access_policy(assignment).await?;

        // Add DNS records
        self.update_forward_ip_dns(assignment).await?;
        self.update_reverse_ip_dns(assignment).await?;

        // save to db
        self.db.insert_vm_ip_assignment(assignment).await?;
        Ok(())
    }

    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        let vm = self.db.get_vm(vm_id).await?;
        let existing_ips = self.db.list_vm_ip_assignments(vm_id).await?;
        if !existing_ips.is_empty() {
            return Ok(existing_ips);
        }

        // Use random network provisioner
        let network = NetworkProvisioner::new(ProvisionerMethod::Random, self.db.clone());

        let template = self.db.get_vm_template(vm.template_id).await?;
        let ip = network.pick_ip_for_region(template.region_id).await?;
        let mut assignment = VmIpAssignment {
            id: 0,
            vm_id,
            ip_range_id: ip.range_id,
            ip: ip.ip.to_string(),
            deleted: false,
            arp_ref: None,
            dns_forward: None,
            dns_forward_ref: None,
            dns_reverse: None,
            dns_reverse_ref: None,
        };

        self.save_ip_assignment(&mut assignment).await?;
        Ok(vec![assignment])
    }

    /// Do any necessary initialization
    pub async fn init(&self) -> Result<()> {
        let hosts = self.db.list_hosts().await?;
        let images = self.db.list_os_image().await?;
        for host in hosts {
            let client = get_host_client(&host, &self.provisioner_config)?;
            for image in &images {
                if let Err(e) = client.download_os_image(image).await {
                    warn!(
                        "Error downloading image {} on {}: {}",
                        image.url, host.name, e
                    );
                }
            }
        }
        Ok(())
    }

    /// Provision a new VM for a user on the database
    ///
    /// Note:
    /// 1. Does not create a VM on the host machine
    /// 2. Does not assign any IP resources
    pub async fn provision(
        &self,
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
        ref_code: Option<String>,
    ) -> Result<Vm> {
        let user = self.db.get_user(user_id).await?;
        let template = self.db.get_vm_template(template_id).await?;
        let image = self.db.get_os_image(image_id).await?;
        let ssh_key = self.db.get_user_ssh_key(ssh_key_id).await?;

        // TODO: cache capacity somewhere
        let cap = HostCapacityService::new(self.db.clone());
        let host = cap.get_host_for_template(&template).await?;

        let pick_disk = if let Some(hd) = host.disks.first() {
            hd
        } else {
            bail!("No host disk found")
        };

        let client = get_host_client(&host.host, &self.provisioner_config)?;
        let mut new_vm = Vm {
            id: 0,
            host_id: host.host.id,
            user_id: user.id,
            image_id: image.id,
            template_id: template.id,
            ssh_key_id: ssh_key.id,
            created: Utc::now(),
            expires: Utc::now(),
            disk_id: pick_disk.disk.id,
            mac_address: "NOT FILLED YET".to_string(),
            deleted: false,
            ref_code,
        };

        // ask host client to generate the mac address
        new_vm.mac_address = client.generate_mac(&new_vm).await?;

        let new_id = self.db.insert_vm(&new_vm).await?;
        new_vm.id = new_id;
        Ok(new_vm)
    }

    /// Create a renewal payment
    pub async fn renew(&self, vm_id: u64) -> Result<VmPayment> {
        let vm = self.db.get_vm(vm_id).await?;
        let template = self.db.get_vm_template(vm.template_id).await?;
        let cost_plan = self.db.get_cost_plan(template.cost_plan_id).await?;

        // Reuse existing payment until expired
        let payments = self.db.list_vm_payment(vm.id).await?;
        if let Some(px) = payments
            .into_iter()
            .find(|p| p.expires > Utc::now() && !p.is_paid)
        {
            return Ok(px);
        }

        // push the expiration forward by cost plan interval amount
        let new_expire = match cost_plan.interval_type {
            VmCostPlanIntervalType::Day => vm.expires.add(Days::new(cost_plan.interval_amount)),
            VmCostPlanIntervalType::Month => vm
                .expires
                .add(Months::new(cost_plan.interval_amount as u32)),
            VmCostPlanIntervalType::Year => vm
                .expires
                .add(Months::new((12 * cost_plan.interval_amount) as u32)),
        };

        const BTC_SATS: f64 = 100_000_000.0;
        const INVOICE_EXPIRE: u32 = 3600;

        let ticker = Ticker::btc_rate(cost_plan.currency.as_str())?;
        let rate = if let Some(r) = self.rates.get_rate(ticker).await {
            r
        } else {
            bail!("No exchange rate found")
        };

        let cost_btc = cost_plan.amount as f32 / rate;
        let cost_msat = (cost_btc as f64 * BTC_SATS) as u64 * 1000;
        info!("Creating invoice for {vm_id} for {} sats", cost_msat / 1000);
        let invoice = self
            .node
            .add_invoice(AddInvoiceRequest {
                memo: Some(format!("VM renewal {vm_id} to {new_expire}")),
                amount: cost_msat,
                expire: Some(INVOICE_EXPIRE),
            })
            .await?;
        let vm_payment = VmPayment {
            id: hex::decode(invoice.payment_hash)?,
            vm_id,
            created: Utc::now(),
            expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE as u64)),
            amount: cost_msat,
            invoice: invoice.pr,
            time_value: (new_expire - vm.expires).num_seconds() as u64,
            is_paid: false,
            rate,
            ..Default::default()
        };
        self.db.insert_vm_payment(&vm_payment).await?;

        Ok(vm_payment)
    }

    /// Create a vm on the host as configured by the template
    pub async fn spawn_vm(&self, vm_id: u64) -> Result<()> {
        if self.read_only {
            bail!("Cant spawn VM's in read-only mode")
        }
        // setup network by allocating some IP space
        self.allocate_ips(vm_id).await?;

        // load full info
        let info = FullVmInfo::load(vm_id, self.db.clone()).await?;

        // load host client
        let host = self.db.get_host(info.vm.host_id).await?;
        let client = get_host_client(&host, &self.provisioner_config)?;
        client.create_vm(&info).await?;

        Ok(())
    }

    /// Delete a VM and its associated resources
    pub async fn delete_vm(&self, vm_id: u64) -> Result<()> {
        // host client currently doesn't support delete (proxmox)
        // VM should already be stopped by [Worker]

        self.delete_ip_assignments(vm_id).await?;
        self.db.delete_vm(vm_id).await?;

        Ok(())
    }

    /// Stop a running VM
    pub async fn stop_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        client.stop_vm(&vm).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::DefaultRateCache;
    use crate::mocks::{MockDb, MockDnsServer, MockNode, MockRouter};
    use crate::settings::{DnsServerConfig, LightningConfig, QemuConfig, RouterConfig};
    use lnvps_db::{DiskInterface, DiskType, User, UserSshKey, VmTemplate};

    const ROUTER_BRIDGE: &str = "bridge1";
    const GB: u64 = 1024 * 1024 * 1024;
    const TB: u64 = GB * 1024;

    fn settings() -> Settings {
        Settings {
            listen: None,
            db: "".to_string(),
            lightning: LightningConfig::LND {
                url: "".to_string(),
                cert: Default::default(),
                macaroon: Default::default(),
            },
            read_only: false,
            provisioner: ProvisionerConfig::Proxmox {
                qemu: QemuConfig {
                    machine: "q35".to_string(),
                    os_type: "l26".to_string(),
                    bridge: "vmbr1".to_string(),
                    cpu: "kvm64".to_string(),
                    vlan: None,
                    kvm: false,
                },
                ssh: None,
                mac_prefix: Some("ff:ff:ff".to_string()),
            },
            network_policy: NetworkPolicy {
                access: NetworkAccessPolicy::StaticArp {
                    interface: ROUTER_BRIDGE.to_string(),
                },
                ip6_slaac: None,
            },
            delete_after: 0,
            smtp: None,
            router: Some(RouterConfig::Mikrotik {
                url: "https://localhost".to_string(),
                username: "admin".to_string(),
                password: "password123".to_string(),
            }),
            dns: Some(DnsServerConfig::Cloudflare {
                token: "abc".to_string(),
                forward_zone_id: "123".to_string(),
                reverse_zone_id: "456".to_string(),
            }),
            nostr: None,
        }
    }

    async fn add_user(db: &Arc<MockDb>) -> Result<(User, UserSshKey)> {
        let pubkey: [u8; 32] = random();

        let user_id = db.upsert_user(&pubkey).await?;
        let mut new_key = UserSshKey {
            id: 0,
            name: "test-key".to_string(),
            user_id,
            created: Default::default(),
            key_data: "ssh-rsa AAA==".to_string(),
        };
        let ssh_key = db.insert_user_ssh_key(&new_key).await?;
        new_key.id = ssh_key;
        Ok((db.get_user(user_id).await?, new_key))
    }

    #[tokio::test]
    async fn basic() -> Result<()> {
        let settings = settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(DefaultRateCache::default());
        let router = MockRouter::new(settings.network_policy.clone());
        let dns = MockDnsServer::new();
        let provisioner = LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone());

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, Some("mock-ref".to_string()))
            .await?;
        println!("{:?}", vm);
        provisioner.spawn_vm(vm.id).await?;

        // check resources
        let arp = router.list_arp_entry().await?;
        assert_eq!(1, arp.len());
        let arp = arp.first().unwrap();
        assert_eq!(&vm.mac_address, &arp.mac_address);
        assert_eq!(vm.ref_code, Some("mock-ref".to_string()));
        assert_eq!(ROUTER_BRIDGE, arp.interface.as_ref().unwrap());
        println!("{:?}", arp);

        let ips = db.list_vm_ip_assignments(vm.id).await?;
        assert_eq!(1, ips.len());
        let ip = ips.first().unwrap();
        println!("{:?}", ip);
        assert_eq!(ip.ip, arp.address);
        assert_eq!(ip.ip_range_id, 1);
        assert_eq!(ip.vm_id, vm.id);
        assert!(ip.dns_forward.is_some());
        assert!(ip.dns_reverse.is_some());
        assert!(ip.dns_reverse_ref.is_some());
        assert!(ip.dns_forward_ref.is_some());
        assert_eq!(ip.dns_reverse, ip.dns_forward);

        // assert IP address is not CIDR
        assert!(IpAddr::from_str(&ip.ip).is_ok());
        assert!(!ip.ip.ends_with("/8"));
        assert!(!ip.ip.ends_with("/24"));

        // now expire
        provisioner.delete_vm(vm.id).await?;

        // test arp/dns is removed
        let arp = router.list_arp_entry().await?;
        assert!(arp.is_empty());
        assert_eq!(dns.forward.lock().await.len(), 0);
        assert_eq!(dns.reverse.lock().await.len(), 0);

        // ensure IPS are deleted
        let ips = db.ip_assignments.lock().await;
        let ip = ips.values().next().unwrap();
        assert!(ip.arp_ref.is_none());
        assert!(ip.dns_forward.is_none());
        assert!(ip.dns_reverse.is_none());
        assert!(ip.dns_reverse_ref.is_none());
        assert!(ip.dns_forward_ref.is_none());
        assert!(ip.deleted);
        println!("{:?}", ip);

        Ok(())
    }

    #[tokio::test]
    async fn test_no_capacity() -> Result<()> {
        let settings = settings();
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(DefaultRateCache::default());
        let prov = LNVpsProvisioner::new(settings.clone(), db.clone(), node.clone(), rates.clone());

        let large_template = VmTemplate {
            id: 0,
            name: "mock-large-template".to_string(),
            enabled: true,
            created: Default::default(),
            expires: None,
            cpu: 64,
            memory: 512 * GB,
            disk_size: 20 * TB,
            disk_type: DiskType::SSD,
            disk_interface: DiskInterface::PCIe,
            cost_plan_id: 1,
            region_id: 1,
        };
        let id = db.insert_vm_template(&large_template).await?;

        let (user, ssh_key) = add_user(&db).await?;

        let prov = prov.provision(user.id, id, 1, ssh_key.id, None).await;
        assert!(prov.is_err());
        if let Err(e) = prov {
            println!("{}", e);
            assert!(e.to_string().to_lowercase().contains("no available host"))
        }
        Ok(())
    }
}
