use crate::dns::{BasicRecord, DnsServer};
use crate::exchange::{Currency, CurrencyAmount, ExchangeRateService};
use crate::fiat::FiatPaymentService;
use crate::host::{get_host_client, FullVmInfo};
use crate::lightning::{AddInvoiceRequest, LightningNode};
use crate::provisioner::{
    CostResult, HostCapacityService, NetworkProvisioner, PricingEngine, ProvisionerMethod,
};
use crate::router::{ArpEntry, Router};
use crate::settings::{NetworkAccessPolicy, NetworkPolicy, ProvisionerConfig, Settings};
use anyhow::{bail, ensure, Context, Result};
use chrono::Utc;
use isocountry::CountryCode;
use lnvps_db::{LNVpsDb, PaymentMethod, User, Vm, VmCustomTemplate, VmIpAssignment, VmPayment};
use log::{info, warn};
use nostr::util::hex;
use std::collections::HashMap;
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
    tax_rates: HashMap<CountryCode, f32>,

    router: Option<Arc<dyn Router>>,
    dns: Option<Arc<dyn DnsServer>>,
    revolut: Option<Arc<dyn FiatPaymentService>>,

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
            revolut: settings.get_revolut().expect("revolut config"),
            tax_rates: settings.tax_rate,
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

        let host = self.db.get_host(vm.host_id).await?;
        let ip = network.pick_ip_for_region(host.region_id).await?;
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

    /// Get database handle
    pub fn get_db(&self) -> Arc<dyn LNVpsDb> {
        self.db.clone()
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
        let host = cap
            .get_host_for_template(template.region_id, &template)
            .await?;

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
            template_id: Some(template.id),
            custom_template_id: None,
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

    /// Provision a new VM for a user on the database
    ///
    /// Note:
    /// 1. Does not create a VM on the host machine
    /// 2. Does not assign any IP resources
    pub async fn provision_custom(
        &self,
        user_id: u64,
        template: VmCustomTemplate,
        image_id: u64,
        ssh_key_id: u64,
        ref_code: Option<String>,
    ) -> Result<Vm> {
        let user = self.db.get_user(user_id).await?;
        let pricing = self.db.get_vm_template(template.pricing_id).await?;
        let image = self.db.get_os_image(image_id).await?;
        let ssh_key = self.db.get_user_ssh_key(ssh_key_id).await?;

        // TODO: cache capacity somewhere
        let cap = HostCapacityService::new(self.db.clone());
        let host = cap
            .get_host_for_template(pricing.region_id, &template)
            .await?;

        let pick_disk = if let Some(hd) = host.disks.first() {
            hd
        } else {
            bail!("No host disk found")
        };

        // insert custom templates
        let template_id = self.db.insert_custom_vm_template(&template).await?;

        let client = get_host_client(&host.host, &self.provisioner_config)?;
        let mut new_vm = Vm {
            id: 0,
            host_id: host.host.id,
            user_id: user.id,
            image_id: image.id,
            template_id: None,
            custom_template_id: Some(template_id),
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
    pub async fn renew(&self, vm_id: u64, method: PaymentMethod) -> Result<VmPayment> {
        let pe = PricingEngine::new(self.db.clone(), self.rates.clone(), self.tax_rates.clone());

        let price = pe.get_vm_cost(vm_id, method).await?;
        match price {
            CostResult::Existing(p) => Ok(p),
            CostResult::New {
                amount,
                currency,
                time_value,
                new_expiry,
                rate,
                tax,
            } => {
                let desc = format!("VM renewal {vm_id} to {new_expiry}");
                let vm_payment = match method {
                    PaymentMethod::Lightning => {
                        ensure!(
                            currency == Currency::BTC,
                            "Cannot create invoices for non-BTC currency"
                        );
                        const INVOICE_EXPIRE: u64 = 600;
                        let total_amount = amount + tax;
                        info!(
                            "Creating invoice for {vm_id} for {} sats",
                            total_amount / 1000
                        );
                        let invoice = self
                            .node
                            .add_invoice(AddInvoiceRequest {
                                memo: Some(desc),
                                amount: total_amount,
                                expire: Some(INVOICE_EXPIRE as u32),
                            })
                            .await?;
                        VmPayment {
                            id: hex::decode(invoice.payment_hash)?,
                            vm_id,
                            created: Utc::now(),
                            expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE)),
                            amount,
                            tax,
                            currency: currency.to_string(),
                            payment_method: method,
                            time_value,
                            is_paid: false,
                            rate,
                            external_data: invoice.pr,
                            external_id: invoice.external_id,
                        }
                    }
                    PaymentMethod::Revolut => {
                        let rev = if let Some(r) = &self.revolut {
                            r
                        } else {
                            bail!("Revolut not configured")
                        };
                        ensure!(
                            currency != Currency::BTC,
                            "Cannot create revolut orders for BTC currency"
                        );
                        let order = rev
                            .create_order(&desc, CurrencyAmount::from_u64(currency, amount + tax))
                            .await?;
                        let new_id: [u8; 32] = rand::random();
                        VmPayment {
                            id: new_id.to_vec(),
                            vm_id,
                            created: Utc::now(),
                            expires: Utc::now().add(Duration::from_secs(3600)),
                            amount,
                            tax,
                            currency: currency.to_string(),
                            payment_method: method,
                            time_value,
                            is_paid: false,
                            rate,
                            external_data: order.raw_data,
                            external_id: Some(order.external_id),
                        }
                    }
                    PaymentMethod::Paypal => todo!(),
                };

                self.db.insert_vm_payment(&vm_payment).await?;

                Ok(vm_payment)
            }
        }
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
    use crate::exchange::{DefaultRateCache, Ticker};
    use crate::mocks::{MockDb, MockDnsServer, MockExchangeRate, MockNode, MockRouter};
    use crate::settings::{
        mock_settings, DnsServerConfig, LightningConfig, QemuConfig, RouterConfig,
    };
    use lnvps_db::{DiskInterface, DiskType, User, UserSshKey, VmTemplate};
    use std::net::IpAddr;
    use std::str::FromStr;

    const ROUTER_BRIDGE: &str = "bridge1";

    pub fn settings() -> Settings {
        let mut settings = mock_settings();
        settings.network_policy.access = NetworkAccessPolicy::StaticArp {
            interface: ROUTER_BRIDGE.to_string(),
        };
        settings
    }

    async fn add_user(db: &Arc<MockDb>) -> Result<(User, UserSshKey)> {
        let pubkey: [u8; 32] = rand::random();

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
        let rates = Arc::new(MockExchangeRate::new());
        const MOCK_RATE: f32 = 69_420.0;
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        let router = MockRouter::new(settings.network_policy.clone());
        let dns = MockDnsServer::new();
        let provisioner = LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone());

        let (user, ssh_key) = add_user(&db).await?;
        let vm = provisioner
            .provision(user.id, 1, 1, ssh_key.id, Some("mock-ref".to_string()))
            .await?;
        println!("{:?}", vm);

        // renew vm
        let payment = provisioner.renew(vm.id, PaymentMethod::Lightning).await?;
        assert_eq!(vm.id, payment.vm_id);
        assert_eq!(payment.tax, (payment.amount as f64 * 0.01).floor() as u64);

        // check invoice amount matches amount+tax
        let inv = node.invoices.lock().await;
        if let Some(i) = inv.get(&hex::encode(payment.id)) {
            assert_eq!(i.amount, payment.amount + payment.tax);
        } else {
            bail!("Invoice doesnt exist");
        }

        // spawn vm
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
            memory: 512 * crate::GB,
            disk_size: 20 * crate::TB,
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
