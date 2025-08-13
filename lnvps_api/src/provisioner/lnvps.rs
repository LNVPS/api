use crate::dns::{BasicRecord, DnsServer};
use crate::fiat::FiatPaymentService;
use crate::host::{get_host_client, FullVmInfo};
use crate::lightning::{AddInvoiceRequest, LightningNode};
use crate::router::{ArpEntry, MikrotikRouter, OvhDedicatedServerVMacRouter, Router};
use crate::settings::{ProvisionerConfig, Settings};
use anyhow::{bail, ensure, Context, Result};
use chrono::Utc;
use ipnetwork::IpNetwork;
use isocountry::CountryCode;
use lnvps_api_common::{
    AvailableIp, CostResult, HostCapacityService, NetworkProvisioner, NewPaymentInfo,
    PricingEngine, UpgradeConfig, UpgradeCostQuote,
};
use lnvps_api_common::{Currency, CurrencyAmount, ExchangeRateService};
use lnvps_db::{
    AccessPolicy, IpRangeAllocationMode, LNVpsDb, NetworkAccessPolicy, PaymentMethod, PaymentType,
    RouterKind, Vm, VmCustomTemplate, VmHost, VmIpAssignment, VmPayment, VmTemplate,
};
use log::{info, warn};
use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;
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

    dns: Option<Arc<dyn DnsServer>>,
    revolut: Option<Arc<dyn FiatPaymentService>>,

    /// Forward zone ID used for all VM's
    /// passed to the DNSServer type
    forward_zone_id: Option<String>,
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
            dns: settings.get_dns().expect("dns config"),
            revolut: settings.get_revolut().expect("revolut config"),
            tax_rates: settings.tax_rate,
            provisioner_config: settings.provisioner,
            read_only: settings.read_only,
            forward_zone_id: settings.dns.map(|z| z.forward_zone_id),
        }
    }

    pub async fn get_router(&self, router_id: u64) -> Result<Arc<dyn Router>> {
        #[cfg(test)]
        return Ok(Arc::new(crate::mocks::MockRouter::new()));

        let cfg = self.db.get_router(router_id).await?;
        match cfg.kind {
            RouterKind::Mikrotik => {
                let mut t_split = cfg.token.as_str().split(":");
                let (username, password) = (
                    t_split.next().context("Invalid username:password")?,
                    t_split.next().context("Invalid username:password")?,
                );
                Ok(Arc::new(MikrotikRouter::new(&cfg.url, username, password)))
            }
            RouterKind::OvhAdditionalIp => Ok(Arc::new(
                OvhDedicatedServerVMacRouter::new(&cfg.url, &cfg.name, &cfg.token.as_str()).await?,
            )),
        }
    }

    /// Create or Update access policy for a given ip assignment, does not save to database!
    pub async fn update_access_policy(
        &self,
        assignment: &mut VmIpAssignment,
        policy: &AccessPolicy,
    ) -> Result<()> {
        let ip = IpNetwork::from_str(&assignment.ip)?;
        if matches!(policy.kind, NetworkAccessPolicy::StaticArp) && ip.is_ipv4() {
            let router = self
                .get_router(
                    policy
                        .router_id
                        .context("Cannot apply static arp policy with no router")?,
                )
                .await?;
            let vm = self.db.get_vm(assignment.vm_id).await?;
            let entry = ArpEntry::new(&vm, assignment, policy.interface.clone())?;
            let arp = if let Some(_id) = &assignment.arp_ref {
                router.update_arp_entry(&entry).await?
            } else {
                router.add_arp_entry(&entry).await?
            };
            ensure!(arp.id.is_some(), "ARP id was empty");
            assignment.arp_ref = arp.id;
        }
        Ok(())
    }

    /// Remove an access policy for a given ip assignment, does not save to database!
    pub async fn remove_access_policy(
        &self,
        assignment: &mut VmIpAssignment,
        policy: &AccessPolicy,
    ) -> Result<()> {
        let ip = IpNetwork::from_str(&assignment.ip)?;
        if matches!(policy.kind, NetworkAccessPolicy::StaticArp) && ip.is_ipv4() {
            let router = self
                .get_router(
                    policy
                        .router_id
                        .context("Cannot apply static arp policy with no router")?,
                )
                .await?;
            let id = if let Some(id) = &assignment.arp_ref {
                Some(id.clone())
            } else {
                warn!("ARP REF not found, using arp list");

                let ent = router.list_arp_entry().await?;
                if let Some(ent) = ent.iter().find(|e| e.address == assignment.ip) {
                    ent.id.clone()
                } else {
                    warn!("ARP entry not found, skipping");
                    None
                }
            };

            if let Some(id) = id {
                if let Err(e) = router.remove_arp_entry(&id).await {
                    warn!("Failed to remove arp entry, skipping: {}", e);
                }
            }
            assignment.arp_ref = None;
        }
        Ok(())
    }

    /// Delete DNS on the dns server, does not save to database!
    pub async fn remove_ip_dns(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        // Delete forward/reverse dns
        if let Some(dns) = &self.dns {
            let range = self.db.get_ip_range(assignment.ip_range_id).await?;

            if let (Some(z), Some(_ref)) = (&range.reverse_zone_id, &assignment.dns_reverse_ref) {
                let rev = BasicRecord::reverse(assignment)?;
                if let Err(e) = dns.delete_record(z, &rev).await {
                    warn!("Failed to delete reverse record: {}", e);
                }
                assignment.dns_reverse_ref = None;
                assignment.dns_reverse = None;
            }
            if let (Some(z), Some(_ref)) = (&self.forward_zone_id, &assignment.dns_forward_ref) {
                let rev = BasicRecord::forward(assignment)?;
                if let Err(e) = dns.delete_record(z, &rev).await {
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
        if let (Some(z), Some(dns)) = (&self.forward_zone_id, &self.dns) {
            let fwd = BasicRecord::forward(assignment)?;
            let ret_fwd = if fwd.id.is_some() {
                dns.update_record(z, &fwd).await?
            } else {
                dns.add_record(z, &fwd).await?
            };
            assignment.dns_forward = Some(ret_fwd.name);
            assignment.dns_forward_ref = Some(ret_fwd.id.context("Record id is missing")?);
        }
        Ok(())
    }

    /// Update DNS on the dns server, does not save to database!
    pub async fn update_reverse_ip_dns(&self, assignment: &mut VmIpAssignment) -> Result<()> {
        if let Some(dns) = &self.dns {
            let range = self.db.get_ip_range(assignment.ip_range_id).await?;
            if let Some(z) = &range.reverse_zone_id {
                let ret_rev = if assignment.dns_reverse_ref.is_some() {
                    dns.update_record(z, &BasicRecord::reverse(assignment)?)
                        .await?
                } else {
                    dns.add_record(z, &BasicRecord::reverse_to_fwd(assignment)?)
                        .await?
                };
                assignment.dns_reverse = Some(ret_rev.value);
                assignment.dns_reverse_ref = Some(ret_rev.id.context("Record id is missing")?);
            }
        }
        Ok(())
    }

    /// Delete all ip assignments for a given vm
    pub async fn delete_ip_assignments(&self, vm_id: u64) -> Result<()> {
        let ips = self.db.list_vm_ip_assignments(vm_id).await?;
        for mut ip in ips {
            // load range info to check access policy
            let range = self.db.get_ip_range(ip.ip_range_id).await?;
            if let Some(ap) = range.access_policy_id {
                let ap = self.db.get_access_policy(ap).await?;
                // remove access policy
                self.remove_access_policy(&mut ip, &ap).await?;
            }
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
        // load range info to check access policy
        let range = self.db.get_ip_range(assignment.ip_range_id).await?;
        if let Some(ap) = range.access_policy_id {
            let ap = self.db.get_access_policy(ap).await?;
            // apply access policy
            self.update_access_policy(assignment, &ap).await?;
        }

        // Add DNS records
        self.update_forward_ip_dns(assignment).await?;
        self.update_reverse_ip_dns(assignment).await?;

        // save to db
        self.db.insert_vm_ip_assignment(assignment).await?;
        Ok(())
    }

    async fn get_mac_for_assignment(
        &self,
        host: &VmHost,
        vm: &Vm,
        assignment: &VmIpAssignment,
    ) -> Result<ArpEntry> {
        let range = self.db.get_ip_range(assignment.ip_range_id).await?;

        // ask router first if it wants to set the MAC
        if let Some(ap) = range.access_policy_id {
            let ap = self.db.get_access_policy(ap).await?;
            if let Some(rid) = ap.router_id {
                let router = self.get_router(rid).await?;

                if let Some(mac) = router
                    .generate_mac(&assignment.ip, &format!("VM{}", assignment.vm_id))
                    .await?
                {
                    return Ok(mac);
                }
            }
        }

        // ask the host next to generate the mac
        let client = get_host_client(host, &self.provisioner_config)?;
        let mac = client.generate_mac(vm).await?;
        Ok(ArpEntry {
            id: None,
            address: assignment.ip.clone(),
            mac_address: mac,
            interface: None,
            comment: None,
        })
    }

    pub async fn assign_available_v6_to_vm(
        &self,
        vm: &Vm,
        v6: &mut AvailableIp,
    ) -> Result<VmIpAssignment> {
        match v6.mode {
            // it's a bit awkward, but we need to update the IP AFTER its been picked
            // simply because sometimes we don't know the MAC of the NIC yet
            IpRangeAllocationMode::SlaacEui64 => {
                let mac = NetworkProvisioner::parse_mac(&vm.mac_address)?;
                let addr = NetworkProvisioner::calculate_eui64(&mac, &v6.ip)?;
                v6.ip = IpNetwork::new(addr, v6.ip.prefix())?;
            }
            _ => {}
        }
        let mut assignment = VmIpAssignment {
            vm_id: vm.id,
            ip_range_id: v6.range_id,
            ip: v6.ip.ip().to_string(),
            ..Default::default()
        };
        self.save_ip_assignment(&mut assignment).await?;
        Ok(assignment)
    }

    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        let mut vm = self.db.get_vm(vm_id).await?;
        let existing_ips = self.db.list_vm_ip_assignments(vm_id).await?;
        if !existing_ips.is_empty() {
            return Ok(existing_ips);
        }

        // Use random network provisioner
        let network = NetworkProvisioner::new(self.db.clone());

        let host = self.db.get_host(vm.host_id).await?;
        let ip = network.pick_ip_for_region(host.region_id).await?;
        let mut assignments = vec![];
        match ip.ip4 {
            Some(v4) => {
                let mut assignment = VmIpAssignment {
                    vm_id: vm.id,
                    ip_range_id: v4.range_id,
                    ip: v4.ip.ip().to_string(),
                    ..Default::default()
                };

                //generate mac address from ip assignment
                let mac = self.get_mac_for_assignment(&host, &vm, &assignment).await?;
                vm.mac_address = mac.mac_address;
                assignment.arp_ref = mac.id; // store ref if we got one
                self.db.update_vm(&vm).await?;

                self.save_ip_assignment(&mut assignment).await?;
                assignments.push(assignment);
            }
            /// TODO: add expected number of IPS per templates
            None => bail!("Cannot provision VM without an IPv4 address"),
        }
        if let Some(mut v6) = ip.ip6 {
            assignments.push(self.assign_available_v6_to_vm(&vm, &mut v6).await?);
        }

        Ok(assignments)
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
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            deleted: false,
            ref_code,
            auto_renewal_enabled: false, // Default to disabled for new VMs
        };

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

        let now = Utc::now();
        let mut new_vm = Vm {
            id: 0,
            host_id: host.host.id,
            user_id: user.id,
            image_id: image.id,
            template_id: None,
            custom_template_id: Some(template_id),
            ssh_key_id: ssh_key.id,
            created: now,
            expires: now,
            disk_id: pick_disk.disk.id,
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            deleted: false,
            ref_code,
            auto_renewal_enabled: false, // Default to disabled for new VMs
        };

        let new_id = self.db.insert_vm(&new_vm).await?;
        new_vm.id = new_id;
        Ok(new_vm)
    }

    /// Create a renewal payment
    pub async fn renew(&self, vm_id: u64, method: PaymentMethod) -> Result<VmPayment> {
        let pe = PricingEngine::new_for_vm(
            self.db.clone(),
            self.rates.clone(),
            self.tax_rates.clone(),
            vm_id,
        )
            .await?;
        let price = pe.get_vm_cost(vm_id, method).await?;
        self.price_to_payment(vm_id, method, price).await
    }

    /// Renew a VM using a specific amount
    pub async fn renew_amount(
        &self,
        vm_id: u64,
        amount: CurrencyAmount,
        method: PaymentMethod,
    ) -> Result<VmPayment> {
        let pe = PricingEngine::new_for_vm(
            self.db.clone(),
            self.rates.clone(),
            self.tax_rates.clone(),
            vm_id,
        )
            .await?;
        let price = pe.get_cost_by_amount(vm_id, amount, method).await?;
        self.price_to_payment(vm_id, method, price).await
    }

    async fn price_to_payment(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        price: CostResult,
    ) -> Result<VmPayment> {
        self.price_to_payment_with_type(vm_id, method, price, PaymentType::Renewal, None)
            .await
    }

    async fn price_to_payment_with_type(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        price: CostResult,
        payment_type: PaymentType,
        upgrade_params: Option<String>,
    ) -> Result<VmPayment> {
        match price {
            CostResult::Existing(p) => Ok(p),
            CostResult::New(p) => {
                let desc = match payment_type {
                    PaymentType::Renewal => format!("VM renewal {vm_id} to {}", p.new_expiry),
                    PaymentType::Upgrade => format!("VM upgrade {vm_id}"),
                };
                let vm_payment = match method {
                    PaymentMethod::Lightning => {
                        ensure!(
                            p.currency == Currency::BTC,
                            "Cannot create invoices for non-BTC currency"
                        );
                        const INVOICE_EXPIRE: u64 = 600;
                        let total_amount = p.amount + p.tax;
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
                            amount: p.amount,
                            tax: p.tax,
                            currency: p.currency.to_string(),
                            payment_method: method,
                            payment_type,
                            time_value: p.time_value,
                            is_paid: false,
                            rate: p.rate.rate,
                            external_data: invoice.pr.into(),
                            external_id: invoice.external_id,
                            upgrade_params,
                        }
                    }
                    PaymentMethod::Revolut => {
                        let rev = if let Some(r) = &self.revolut {
                            r
                        } else {
                            bail!("Revolut not configured")
                        };
                        ensure!(
                            p.currency != Currency::BTC,
                            "Cannot create revolut orders for BTC currency"
                        );
                        let order = rev
                            .create_order(
                                &desc,
                                CurrencyAmount::from_u64(p.currency, p.amount + p.tax),
                            )
                            .await?;
                        let new_id: [u8; 32] = rand::random();
                        VmPayment {
                            id: new_id.to_vec(),
                            vm_id,
                            created: Utc::now(),
                            expires: Utc::now().add(Duration::from_secs(3600)),
                            amount: p.amount,
                            tax: p.tax,
                            currency: p.currency.to_string(),
                            payment_method: method,
                            payment_type,
                            time_value: p.time_value,
                            is_paid: false,
                            rate: p.rate.rate,
                            external_data: order.raw_data.into(),
                            external_id: Some(order.external_id),
                            upgrade_params,
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
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        if let Err(e) = client.delete_vm(&vm).await {
            warn!("Failed to delete VM: {}", e);
        }

        self.delete_ip_assignments(vm_id).await?;
        self.db.delete_vm(vm_id).await?;

        Ok(())
    }

    /// Start a VM
    pub async fn start_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        client.start_vm(&vm).await?;
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

    /// Calculate both upgrade cost and new renewal cost for a VM upgrade
    pub async fn calculate_upgrade_cost(
        &self,
        vm_id: u64,
        cfg: &UpgradeConfig,
        method: PaymentMethod,
    ) -> Result<UpgradeCostQuote> {
        let pe = PricingEngine::new_for_vm(
            self.db.clone(),
            self.rates.clone(),
            self.tax_rates.clone(),
            vm_id,
        )
            .await?;
        pe.calculate_upgrade_cost(vm_id, cfg, method).await
    }

    /// Convert a VM from standard template to custom template
    pub async fn convert_to_custom_template(&self, vm_id: u64, cfg: &UpgradeConfig) -> Result<()> {
        let (mut vm, _, new_custom_template) = self.create_upgrade_template(vm_id, cfg).await?;

        // Insert the new custom template
        let custom_template_id = self
            .db
            .insert_custom_vm_template(&new_custom_template)
            .await?;

        // Update the VM to use the custom template instead of the standard template
        vm.template_id = None;
        vm.custom_template_id = Some(custom_template_id);

        self.db.update_vm(&vm).await?;

        Ok(())
    }

    /// Create an upgrade payment
    pub async fn create_upgrade_payment(
        &self,
        vm_id: u64,
        cfg: &UpgradeConfig,
        method: PaymentMethod,
    ) -> Result<VmPayment> {
        let cost_difference = self.calculate_upgrade_cost(vm_id, cfg, method).await?;

        // create a payment entry for upgrade
        let payment = NewPaymentInfo {
            amount: cost_difference.upgrade.amount.value(),
            currency: cost_difference.upgrade.amount.currency(),
            rate: cost_difference.upgrade.rate,
            time_value: 0, //upgrades dont add time
            new_expiry: Default::default(),
            tax: 0, // No tax on upgrades for now
        };
        let upgrade_params_json = serde_json::to_string(cfg)?;

        self.price_to_payment_with_type(
            vm_id,
            method,
            CostResult::New(payment),
            PaymentType::Upgrade,
            Some(upgrade_params_json),
        )
            .await
    }

    /// Create a new custom template using a vm's existing standard template
    async fn create_upgrade_template(
        &self,
        vm_id: u64,
        cfg: &UpgradeConfig,
    ) -> Result<(Vm, VmTemplate, VmCustomTemplate)> {
        let vm = self.db.get_vm(vm_id).await?;

        // Only allow upgrading VMs with standard templates
        let template_id = vm
            .template_id
            .ok_or_else(|| anyhow::anyhow!("VM must have a standard template to upgrade"))?;
        let current_template = self.db.get_vm_template(template_id).await?;

        // Get the custom pricing for the region that supports the required disk type and interface
        let custom_pricings = self
            .db
            .list_custom_pricing(current_template.region_id)
            .await?;
        let mut compatible_pricing = None;

        for pricing in custom_pricings {
            if !pricing.enabled {
                continue;
            }

            // Check if this pricing supports the required disk type and interface
            let disk_configs = self.db.list_custom_pricing_disk(pricing.id).await?;
            let has_compatible_disk = disk_configs.iter().any(|disk| {
                disk.kind == current_template.disk_type
                    && disk.interface == current_template.disk_interface
            });

            if has_compatible_disk {
                compatible_pricing = Some(pricing);
                break;
            }
        }

        let custom_pricing = compatible_pricing
            .ok_or_else(|| anyhow::anyhow!(
                "No custom pricing available for this region that supports disk type {:?} with interface {:?}", 
                current_template.disk_type, 
                current_template.disk_interface
            ))?;

        // Build the new custom template with upgraded specs
        let new_custom_template = VmCustomTemplate {
            id: 0,
            cpu: cfg.new_cpu.unwrap_or(current_template.cpu),
            memory: cfg.new_memory.unwrap_or(current_template.memory),
            disk_size: cfg.new_disk.unwrap_or(current_template.disk_size),
            disk_type: current_template.disk_type,
            disk_interface: current_template.disk_interface,
            pricing_id: custom_pricing.id,
        };

        // Validate the upgrade (ensure we're not downgrading)
        ensure!(
            new_custom_template.cpu >= current_template.cpu,
            "Cannot downgrade CPU"
        );
        ensure!(
            new_custom_template.memory >= current_template.memory,
            "Cannot downgrade memory"
        );
        ensure!(
            new_custom_template.disk_size >= current_template.disk_size,
            "Cannot downgrade disk"
        );

        Ok((vm, current_template, new_custom_template))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::{MockDnsServer, MockNode, MockRouter};
    use crate::settings::mock_settings;
    use lnvps_api_common::{DefaultRateCache, MockDb, MockExchangeRate, Ticker};
    use lnvps_db::{DiskInterface, DiskType, LNVpsDbBase, User, UserSshKey, VmTemplate};
    use std::net::IpAddr;
    use std::str::FromStr;

    const ROUTER_BRIDGE: &str = "bridge1";

    pub fn settings() -> Settings {
        mock_settings()
    }

    async fn add_user(db: &Arc<MockDb>) -> Result<(User, UserSshKey)> {
        let pubkey: [u8; 32] = rand::random();

        let user_id = db.upsert_user(&pubkey).await?;
        let mut new_key = UserSshKey {
            id: 0,
            name: "test-key".to_string(),
            user_id,
            created: Default::default(),
            key_data: "ssh-rsa AAA==".into(),
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

        // add static arp policy
        {
            let mut r = db.router.lock().await;
            r.insert(
                1,
                lnvps_db::Router {
                    id: 1,
                    name: "mock-router".to_string(),
                    enabled: true,
                    kind: RouterKind::Mikrotik,
                    url: "https://localhost".to_string(),
                    token: "username:password".into(),
                },
            );
            let mut p = db.access_policy.lock().await;
            p.insert(
                1,
                AccessPolicy {
                    id: 1,
                    name: "static-arp".to_string(),
                    kind: NetworkAccessPolicy::StaticArp,
                    router_id: Some(1),
                    interface: Some(ROUTER_BRIDGE.to_string()),
                },
            );
            let mut i = db.ip_range.lock().await;
            let r = i.get_mut(&1).unwrap();
            r.access_policy_id = Some(1);
            r.reverse_zone_id = Some("mock-rev-zone-id".to_string());
            let r = i.get_mut(&2).unwrap();
            r.reverse_zone_id = Some("mock-v6-rev-zone-id".to_string());
        }

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

        let vm = db.get_vm(vm.id).await?;
        // check resources
        let router = MockRouter::new();
        let arp = router.list_arp_entry().await?;
        assert_eq!(1, arp.len());
        let arp = arp.first().unwrap();
        assert_eq!(&vm.mac_address, &arp.mac_address);
        assert_eq!(vm.ref_code, Some("mock-ref".to_string()));
        assert_eq!(ROUTER_BRIDGE, arp.interface.as_ref().unwrap());
        println!("{:?}", arp);

        let ips = db.list_vm_ip_assignments(vm.id).await?;
        assert_eq!(2, ips.len());

        // lookup v4 ip
        let v4 = ips.iter().find(|r| r.ip_range_id == 1).unwrap();
        println!("{:?}", v4);
        assert_eq!(v4.ip, arp.address);
        assert_eq!(v4.ip_range_id, 1);
        assert_eq!(v4.vm_id, vm.id);
        assert!(v4.dns_forward.is_some());
        assert!(v4.dns_reverse.is_some());
        assert!(v4.dns_reverse_ref.is_some());
        assert!(v4.dns_forward_ref.is_some());
        assert_eq!(v4.dns_reverse, v4.dns_forward);

        // assert IP address is not CIDR
        assert!(IpAddr::from_str(&v4.ip).is_ok());
        assert!(!v4.ip.ends_with("/8"));
        assert!(!v4.ip.ends_with("/24"));

        // lookup v6 ip
        let v6 = ips.iter().find(|r| r.ip_range_id == 2).unwrap();
        println!("{:?}", v6);
        assert_eq!(v6.ip_range_id, 2);
        assert_eq!(v6.vm_id, vm.id);
        assert!(v6.dns_forward.is_some());
        assert!(v6.dns_reverse.is_some());
        assert!(v6.dns_reverse_ref.is_some());
        assert!(v6.dns_forward_ref.is_some());
        assert_eq!(v6.dns_reverse, v6.dns_forward);

        // test zones have dns entries
        {
            let zones = dns.zones.lock().await;
            assert_eq!(zones.get("mock-rev-zone-id").unwrap().len(), 1);
            assert_eq!(zones.get("mock-v6-rev-zone-id").unwrap().len(), 1);
            assert_eq!(zones.get("mock-forward-zone-id").unwrap().len(), 2);

            let v6 = zones
                .get("mock-v6-rev-zone-id")
                .unwrap()
                .iter()
                .next()
                .unwrap();
            assert_eq!(v6.1.kind, "PTR");
            assert!(v6.1.name.ends_with("0.0.d.f.ip6.arpa"));
        }

        // now expire
        provisioner.delete_vm(vm.id).await?;

        // test arp/dns is removed
        let arp = router.list_arp_entry().await?;
        assert!(arp.is_empty());

        // test dns entries are deleted
        {
            let zones = dns.zones.lock().await;
            assert_eq!(zones.get("mock-rev-zone-id").unwrap().len(), 0);
            assert_eq!(zones.get("mock-forward-zone-id").unwrap().len(), 0);
        }

        // ensure IPS are deleted
        let ips = db.list_vm_ip_assignments(vm.id).await?;
        for ip in ips {
            println!("{:?}", ip);
            assert!(ip.arp_ref.is_none());
            assert!(ip.dns_forward.is_none());
            assert!(ip.dns_reverse.is_none());
            assert!(ip.dns_reverse_ref.is_none());
            assert!(ip.dns_forward_ref.is_none());
            assert!(ip.deleted);
        }

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
            memory: 512 * lnvps_api_common::GB,
            disk_size: 20 * lnvps_api_common::TB,
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
