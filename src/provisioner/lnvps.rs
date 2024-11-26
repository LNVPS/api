use crate::host::proxmox::ProxmoxClient;
use crate::provisioner::Provisioner;
use anyhow::{bail, Result};
use chrono::{Days, Months, Utc};
use fedimint_tonic_lnd::lnrpc::Invoice;
use fedimint_tonic_lnd::tonic::async_trait;
use fedimint_tonic_lnd::Client;
use ipnetwork::IpNetwork;
use lnvps_db::hydrate::Hydrate;
use lnvps_db::{
    IpRange, LNVpsDb, Vm, VmCostPlanIntervalType, VmIpAssignment, VmOsImage, VmPayment,
};
use log::{info, warn};
use rand::seq::IteratorRandom;
use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::Add;
use std::path::PathBuf;
use std::time::Duration;

pub struct LNVpsProvisioner {
    db: Box<dyn LNVpsDb>,
    lnd: Client,
}

impl LNVpsProvisioner {
    pub fn new<D: LNVpsDb + 'static>(db: D, lnd: Client) -> Self {
        Self {
            db: Box::new(db),
            lnd,
        }
    }

    /// Auto-discover resources
    pub async fn auto_discover(&self) -> Result<()> {
        let hosts = self.db.list_hosts().await?;
        for host in hosts {
            let api = ProxmoxClient::new(host.ip.parse()?).with_api_token(&host.api_token);

            let nodes = api.list_nodes().await?;
            if let Some(node) = nodes.iter().find(|n| n.name == host.name) {
                // Update host resources
                if node.max_cpu.unwrap_or(host.cpu) != host.cpu
                    || node.max_mem.unwrap_or(host.memory) != host.memory
                {
                    let mut host = host.clone();
                    host.cpu = node.max_cpu.unwrap_or(host.cpu);
                    host.memory = node.max_mem.unwrap_or(host.memory);
                    info!("Patching host: {:?}", host);
                    self.db.update_host(&host).await?;
                }
                // Update disk info
                let storages = api.list_storage().await?;
                let host_disks = self.db.list_host_disks(host.id).await?;
                for storage in storages {
                    let host_storage =
                        if let Some(s) = host_disks.iter().find(|d| d.name == storage.storage) {
                            s
                        } else {
                            warn!("Disk not found: {} on {}", storage.storage, host.name);
                            continue;
                        };

                    // TODO: patch host storage info
                }
            }
            info!(
                "Discovering resources from: {} v{}",
                &host.name,
                api.version().await?.version
            );
        }

        Ok(())
    }

    fn map_os_image(image: &VmOsImage) -> PathBuf {
        PathBuf::from("/var/lib/vz/images/").join(format!(
            "{:?}_{}_{}.img",
            image.distribution, image.flavour, image.version
        ))
    }
}

#[async_trait]
impl Provisioner for LNVpsProvisioner {
    async fn provision(
        &self,
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
    ) -> Result<Vm> {
        let user = self.db.get_user(user_id).await?;
        let template = self.db.get_vm_template(template_id).await?;
        let image = self.db.get_os_image(image_id).await?;
        let ssh_key = self.db.get_user_ssh_key(ssh_key_id).await?;
        let hosts = self.db.list_hosts().await?;

        // TODO: impl resource usage based provisioning
        let pick_host = if let Some(h) = hosts.first() {
            h
        } else {
            bail!("No host found")
        };
        let host_disks = self.db.list_host_disks(pick_host.id).await?;
        let pick_disk = if let Some(hd) = host_disks.first() {
            hd
        } else {
            bail!("No host disk found")
        };

        let mut new_vm = Vm {
            host_id: pick_host.id,
            user_id: user.id,
            image_id: image.id,
            template_id: template.id,
            ssh_key_id: ssh_key.id,
            created: Utc::now(),
            expires: Utc::now(),
            cpu: template.cpu,
            memory: template.memory,
            disk_size: template.disk_size,
            disk_id: pick_disk.id,
            ..Default::default()
        };

        let new_id = self.db.insert_vm(&new_vm).await?;
        new_vm.id = new_id;
        Ok(new_vm)
    }

    async fn renew(&self, vm_id: u64) -> Result<VmPayment> {
        let vm = self.db.get_vm(vm_id).await?;
        let template = self.db.get_vm_template(vm.template_id).await?;
        let cost_plan = self.db.get_cost_plan(template.cost_plan_id).await?;

        /// Reuse existing payment until expired
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

        const BTC_MILLI_SATS: u64 = 100_000_000_000;
        const INVOICE_EXPIRE: i64 = 3600;

        let cost = cost_plan.amount
            * match cost_plan.currency.as_str() {
                "EUR" => 1_100_000, //TODO: rates
                "BTC" => 1,         // BTC amounts are always millisats
                c => bail!("Unknown currency {c}"),
            };
        info!("Creating invoice for {vm_id} for {cost} mSats");
        let mut lnd = self.lnd.clone();
        let invoice = lnd
            .lightning()
            .add_invoice(Invoice {
                memo: format!("VM renewal {vm_id} to {new_expire}"),
                value_msat: cost as i64,
                expiry: INVOICE_EXPIRE,
                ..Default::default()
            })
            .await?;

        let invoice = invoice.into_inner();
        let vm_payment = VmPayment {
            id: invoice.r_hash.clone(),
            vm_id,
            created: Utc::now(),
            expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE as u64)),
            amount: cost,
            invoice: invoice.payment_request.clone(),
            time_value: (new_expire - vm.expires).num_seconds() as u64,
            is_paid: false,
            ..Default::default()
        };
        self.db.insert_vm_payment(&vm_payment).await?;

        Ok(vm_payment)
    }

    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        let mut vm = self.db.get_vm(vm_id).await?;
        let ips = self.db.get_vm_ip_assignments(vm.id).await?;

        if !ips.is_empty() {
            bail!("IP resources are already assigned");
        }

        vm.hydrate_up(&self.db).await?;
        let ip_ranges = self.db.list_ip_range().await?;
        let ip_ranges: Vec<IpRange> = ip_ranges
            .into_iter()
            .filter(|i| i.region_id == vm.template.as_ref().unwrap().region_id)
            .collect();

        if ip_ranges.is_empty() {
            bail!("No ip range found in this region");
        }

        let mut ret = vec![];
        /// Try all ranges
        // TODO: pick round-robin ranges
        for range in ip_ranges {
            let range_cidr: IpNetwork = range.cidr.parse()?;
            let ips = self.db.get_vm_ip_assignments_in_range(range.id).await?;
            let ips: HashSet<IpAddr> = ips.iter().map(|i| i.ip.parse().unwrap()).collect();

            // pick an IP at random
            let cidr: Vec<IpAddr> = {
                let mut rng = rand::thread_rng();
                range_cidr.iter().choose(&mut rng).into_iter().collect()
            };

            for ip in cidr {
                if !ips.contains(&ip) {
                    info!("Attempting to allocate IP for {vm_id} to {ip}");
                    let mut assignment = VmIpAssignment {
                        id: 0,
                        vm_id,
                        ip_range_id: range.id,
                        ip: IpNetwork::new(ip, range_cidr.prefix())?.to_string(),
                    };
                    let id = self.db.insert_vm_ip_assignment(&assignment).await?;
                    assignment.id = id;

                    ret.push(assignment);
                    break;
                }
            }
        }

        Ok(ret)
    }
}
