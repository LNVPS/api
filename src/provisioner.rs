use crate::host::proxmox::ProxmoxClient;
use anyhow::{bail, Result};
use chrono::{Days, Months, Utc};
use fedimint_tonic_lnd::lnrpc::Invoice;
use fedimint_tonic_lnd::Client;
use lnvps_db::{LNVpsDb, Vm, VmCostPlanIntervalType, VmOsImage, VmPayment};
use log::{info, warn};
use rocket::async_trait;
use rocket::yansi::Paint;
use std::ops::Add;
use std::path::PathBuf;
use std::time::Duration;

#[async_trait]
pub trait Provisioner: Send + Sync {
    /// Provision a new VM
    async fn provision(
        &self,
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
    ) -> Result<Vm>;

    /// Create a renewal payment
    async fn renew(&self, vm_id: u64) -> Result<VmPayment>;
}

pub struct LNVpsProvisioner {
    db: Box<dyn LNVpsDb>,
    lnd: Client,
}

impl LNVpsProvisioner {
    pub fn new(db: impl LNVpsDb + 'static, lnd: Client) -> Self {
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

        let mut vm_payment = VmPayment {
            id: 0,
            vm_id,
            created: Utc::now(),
            expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE as u64)),
            amount: cost,
            invoice: invoice.into_inner().payment_request,
            time_value: (new_expire - vm.expires).num_seconds() as u64,
            is_paid: false,
        };
        let payment_id = self.db.insert_vm_payment(&vm_payment).await?;
        vm_payment.id = payment_id;

        Ok(vm_payment)
    }
}
