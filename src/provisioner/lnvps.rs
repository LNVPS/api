use crate::exchange::{ExchangeRateService, Ticker};
use crate::host::get_host_client;
use crate::host::proxmox::{
    ConfigureVm, CreateVm, DownloadUrlRequest, ImportDiskImageRequest, ProxmoxClient,
    ResizeDiskRequest, StorageContent, VmConfig,
};
use crate::lightning::{AddInvoiceRequest, LightningNode};
use crate::provisioner::{NetworkProvisioner, Provisioner, ProvisionerMethod};
use crate::router::Router;
use crate::settings::{NetworkAccessPolicy, NetworkPolicy, ProvisionerConfig, Settings};
use anyhow::{bail, Result};
use chrono::{Days, Months, Utc};
use fedimint_tonic_lnd::tonic::async_trait;
use lnvps_db::{DiskType, LNVpsDb, Vm, VmCostPlanIntervalType, VmIpAssignment, VmPayment};
use log::{debug, info, warn};
use nostr::util::hex;
use rand::random;
use rocket::futures::{SinkExt, StreamExt};
use std::net::IpAddr;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// Main provisioner class for LNVPS
///
/// Does all the hard work and logic for creating / expiring VM's
pub struct LNVpsProvisioner {
    read_only: bool,

    db: Arc<dyn LNVpsDb>,
    node: Arc<dyn LightningNode>,
    rates: Arc<dyn ExchangeRateService>,

    router: Option<Arc<dyn Router>>,
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
            network_policy: settings.network_policy,
            provisioner_config: settings.provisioner,
            read_only: settings.read_only,
        }
    }

    async fn get_iso_storage(node: &str, client: &ProxmoxClient) -> Result<String> {
        let storages = client.list_storage(node).await?;
        if let Some(s) = storages
            .iter()
            .find(|s| s.contents().contains(&StorageContent::ISO))
        {
            Ok(s.storage.clone())
        } else {
            bail!("No image storage found");
        }
    }

    async fn save_ip_assignment(&self, vm: &Vm, assignment: &VmIpAssignment) -> Result<()> {
        // apply network policy
        if let NetworkAccessPolicy::StaticArp { interface } = &self.network_policy.access {
            if let Some(r) = self.router.as_ref() {
                r.add_arp_entry(
                    IpAddr::from_str(&assignment.ip)?,
                    &vm.mac_address,
                    interface,
                    Some(&format!("VM{}", vm.id)),
                )
                .await?;
            } else {
                bail!("No router found to apply static arp entry!")
            }
        }

        // save to db
        self.db.insert_vm_ip_assignment(assignment).await?;
        Ok(())
    }
}

#[async_trait]
impl Provisioner for LNVpsProvisioner {
    async fn init(&self) -> Result<()> {
        // tell hosts to download images
        let hosts = self.db.list_hosts().await?;
        for host in hosts {
            let client = get_host_client(&host, &self.provisioner_config)?;
            let iso_storage = Self::get_iso_storage(&host.name, &client).await?;
            let files = client.list_storage_files(&host.name, &iso_storage).await?;

            for image in self.db.list_os_image().await? {
                info!("Downloading image {} on {}", image.url, host.name);
                let i_name = image.filename()?;
                if files
                    .iter()
                    .any(|v| v.vol_id.ends_with(&format!("iso/{i_name}")))
                {
                    info!("Already downloaded, skipping");
                    continue;
                }
                let t_download = client
                    .download_image(DownloadUrlRequest {
                        content: StorageContent::ISO,
                        node: host.name.clone(),
                        storage: iso_storage.clone(),
                        url: image.url.clone(),
                        filename: i_name,
                    })
                    .await?;
                client.wait_for_task(&t_download).await?;
            }
        }
        Ok(())
    }

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
            disk_id: pick_disk.id,
            mac_address: format!(
                "bc:24:11:{}:{}:{}",
                hex::encode([random::<u8>()]),
                hex::encode([random::<u8>()]),
                hex::encode([random::<u8>()])
            ),
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

    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        let vm = self.db.get_vm(vm_id).await?;
        let existing_ips = self.db.list_vm_ip_assignments(vm_id).await?;
        if !existing_ips.is_empty() {
            return Ok(existing_ips);
        }

        // Use random network provisioner
        let prov = NetworkProvisioner::new(ProvisionerMethod::Random, self.db.clone());

        let template = self.db.get_vm_template(vm.template_id).await?;
        let ip = prov.pick_ip_for_region(template.region_id).await?;
        let assignment = VmIpAssignment {
            id: 0,
            vm_id,
            ip_range_id: ip.range_id,
            ip: ip.ip.to_string(),
            deleted: false,
        };

        self.save_ip_assignment(&vm, &assignment).await?;
        Ok(vec![assignment])
    }

    /// Create a vm on the host as configured by the template
    async fn spawn_vm(&self, vm_id: u64) -> Result<()> {
        if self.read_only {
            bail!("Cant spawn VM's in read-only mode")
        }
        let vm = self.db.get_vm(vm_id).await?;
        let template = self.db.get_vm_template(vm.template_id).await?;
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &self.provisioner_config)?;
        let image = self.db.get_os_image(vm.image_id).await?;

        // TODO: remove +100 nonsense (proxmox specific)
        let vm_id = 100 + vm.id as i32;

        // setup network by allocating some IP space
        let ips = self.allocate_ips(vm.id).await?;

        // create VM
        let config = client.make_vm_config(&self.db, &vm, &ips).await?;
        let t_create = client
            .create_vm(CreateVm {
                node: host.name.clone(),
                vm_id,
                config,
            })
            .await?;
        client.wait_for_task(&t_create).await?;

        // TODO: pick disk based on available space
        // TODO: build external module to manage picking disks
        // pick disk
        let drives = self.db.list_host_disks(vm.host_id).await?;
        let drive = if let Some(d) = drives.iter().find(|d| d.enabled) {
            d
        } else {
            bail!("No host drive found!")
        };

        // TODO: remove scsi0 terms (proxmox specific)
        // import primary disk from image (scsi0)?
        client
            .import_disk_image(ImportDiskImageRequest {
                vm_id,
                node: host.name.clone(),
                storage: drive.name.clone(),
                disk: "scsi0".to_string(),
                image: image.filename()?,
                is_ssd: matches!(drive.kind, DiskType::SSD),
            })
            .await?;

        // TODO: remove scsi0 terms (proxmox specific)
        // resize disk to match template
        let j_resize = client
            .resize_disk(ResizeDiskRequest {
                node: host.name.clone(),
                vm_id,
                disk: "scsi0".to_string(),
                size: template.disk_size.to_string(),
            })
            .await?;
        client.wait_for_task(&j_resize).await?;

        // try start, otherwise ignore error (maybe its already running)
        if let Ok(j_start) = client.start_vm(&host.name, vm_id as u64).await {
            client.wait_for_task(&j_start).await?;
        }

        Ok(())
    }

    async fn start_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        let j_start = client.start_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;
        Ok(())
    }

    async fn stop_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        let j_start = client.shutdown_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;

        Ok(())
    }

    async fn restart_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host, &self.provisioner_config)?;
        let j_start = client.reset_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;

        Ok(())
    }

    async fn delete_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        //let host = self.db.get_host(vm.host_id).await?;

        // TODO: delete not implemented, stop only
        //let client = get_host_client(&host)?;
        //let j_start = client.delete_vm(&host.name, vm.id + 100).await?;
        //let j_stop = client.stop_vm(&host.name, vm.id + 100).await?;
        //client.wait_for_task(&j_stop).await?;

        if let Some(r) = self.router.as_ref() {
            let ent = r.list_arp_entry().await?;
            if let Some(ent) = ent.iter().find(|e| {
                e.mac_address
                    .as_ref()
                    .map(|m| m.eq_ignore_ascii_case(&vm.mac_address))
                    .unwrap_or(false)
            }) {
                r.remove_arp_entry(ent.id.as_ref().unwrap().as_str())
                    .await?;
            } else {
                warn!("ARP entry not found, skipping")
            }
        }

        self.db.delete_vm_ip_assignment(vm.id).await?;
        self.db.delete_vm(vm.id).await?;

        Ok(())
    }

    async fn terminal_proxy(
        &self,
        vm_id: u64,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &self.provisioner_config)?;

        let host_vm_id = vm.id + 100;
        let term = client.terminal_proxy(&host.name, host_vm_id).await?;

        let login_msg = format!("{}:{}\n", term.user, term.ticket);
        let mut ws = client
            .open_terminal_proxy(&host.name, host_vm_id, term)
            .await?;
        debug!("Sending login msg: {}", login_msg);
        ws.send(Message::Text(login_msg)).await?;
        if let Some(n) = ws.next().await {
            debug!("{:?}", n);
        } else {
            bail!("No response from terminal_proxy");
        }
        ws.send(Message::Text("1:86:24:".to_string())).await?;
        Ok(ws)
    }

    async fn patch_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;
        let ips = self.db.list_vm_ip_assignments(vm.id).await?;
        let client = get_host_client(&host, &self.provisioner_config)?;
        let host_vm_id = vm.id + 100;

        let t = client
            .configure_vm(ConfigureVm {
                node: host.name.clone(),
                vm_id: host_vm_id as i32,
                current: None,
                snapshot: None,
                config: VmConfig {
                    scsi_0: None,
                    scsi_1: None,
                    efi_disk_0: None,
                    ..client.make_vm_config(&self.db, &vm, &ips).await?
                },
            })
            .await?;
        client.wait_for_task(&t).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::DefaultRateCache;
    use crate::mocks::{MockDb, MockNode};
    use crate::settings::{
        ApiConfig, Credentials, LndConfig, ProvisionerConfig, QemuConfig, RouterConfig,
    };

    #[ignore]
    #[tokio::test]
    async fn test_basic_provisioner() -> Result<()> {
        let settings = Settings {
            listen: None,
            db: "".to_string(),
            lnd: LndConfig {
                url: "".to_string(),
                cert: Default::default(),
                macaroon: Default::default(),
            },
            read_only: false,
            provisioner: ProvisionerConfig::Proxmox {
                qemu: QemuConfig {
                    machine: "q35".to_string(),
                    os_type: "linux26".to_string(),
                    bridge: "vmbr1".to_string(),
                    cpu: "kvm64".to_string(),
                    vlan: None,
                    kvm: false,
                },
                ssh: None,
            },
            network_policy: NetworkPolicy {
                access: NetworkAccessPolicy::StaticArp {
                    interface: "bridge1".to_string(),
                },
            },
            delete_after: 0,
            smtp: None,
            router: Some(RouterConfig::Mikrotik(ApiConfig {
                id: "mock-router".to_string(),
                url: "https://localhost".to_string(),
                credentials: Credentials::UsernamePassword {
                    username: "admin".to_string(),
                    password: "password123".to_string(),
                },
            })),
            dns: None,
            nostr: None,
        };
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(DefaultRateCache::default());
        let provisioner = LNVpsProvisioner::new(settings, db.clone(), node.clone(), rates.clone());

        let vm = db
            .insert_vm(&Vm {
                id: 1,
                host_id: 1,
                user_id: 1,
                image_id: 1,
                template_id: 1,
                ssh_key_id: 1,
                created: Utc::now(),
                expires: Utc::now() + Duration::from_secs(30),
                disk_id: 1,
                mac_address: "00:00:00:00:00:00".to_string(),
                deleted: false,
            })
            .await?;
        provisioner.spawn_vm(1).await?;
        Ok(())
    }
}
