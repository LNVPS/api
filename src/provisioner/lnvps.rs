use crate::exchange::{ExchangeRateCache, Ticker};
use crate::host::get_host_client;
use crate::host::proxmox::{
    CreateVm, DownloadUrlRequest, ProxmoxClient, ResizeDiskRequest, StorageContent, VmBios,
    VmConfig,
};
use crate::provisioner::Provisioner;
use crate::settings::{QemuConfig, SshConfig};
use crate::ssh_client::SshClient;
use anyhow::{bail, Result};
use chrono::{Days, Months, Utc};
use fedimint_tonic_lnd::lnrpc::Invoice;
use fedimint_tonic_lnd::tonic::async_trait;
use fedimint_tonic_lnd::Client;
use ipnetwork::IpNetwork;
use lnvps_db::hydrate::Hydrate;
use lnvps_db::{IpRange, LNVpsDb, Vm, VmCostPlanIntervalType, VmIpAssignment, VmPayment};
use log::info;
use nostr::util::hex;
use rand::random;
use rand::seq::IteratorRandom;
use reqwest::Url;
use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::Add;
use std::time::Duration;

pub struct LNVpsProvisioner {
    db: Box<dyn LNVpsDb>,
    lnd: Client,
    rates: ExchangeRateCache,
    read_only: bool,
    config: QemuConfig,
    ssh: Option<SshConfig>,
}

impl LNVpsProvisioner {
    pub fn new(
        read_only: bool,
        config: QemuConfig,
        ssh: Option<SshConfig>,
        db: impl LNVpsDb + 'static,
        lnd: Client,
        rates: ExchangeRateCache,
    ) -> Self {
        Self {
            db: Box::new(db),
            lnd,
            rates,
            config,
            read_only,
            ssh,
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
}

#[async_trait]
impl Provisioner for LNVpsProvisioner {
    async fn init(&self) -> Result<()> {
        // tell hosts to download images
        let hosts = self.db.list_hosts().await?;
        for host in hosts {
            let client = get_host_client(&host)?;
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
            cpu: template.cpu,
            memory: template.memory,
            disk_size: template.disk_size,
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
        const INVOICE_EXPIRE: i64 = 3600;

        let ticker = Ticker::btc_rate(cost_plan.currency.as_str())?;
        let rate = if let Some(r) = self.rates.get_rate(ticker).await {
            r
        } else {
            bail!("No exchange rate found")
        };

        let cost_btc = cost_plan.amount as f32 / rate;
        let cost_msat = (cost_btc as f64 * BTC_SATS) as i64 * 1000;
        info!("Creating invoice for {vm_id} for {} sats", cost_msat / 1000);
        let mut lnd = self.lnd.clone();
        let invoice = lnd
            .lightning()
            .add_invoice(Invoice {
                memo: format!("VM renewal {vm_id} to {new_expire}"),
                value_msat: cost_msat,
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
            amount: cost_msat as u64,
            invoice: invoice.payment_request.clone(),
            time_value: (new_expire - vm.expires).num_seconds() as u64,
            is_paid: false,
            rate,
            ..Default::default()
        };
        self.db.insert_vm_payment(&vm_payment).await?;

        Ok(vm_payment)
    }

    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>> {
        let mut vm = self.db.get_vm(vm_id).await?;
        let ips = self.db.list_vm_ip_assignments(vm.id).await?;

        if !ips.is_empty() {
            bail!("IP resources are already assigned");
        }

        vm.hydrate_up(&self.db).await?;
        let ip_ranges = self.db.list_ip_range().await?;
        let ip_ranges: Vec<IpRange> = ip_ranges
            .into_iter()
            .filter(|i| i.region_id == vm.template.as_ref().unwrap().region_id && i.enabled)
            .collect();

        if ip_ranges.is_empty() {
            bail!("No ip range found in this region");
        }

        let mut ret = vec![];
        // Try all ranges
        // TODO: pick round-robin ranges
        // TODO: pick one of each type
        'ranges: for range in ip_ranges {
            let range_cidr: IpNetwork = range.cidr.parse()?;
            let ips = self.db.list_vm_ip_assignments_in_range(range.id).await?;
            let ips: HashSet<IpAddr> = ips.iter().map_while(|i| i.ip.parse().ok()).collect();

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
                        ..Default::default()
                    };
                    let id = self.db.insert_vm_ip_assignment(&assignment).await?;
                    assignment.id = id;

                    ret.push(assignment);
                    break 'ranges;
                }
            }
        }

        Ok(ret)
    }

    async fn spawn_vm(&self, vm_id: u64) -> Result<()> {
        if self.read_only {
            bail!("Cant spawn VM's in read-only mode");
        }
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host)?;

        let mut ips = self.db.list_vm_ip_assignments(vm.id).await?;
        if ips.is_empty() {
            ips = self.allocate_ips(vm.id).await?;
        }

        // load ranges
        for ip in &mut ips {
            ip.hydrate_up(&self.db).await?;
        }

        let mut ip_config = ips
            .iter()
            .map_while(|ip| {
                if let Ok(net) = ip.ip.parse::<IpNetwork>() {
                    Some(match net {
                        IpNetwork::V4(addr) => {
                            format!(
                                "ip={},gw={}",
                                addr,
                                ip.ip_range.as_ref().map(|r| &r.gateway).unwrap()
                            )
                        }
                        IpNetwork::V6(addr) => format!("ip6={}", addr),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        ip_config.push("ip6=auto".to_string());

        let drives = self.db.list_host_disks(vm.host_id).await?;
        let drive = if let Some(d) = drives.iter().find(|d| d.enabled) {
            d
        } else {
            bail!("No host drive found!")
        };

        let ssh_key = self.db.get_user_ssh_key(vm.ssh_key_id).await?;

        let mut net = vec![
            format!("virtio={}", vm.mac_address),
            format!("bridge={}", self.config.bridge),
        ];
        if let Some(t) = self.config.vlan {
            net.push(format!("tag={}", t));
        }

        let vm_id = 100 + vm.id as i32;

        // create VM
        let t_create = client
            .create_vm(CreateVm {
                node: host.name.clone(),
                vm_id,
                config: VmConfig {
                    on_boot: Some(true),
                    bios: Some(VmBios::OVMF),
                    boot: Some("order=scsi0".to_string()),
                    cores: Some(vm.cpu as i32),
                    cpu: Some(self.config.cpu.clone()),
                    kvm: Some(self.config.kvm),
                    ip_config: Some(ip_config.join(",")),
                    machine: Some(self.config.machine.clone()),
                    memory: Some((vm.memory / 1024 / 1024).to_string()),
                    net: Some(net.join(",")),
                    os_type: Some(self.config.os_type.clone()),
                    scsi_1: Some(format!("{}:cloudinit", &drive.name)),
                    scsi_hw: Some("virtio-scsi-pci".to_string()),
                    ssh_keys: Some(urlencoding::encode(&ssh_key.key_data).to_string()),
                    efi_disk_0: Some(format!("{}:0,efitype=4m", &drive.name)),
                    ..Default::default()
                },
            })
            .await?;
        client.wait_for_task(&t_create).await?;

        // import the disk
        // TODO: find a way to avoid using SSH
        if let Some(ssh_config) = &self.ssh {
            let image = self.db.get_os_image(vm.image_id).await?;
            let host_addr: Url = host.ip.parse()?;
            let mut ses = SshClient::new()?;
            ses.connect(
                (host_addr.host().unwrap().to_string(), 22),
                &ssh_config.user,
                &ssh_config.key,
            )
            .await?;

            let cmd = format!(
                "/usr/sbin/qm set {} --scsi0 {}:0,import-from=/var/lib/vz/template/iso/{}",
                vm_id,
                &drive.name,
                &image.filename()?
            );
            let (code, rsp) = ses.execute(cmd.as_str()).await?;
            info!("{}", rsp);

            if code != 0 {
                bail!("Failed to import disk, exit-code {}", code);
            }
        } else {
            bail!("Cannot complete, no method available to import disk, consider configuring ssh")
        }

        // resize disk
        let j_resize = client
            .resize_disk(ResizeDiskRequest {
                node: host.name.clone(),
                vm_id,
                disk: "scsi0".to_string(),
                size: vm.disk_size.to_string(),
            })
            .await?;
        client.wait_for_task(&j_resize).await?;

        let j_start = client.start_vm(&host.name, vm_id as u64).await?;
        client.wait_for_task(&j_start).await?;

        Ok(())
    }

    async fn start_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host)?;
        let j_start = client.start_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;
        Ok(())
    }

    async fn stop_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host)?;
        let j_start = client.shutdown_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;

        Ok(())
    }

    async fn restart_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host)?;
        let j_start = client.reset_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;

        Ok(())
    }

    async fn delete_vm(&self, vm_id: u64) -> Result<()> {
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;

        let client = get_host_client(&host)?;
        let j_start = client.delete_vm(&host.name, vm.id + 100).await?;
        client.wait_for_task(&j_start).await?;

        self.db.delete_vm(vm.id).await?;

        Ok(())
    }
}
