use crate::exchange::ExchangeRateCache;
use crate::host::proxmox::{CreateVm, ProxmoxClient, VmBios, VmStatus};
use crate::provisioner::lnvps::LNVpsProvisioner;
use crate::provisioner::Provisioner;
use crate::status::{VmRunningState, VmState, VmStateCache};
use anyhow::{bail, Result};
use chrono::Utc;
use fedimint_tonic_lnd::Client;
use ipnetwork::IpNetwork;
use lnvps_db::{LNVpsDb, Vm, VmHost};
use log::{error, info, warn};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub enum WorkJob {
    /// Check the VM status matches database state
    ///
    /// This job starts a vm if stopped and also creates the vm if it doesn't exist yet
    CheckVm { vm_id: u64 },
    /// Send a notification to the users chosen contact preferences
    SendNotification { user_id: u64, message: String },
}

pub struct Worker {
    read_only: bool,
    db: Box<dyn LNVpsDb>,
    lnd: Client,
    provisioner: Box<dyn Provisioner>,
    vm_state_cache: VmStateCache,
    tx: UnboundedSender<WorkJob>,
    rx: UnboundedReceiver<WorkJob>,
}

impl Worker {
    pub fn new<D: LNVpsDb + Clone + 'static>(
        read_only: bool,
        db: D,
        lnd: Client,
        vm_state_cache: VmStateCache,
        rates: ExchangeRateCache,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        let p = LNVpsProvisioner::new(db.clone(), lnd.clone(), rates);
        Self {
            read_only,
            db: Box::new(db),
            provisioner: Box::new(p),
            vm_state_cache,
            lnd,
            tx,
            rx,
        }
    }

    pub fn sender(&self) -> UnboundedSender<WorkJob> {
        self.tx.clone()
    }

    /// Spawn a VM on the host
    async fn spawn_vm(&self, vm: &Vm, vm_host: &VmHost, client: &ProxmoxClient) -> Result<()> {
        if self.read_only {
            bail!("Cant spawn VM's in read-only mode");
        }
        let mut ips = self.db.list_vm_ip_assignments(vm.id).await?;
        if ips.is_empty() {
            ips = self.provisioner.allocate_ips(vm.id).await?;
        }

        let ip_config = ips
            .iter()
            .map_while(|ip| {
                if let Ok(net) = ip.ip.parse::<IpNetwork>() {
                    Some(match net {
                        IpNetwork::V4(addr) => format!("ip={}", addr),
                        IpNetwork::V6(addr) => format!("ip6={}", addr),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(",");

        let drives = self.db.list_host_disks(vm.host_id).await?;
        let drive = if let Some(d) = drives.iter().find(|d| d.enabled) {
            d
        } else {
            bail!("No host drive found!")
        };

        let ssh_key = self.db.get_user_ssh_key(vm.ssh_key_id).await?;

        client
            .create_vm(CreateVm {
                node: vm_host.name.clone(),
                vm_id: (vm.id + 100) as i32,
                bios: Some(VmBios::OVMF),
                boot: Some("order=scsi0".to_string()),
                cores: Some(vm.cpu as i32),
                cpu: Some("kvm64".to_string()),
                ip_config: Some(ip_config),
                machine: Some("q35".to_string()),
                memory: Some((vm.memory / 1024 / 1024).to_string()),
                net: Some("virtio,bridge=vmbr0,tag=100".to_string()),
                os_type: Some("l26".to_string()),
                scsi_1: Some(format!("{}:cloudinit", &drive.name)),
                scsi_hw: Some("virtio-scsi-pci".to_string()),
                ssh_keys: Some(urlencoding::encode(&ssh_key.key_data).to_string()),
                efi_disk_0: Some(format!("{}:0,efitype=4m", &drive.name)),
                ..Default::default()
            })
            .await?;

        Ok(())
    }

    /// Check a VM's status
    async fn check_vm(&self, vm_id: u64) -> Result<()> {
        info!("Checking VM {}", vm_id);
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;
        let client = ProxmoxClient::new(host.ip.parse()?).with_api_token(&host.api_token);

        match client.get_vm_status(&host.name, (vm.id + 100) as i32).await {
            Ok(s) => {
                info!("VM {} status: {:?}", vm_id, s.status);
                let state = VmState {
                    state: match s.status {
                        VmStatus::Stopped => VmRunningState::Stopped,
                        VmStatus::Running => VmRunningState::Running,
                    },
                    cpu_usage: s.cpu.unwrap_or(0.0),
                    mem_usage: s.mem.unwrap_or(0) as f32 / s.max_mem.unwrap_or(1) as f32,
                    uptime: s.uptime.unwrap_or(0),
                    net_in: s.net_in.unwrap_or(0),
                    net_out: s.net_out.unwrap_or(0),
                    disk_write: s.disk_write.unwrap_or(0),
                    disk_read: s.disk_read.unwrap_or(0),
                };
                self.vm_state_cache.set_state(vm_id, state).await?;
            }
            Err(e) => {
                warn!("Failed to get VM status: {}", e);
                if vm.expires > Utc::now() {
                    self.spawn_vm(&vm, &host, &client).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn handle(&mut self) -> Result<()> {
        while let Some(job) = self.rx.recv().await {
            match job {
                WorkJob::CheckVm { vm_id } => {
                    if let Err(e) = self.check_vm(vm_id).await {
                        error!("Failed to check VM {}: {}", vm_id, e);
                    }
                }
                WorkJob::SendNotification { .. } => {}
            }
        }
        Ok(())
    }
}
