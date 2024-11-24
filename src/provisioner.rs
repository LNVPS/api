use crate::host::proxmox::{CreateVm, ProxmoxClient, VmBios};
use anyhow::{bail, Result};
use lnvps_db::{LNVpsDb, Vm, VmTemplate};
use log::{info, warn};
use rocket::async_trait;

#[async_trait]
pub trait Provisioner: Send + Sync {
    /// Provision a new VM
    async fn provision(&self, spec: VmTemplate) -> Result<Vm>;
}

pub struct LNVpsProvisioner {
    db: Box<dyn LNVpsDb>,
}

impl LNVpsProvisioner {
    pub fn new(db: impl LNVpsDb + 'static) -> Self {
        Self { db: Box::new(db) }
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
                    self.db.update_host(host).await?;
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
}

#[async_trait]
impl Provisioner for LNVpsProvisioner {
    async fn provision(&self, spec: VmTemplate) -> Result<Vm> {
        let hosts = self.db.list_hosts().await?;

        // try any host
        // TODO: impl resource usage based provisioning
        for host in hosts {
            let api = ProxmoxClient::new(host.ip.parse()?).with_api_token(&host.api_token);

            let nodes = api.list_nodes().await?;
            let node = if let Some(n) = nodes.iter().find(|n| n.name == host.name) {
                n
            } else {
                continue;
            };
            let host_disks = self.db.list_host_disks(host.id).await?;
            let disk_name = if let Some(d) = host_disks.first() {
                d
            } else {
                continue;
            };
            let next_id = 101;
            let vm_result = api
                .create_vm(
                    &node.name,
                    CreateVm {
                        vm_id: next_id,
                        bios: Some(VmBios::OVMF),
                        boot: Some("order=scsi0".to_string()),
                        cores: Some(spec.cpu as i32),
                        cpu: Some("kvm64".to_string()),
                        memory: Some((spec.memory / 1024 / 1024).to_string()),
                        machine: Some("q35".to_string()),
                        scsi_hw: Some("virtio-scsi-pci".to_string()),
                        efi_disk_0: Some(format!("{}:vm-{next_id}-efi,size=1M", &disk_name.name)),
                        net: Some("virtio=auto,bridge=vmbr0,tag=100".to_string()),
                        ip_config: Some(format!("ip=auto,ipv6=auto")),
                        ..Default::default()
                    },
                )
                .await?;

            return Ok(Vm {
                id: 0,
                host_id: 0,
                user_id: 0,
                image_id: 0,
                template_id: 0,
                ssh_key_id: 0,
                created: Default::default(),
                expires: Default::default(),
                cpu: 0,
                memory: 0,
                disk_size: 0,
                disk_id: 0,
            });
        }

        bail!("Failed to create VM")
    }
}
