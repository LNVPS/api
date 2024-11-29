use crate::host::get_host_client;
use crate::host::proxmox::{ProxmoxClient, VmInfo, VmStatus};
use crate::provisioner::Provisioner;
use crate::status::{VmRunningState, VmState, VmStateCache};
use anyhow::Result;
use chrono::{Days, Utc};
use lnvps_db::LNVpsDb;
use log::{debug, error, info, warn};
use std::ops::Add;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub enum WorkJob {
    /// Check all running VMS
    CheckVms,
    /// Check the VM status matches database state
    ///
    /// This job starts a vm if stopped and also creates the vm if it doesn't exist yet
    CheckVm { vm_id: u64 },
    /// Send a notification to the users chosen contact preferences
    SendNotification { user_id: u64, message: String },
}

pub struct Worker {
    db: Box<dyn LNVpsDb>,
    provisioner: Box<dyn Provisioner>,
    vm_state_cache: VmStateCache,
    tx: UnboundedSender<WorkJob>,
    rx: UnboundedReceiver<WorkJob>,
}

impl Worker {
    pub fn new<D: LNVpsDb + Clone + 'static, P: Provisioner + 'static>(
        db: D,
        provisioner: P,
        vm_state_cache: VmStateCache,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            db: Box::new(db),
            provisioner: Box::new(provisioner),
            vm_state_cache,
            tx,
            rx,
        }
    }

    pub fn sender(&self) -> UnboundedSender<WorkJob> {
        self.tx.clone()
    }

    async fn handle_vm_info(&self, s: VmInfo) -> Result<()> {
        // TODO: remove assumption
        let db_id = (s.vm_id - 100) as u64;
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
        self.vm_state_cache.set_state(db_id, state).await?;

        if let Ok(db_vm) = self.db.get_vm(db_id).await {
            // Stop VM if expired and is running
            if db_vm.expires < Utc::now() && s.status == VmStatus::Running {
                info!("Stopping expired VM {}", db_vm.id);
                self.provisioner.stop_vm(db_vm.id).await?;
            }
            // Delete VM if expired > 3 days
            if db_vm.expires.add(Days::new(3)) < Utc::now() {
                info!("Deleting expired VM {}", db_vm.id);
                self.provisioner.delete_vm(db_vm.id).await?;
            }
        }

        Ok(())
    }

    /// Check a VM's status
    async fn check_vm(&self, vm_id: u64) -> Result<()> {
        debug!("Checking VM: {}", vm_id);
        let vm = self.db.get_vm(vm_id).await?;
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host)?;

        match client.get_vm_status(&host.name, (vm.id + 100) as i32).await {
            Ok(s) => self.handle_vm_info(s).await?,
            Err(_) => {
                if vm.expires > Utc::now() {
                    self.provisioner.spawn_vm(vm.id).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn check_vms(&self) -> Result<()> {
        let hosts = self.db.list_hosts().await?;
        for host in hosts {
            let client = get_host_client(&host)?;

            for node in client.list_nodes().await? {
                info!("Checking vms for {}", node.name);
                for vm in client.list_vms(&node.name).await? {
                    info!("\t{}: {:?}", vm.vm_id, vm.status);
                    if let Err(e) = self.handle_vm_info(vm).await {
                        error!("{}", e);
                    }
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
                WorkJob::CheckVms => {
                    if let Err(e) = self.check_vms().await {
                        error!("Failed to check VMs: {}", e);
                    }
                }
            }
        }
        Ok(())
    }
}
