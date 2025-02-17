use crate::host::get_host_client;
use crate::host::proxmox::{VmInfo, VmStatus};
use crate::provisioner::Provisioner;
use crate::settings::{Settings, SmtpConfig};
use crate::status::{VmRunningState, VmState, VmStateCache};
use anyhow::Result;
use chrono::{DateTime, Datelike, Days, Utc};
use lettre::message::{MessageBuilder, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::AsyncTransport;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use lnvps_db::LNVpsDb;
use log::{debug, error, info};
use nostr::{EventBuilder, PublicKey};
use nostr_sdk::Client;
use std::ops::{Add, Sub};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum WorkJob {
    /// Check all running VMS
    CheckVms,
    /// Check the VM status matches database state
    ///
    /// This job starts a vm if stopped and also creates the vm if it doesn't exist yet
    CheckVm { vm_id: u64 },
    /// Send a notification to the users chosen contact preferences
    SendNotification {
        user_id: u64,
        message: String,
        title: Option<String>,
    },
}

pub struct Worker {
    settings: WorkerSettings,
    db: Box<dyn LNVpsDb>,
    provisioner: Box<dyn Provisioner>,
    vm_state_cache: VmStateCache,
    tx: UnboundedSender<WorkJob>,
    rx: UnboundedReceiver<WorkJob>,
    client: Option<Client>,
    last_check_vms: DateTime<Utc>,
}

pub struct WorkerSettings {
    pub delete_after: u16,
    pub smtp: Option<SmtpConfig>,
}

impl Into<WorkerSettings> for &Settings {
    fn into(self) -> WorkerSettings {
        WorkerSettings {
            delete_after: self.delete_after,
            smtp: self.smtp.clone(),
        }
    }
}

impl Worker {
    pub fn new<D: LNVpsDb + Clone + 'static, P: Provisioner + 'static>(
        db: D,
        provisioner: P,
        settings: impl Into<WorkerSettings>,
        vm_state_cache: VmStateCache,
        client: Option<Client>,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            db: Box::new(db),
            provisioner: Box::new(provisioner),
            vm_state_cache,
            settings: settings.into(),
            tx,
            rx,
            client,
            last_check_vms: Utc::now(),
        }
    }

    pub fn sender(&self) -> UnboundedSender<WorkJob> {
        self.tx.clone()
    }

    async fn handle_vm_info(&self, s: VmInfo) -> Result<()> {
        // TODO: remove assumption
        let db_id = (s.vm_id - 100) as u64;
        let state = VmState {
            timestamp: Utc::now().timestamp() as u64,
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
            const BEFORE_EXPIRE_NOTIFICATION: u64 = 1;

            // Send notification of VM expiring soon
            if db_vm.expires < Utc::now().add(Days::new(BEFORE_EXPIRE_NOTIFICATION))
                && db_vm.expires
                    > self
                        .last_check_vms
                        .add(Days::new(BEFORE_EXPIRE_NOTIFICATION))
            {
                info!("Sending expire soon notification VM {}", db_vm.id);
                self.tx.send(WorkJob::SendNotification {
                    user_id: db_vm.user_id,
                    title: Some(format!("[VM{}] Expiring Soon", db_vm.id)),
                    message: format!("Your VM #{} will expire soon, please renew in the next {} days or your VM will be stopped.", db_vm.id, BEFORE_EXPIRE_NOTIFICATION)
                })?;
            }

            // Stop VM if expired and is running
            if db_vm.expires < Utc::now() && s.status == VmStatus::Running {
                info!("Stopping expired VM {}", db_vm.id);
                self.provisioner.stop_vm(db_vm.id).await?;
                self.tx.send(WorkJob::SendNotification {
                    user_id: db_vm.user_id,
                    title: Some(format!("[VM{}] Expired", db_vm.id)),
                    message: format!("Your VM #{} has expired and is now stopped, please renew in the next {} days or your VM will be deleted.", db_vm.id, self.settings.delete_after)
                })?;
            }
            // Delete VM if expired > self.settings.delete_after days
            if db_vm
                .expires
                .add(Days::new(self.settings.delete_after as u64))
                < Utc::now()
                && !db_vm.deleted
            {
                info!("Deleting expired VM {}", db_vm.id);
                self.provisioner.delete_vm(db_vm.id).await?;
                let title = Some(format!("[VM{}] Deleted", db_vm.id));
                self.tx.send(WorkJob::SendNotification {
                    user_id: db_vm.user_id,
                    title: title.clone(),
                    message: format!("Your VM #{} has been deleted!", db_vm.id),
                })?;
                self.queue_admin_notification(
                    format!("VM{} is ready for deletion", db_vm.id),
                    title,
                )?;
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
                    let vm_ips = self.db.list_vm_ip_assignments(vm.id).await?;
                    let image = self.db.get_os_image(vm.image_id).await?;
                    self.tx.send(WorkJob::SendNotification {
                        user_id: vm.user_id,
                        title: Some(format!("[VM{}] Created", vm.id)),
                        message: format!(
                            "Your VM #{} been created!\nOS: {}\nIPs: {}",
                            vm.id,
                            image,
                            vm_ips
                                .iter()
                                .map(|i| i.to_string())
                                .collect::<Vec<String>>()
                                .join(", ")
                        ),
                    })?;
                }
            }
        }
        Ok(())
    }

    pub async fn check_vms(&mut self) -> Result<()> {
        let hosts = self.db.list_hosts().await?;
        for host in hosts {
            let client = get_host_client(&host)?;

            for node in client.list_nodes().await? {
                debug!("Checking vms for {}", node.name);
                for vm in client.list_vms(&node.name).await? {
                    let vm_id = vm.vm_id;
                    debug!("\t{}: {:?}", vm_id, vm.status);
                    if let Err(e) = self.handle_vm_info(vm).await {
                        error!("{}", e);
                        self.queue_admin_notification(
                            format!("Failed to check VM {}:\n{}", vm_id, e.to_string()),
                            Some("Job Failed".to_string()),
                        )?
                    }
                }
            }
        }

        // check VM status from db vm list
        let db_vms = self.db.list_vms().await?;
        for vm in db_vms {
            let state = if let Some(s) = self.vm_state_cache.get_state(vm.id).await {
                if s.timestamp > Utc::now().timestamp() as u64 - 120 {
                    Some(s)
                } else {
                    None
                }
            } else {
                None
            };

            // create VM if not spawned yet
            if vm.expires > Utc::now() && state.is_none() {
                self.check_vm(vm.id).await?;
            }

            // delete vm if not paid (in new state)
            if !vm.deleted && vm.expires < Utc::now().sub(Days::new(1)) && state.is_none() {
                info!("Deleting unpaid VM {}", vm.id);
                self.provisioner.delete_vm(vm.id).await?;
            }
        }

        self.last_check_vms = Utc::now();
        Ok(())
    }

    async fn send_notification(
        &self,
        user_id: u64,
        message: String,
        title: Option<String>,
    ) -> Result<()> {
        let user = self.db.get_user(user_id).await?;
        if let Some(smtp) = self.settings.smtp.as_ref() {
            if user.contact_email && user.email.is_some() {
                // send email
                let mut b = MessageBuilder::new().to(user.email.unwrap().parse()?);
                if let Some(t) = title {
                    b = b.subject(t);
                }
                if let Some(f) = &smtp.from {
                    b = b.from(f.parse()?);
                }
                let template = include_str!("../email.html");
                let html = MultiPart::alternative_plain_html(
                    message.clone(),
                    template
                        .replace("%%_MESSAGE_%%", &message)
                        .replace("%%YEAR%%", Utc::now().year().to_string().as_str()),
                );

                let msg = b.multipart(html)?;

                let sender = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.server)?
                    .credentials(Credentials::new(
                        smtp.username.to_string(),
                        smtp.password.to_string(),
                    ))
                    .build();

                sender.send(msg).await?;
            }
        }
        if user.contact_nip4 {
            // send dm
        }
        if user.contact_nip17 {
            if let Some(c) = self.client.as_ref() {
                let sig = c.signer().await?;
                let ev = EventBuilder::private_msg(
                    &sig,
                    PublicKey::from_slice(&user.pubkey)?,
                    message,
                    None,
                )
                .await?;
                c.send_event(ev).await?;
            }
        }
        Ok(())
    }

    fn queue_notification(
        &self,
        user_id: u64,
        message: String,
        title: Option<String>,
    ) -> Result<()> {
        self.tx.send(WorkJob::SendNotification {
            user_id,
            message,
            title,
        })?;
        Ok(())
    }

    fn queue_admin_notification(&self, message: String, title: Option<String>) -> Result<()> {
        if let Some(a) = self.settings.smtp.as_ref().and_then(|s| s.admin) {
            self.queue_notification(a, message, title)?;
        }
        Ok(())
    }

    pub async fn handle(&mut self) -> Result<()> {
        while let Some(ref job) = self.rx.recv().await {
            match job {
                WorkJob::CheckVm { vm_id } => {
                    if let Err(e) = self.check_vm(*vm_id).await {
                        error!("Failed to check VM {}: {}", vm_id, e);
                        self.queue_admin_notification(
                            format!(
                                "Failed to check VM {}:\n{:?}\n{}",
                                vm_id,
                                &job,
                                e.to_string()
                            ),
                            Some("Job Failed".to_string()),
                        )?
                    }
                }
                WorkJob::SendNotification {
                    user_id,
                    message,
                    title,
                } => {
                    if let Err(e) = self
                        .send_notification(*user_id, message.clone(), title.clone())
                        .await
                    {
                        error!("Failed to send notification {}: {}", user_id, e);
                        self.queue_admin_notification(
                            format!(
                                "Failed to send notification:\n{:?}\n{}",
                                &job,
                                e.to_string()
                            ),
                            Some("Job Failed".to_string()),
                        )?
                    }
                }
                WorkJob::CheckVms => {
                    if let Err(e) = self.check_vms().await {
                        error!("Failed to check VMs: {}", e);
                        self.queue_admin_notification(
                            format!("Failed to check VM's:\n{:?}\n{}", &job, e.to_string()),
                            Some("Job Failed".to_string()),
                        )?
                    }
                }
            }
        }
        Ok(())
    }
}
