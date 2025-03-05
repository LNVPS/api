use crate::host::get_host_client;
use crate::provisioner::LNVpsProvisioner;
use crate::settings::{ProvisionerConfig, Settings, SmtpConfig};
use crate::status::{VmRunningState, VmState, VmStateCache};
use anyhow::Result;
use chrono::{DateTime, Datelike, Days, Utc};
use lettre::message::{MessageBuilder, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::AsyncTransport;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use lnvps_db::{LNVpsDb, Vm};
use log::{debug, error, info, warn};
use nostr::{EventBuilder, PublicKey, ToBech32};
use nostr_sdk::Client;
use std::ops::{Add, Sub};
use std::sync::Arc;
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

/// Primary background worker logic
/// Handles deleting expired VMs and sending notifications
pub struct Worker {
    settings: WorkerSettings,

    db: Arc<dyn LNVpsDb>,
    provisioner: Arc<LNVpsProvisioner>,
    nostr: Option<Client>,

    vm_state_cache: VmStateCache,
    tx: UnboundedSender<WorkJob>,
    rx: UnboundedReceiver<WorkJob>,
    last_check_vms: DateTime<Utc>,
}

pub struct WorkerSettings {
    pub delete_after: u16,
    pub smtp: Option<SmtpConfig>,
    pub provisioner_config: ProvisionerConfig,
}

impl From<&Settings> for WorkerSettings {
    fn from(val: &Settings) -> Self {
        WorkerSettings {
            delete_after: val.delete_after,
            smtp: val.smtp.clone(),
            provisioner_config: val.provisioner.clone(),
        }
    }
}

impl Worker {
    pub fn new(
        db: Arc<dyn LNVpsDb>,
        provisioner: Arc<LNVpsProvisioner>,
        settings: impl Into<WorkerSettings>,
        vm_state_cache: VmStateCache,
        nostr: Option<Client>,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            db,
            provisioner,
            vm_state_cache,
            nostr,
            settings: settings.into(),
            tx,
            rx,
            last_check_vms: Utc::now(),
        }
    }

    pub fn sender(&self) -> UnboundedSender<WorkJob> {
        self.tx.clone()
    }

    /// Handle VM state
    /// 1. Expire VM and send notification
    /// 2. Stop VM if expired and still running
    /// 3. Send notification for expiring soon
    async fn handle_vm_state(&self, vm: &Vm, state: &VmState) -> Result<()> {
        const BEFORE_EXPIRE_NOTIFICATION: u64 = 1;

        // Send notification of VM expiring soon
        if vm.expires < Utc::now().add(Days::new(BEFORE_EXPIRE_NOTIFICATION))
            && vm.expires
                > self
                    .last_check_vms
                    .add(Days::new(BEFORE_EXPIRE_NOTIFICATION))
        {
            info!("Sending expire soon notification VM {}", vm.id);
            self.tx.send(WorkJob::SendNotification {
                    user_id: vm.user_id,
                    title: Some(format!("[VM{}] Expiring Soon", vm.id)),
                    message: format!("Your VM #{} will expire soon, please renew in the next {} days or your VM will be stopped.", vm.id, BEFORE_EXPIRE_NOTIFICATION)
                })?;
        }

        // Stop VM if expired and is running
        if vm.expires < Utc::now() && state.state == VmRunningState::Running {
            info!("Stopping expired VM {}", vm.id);
            if let Err(e) = self.provisioner.stop_vm(vm.id).await {
                warn!("Failed to stop VM {}: {}", vm.id, e);
            }
            self.tx.send(WorkJob::SendNotification {
                    user_id: vm.user_id,
                    title: Some(format!("[VM{}] Expired", vm.id)),
                    message: format!("Your VM #{} has expired and is now stopped, please renew in the next {} days or your VM will be deleted.", vm.id, self.settings.delete_after)
                })?;
        }

        // Delete VM if expired > self.settings.delete_after days
        if vm.expires.add(Days::new(self.settings.delete_after as u64)) < Utc::now() && !vm.deleted
        {
            info!("Deleting expired VM {}", vm.id);
            self.provisioner.delete_vm(vm.id).await?;
            let title = Some(format!("[VM{}] Deleted", vm.id));
            self.tx.send(WorkJob::SendNotification {
                user_id: vm.user_id,
                title: title.clone(),
                message: format!("Your VM #{} has been deleted!", vm.id),
            })?;
            self.queue_admin_notification(format!("VM{} is ready for deletion", vm.id), title)?;
        }

        Ok(())
    }

    /// Check a VM's status
    async fn check_vm(&self, vm: &Vm) -> Result<()> {
        debug!("Checking VM: {}", vm.id);
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        match client.get_vm_state(&vm).await {
            Ok(s) => {
                self.handle_vm_state(&vm, &s).await?;
                self.vm_state_cache.set_state(vm.id, s).await?;
            }
            Err(_) => {
                // spawn VM if doesnt exist
                if vm.expires > Utc::now() {
                    self.provisioner.spawn_vm(vm.id).await?;
                    let vm_ips = self.db.list_vm_ip_assignments(vm.id).await?;
                    let image = self.db.get_os_image(vm.image_id).await?;
                    let user = self.db.get_user(vm.user_id).await?;

                    let msg = format!(
                        "VM #{} been created!\n\nOS: {}\n{}\n\nNPUB: {}",
                        vm.id,
                        image,
                        vm_ips
                            .iter()
                            .map(|i| if let Some(fwd) = &i.dns_forward {
                                format!("IP: {} ({})", i.ip, fwd)
                            } else {
                                format!("IP: {}", i.ip)
                            })
                            .collect::<Vec<String>>()
                            .join("\n "),
                        PublicKey::from_slice(&user.pubkey)?.to_bech32()?
                    );
                    self.tx.send(WorkJob::SendNotification {
                        user_id: vm.user_id,
                        title: Some(format!("[VM{}] Created", vm.id)),
                        message: format!("Your {}", &msg),
                    })?;
                    self.queue_admin_notification(msg, Some(format!("[VM{}] Created", vm.id)))?;
                }
            }
        }
        Ok(())
    }

    pub async fn check_vms(&mut self) -> Result<()> {
        // check VM status from db vm list
        let db_vms = self.db.list_vms().await?;
        for vm in &db_vms {
            // Refresh VM status if active
            self.check_vm(&vm).await?;

            // delete vm if not paid (in new state)
            if vm.expires < Utc::now().sub(Days::new(1)) {
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
            // TODO: send nip4 dm
        }
        if user.contact_nip17 {
            if let Some(c) = self.nostr.as_ref() {
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
        while let Some(job) = self.rx.recv().await {
            match &job {
                WorkJob::CheckVm { vm_id } => {
                    let vm = self.db.get_vm(*vm_id).await?;
                    if let Err(e) = self.check_vm(&vm).await {
                        error!("Failed to check VM {}: {}", vm_id, e);
                        self.queue_admin_notification(
                            format!("Failed to check VM {}:\n{:?}\n{}", vm_id, &job, e),
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
                            format!("Failed to send notification:\n{:?}\n{}", &job, e),
                            Some("Job Failed".to_string()),
                        )?
                    }
                }
                WorkJob::CheckVms => {
                    if let Err(e) = self.check_vms().await {
                        error!("Failed to check VMs: {}", e);
                        self.queue_admin_notification(
                            format!("Failed to check VM's:\n{:?}\n{}", &job, e),
                            Some("Job Failed".to_string()),
                        )?
                    }
                }
            }
        }
        Ok(())
    }
}
