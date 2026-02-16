use crate::host::{FullVmInfo, get_host_client};
use crate::provisioner::LNVpsProvisioner;
use crate::settings::{ProvisionerConfig, Settings, SmtpConfig};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Days, Utc};
use hickory_resolver::TokioResolver;
use lettre::AsyncTransport;
use lettre::message::{MessageBuilder, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use lnvps_api_common::{
    BlackholeWorkFeedback, ChannelWorkCommander, InMemoryKeyValueStore, JobFeedback, KeyValueStore,
    NetworkProvisioner, RedisConfig, RedisKeyValueStore, RedisWorkCommander, RedisWorkFeedback,
    UpgradeConfig, VmHistoryLogger, VmRunningState, VmRunningStates, VmStateCache, WorkCommander,
    WorkFeedback, WorkJob, WorkJobMessage, op_fatal,
    retry::{OpError, Pipeline, RetryPolicy},
};
use lnvps_db::{LNVpsDb, Vm, VmHost, VmIpAssignment};
use log::{debug, error, info, warn};
use nostr_sdk::{Client, EventBuilder, PublicKey, ToBech32};
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Primary background worker logic
/// Handles deleting expired VMs and sending notifications
#[derive(Clone)]
pub struct Worker {
    settings: WorkerSettings,
    db: Arc<dyn LNVpsDb>,
    provisioner: Arc<LNVpsProvisioner>,
    nostr: Option<Client>,
    vm_history_logger: VmHistoryLogger,
    vm_state_cache: VmStateCache,
    work_commander: Arc<dyn WorkCommander>,
    feedback: Arc<dyn WorkFeedback>,
    kv: Arc<dyn KeyValueStore>,
}

#[derive(Clone)]
pub struct WorkerSettings {
    pub delete_after: u16,
    pub smtp: Option<SmtpConfig>,
    pub provisioner_config: ProvisionerConfig,
    pub redis: Option<RedisConfig>,
    pub nostr_hostname: Option<String>,
}

impl From<&Settings> for WorkerSettings {
    fn from(val: &Settings) -> Self {
        WorkerSettings {
            delete_after: val.delete_after,
            smtp: val.smtp.clone(),
            provisioner_config: val.provisioner.clone(),
            redis: val.redis.clone(),
            nostr_hostname: val.nostr_address_host.clone(),
        }
    }
}

impl Worker {
    const CHECK_VMS_SECONDS: u64 = 30;

    pub async fn new(
        db: Arc<dyn LNVpsDb>,
        provisioner: Arc<LNVpsProvisioner>,
        settings: impl Into<WorkerSettings>,
        vm_state_cache: VmStateCache,
        nostr: Option<Client>,
    ) -> Result<Self> {
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        let settings = settings.into();

        let work_commander: Arc<dyn WorkCommander> = if let Some(redis_config) = &settings.redis {
            Arc::new(RedisWorkCommander::new(&redis_config.url, "workers", "api-worker").await?)
        } else {
            Arc::new(ChannelWorkCommander::new())
        };

        let kv: Arc<dyn KeyValueStore> = if let Some(c) = &settings.redis {
            Arc::new(RedisKeyValueStore::new(&c.url).await?)
        } else {
            Arc::new(InMemoryKeyValueStore::new())
        };

        let feedback: Arc<dyn WorkFeedback> = if let Some(c) = &settings.redis {
            Arc::new(RedisWorkFeedback::new(&c.url).await?)
        } else {
            Arc::new(BlackholeWorkFeedback)
        };
        Ok(Self {
            db,
            provisioner,
            vm_state_cache,
            nostr,
            kv,
            feedback,
            vm_history_logger,
            settings,
            work_commander,
        })
    }

    pub fn commander(&self) -> Arc<dyn WorkCommander> {
        self.work_commander.clone()
    }

    pub fn feedback(&self) -> Arc<dyn WorkFeedback> {
        self.feedback.clone()
    }

    pub async fn get_last_check_vms(&self) -> Result<DateTime<Utc>> {
        let Some(v) = self.kv.get("worker-last-check-vms").await? else {
            return Ok(DateTime::UNIX_EPOCH);
        };
        let timestamp = if v.len() == 8 {
            u64::from_le_bytes(v.as_slice().try_into()?)
        } else {
            0
        };
        let date = DateTime::from_timestamp(timestamp as _, 0).unwrap();
        Ok(date)
    }

    pub async fn set_last_check_vms(&self, last_check_vms: DateTime<Utc>) -> Result<()> {
        let t = last_check_vms.timestamp() as u64;
        self.kv
            .store("worker-last-check-vms", &t.to_le_bytes())
            .await?;
        Ok(())
    }

    /// Handle VM state
    /// 1. Expire VM and send notification
    /// 2. Stop VM if expired and still running
    /// 3. Send notification for expiring soon
    async fn handle_vm_state(&self, vm: &Vm, state: &VmRunningState) -> Result<()> {
        const BEFORE_EXPIRE_NOTIFICATION: u64 = 1;

        let last_check = self.get_last_check_vms().await?;

        // Attempt automatic renewal or send notification of VM expiring soon
        if vm.expires < Utc::now().add(Days::new(BEFORE_EXPIRE_NOTIFICATION))
            && vm.expires > last_check.add(Days::new(BEFORE_EXPIRE_NOTIFICATION))
        {
            // Try automatic renewal via NWC if both user NWC and VM auto-renewal are enabled
            let user = self.db.get_user(vm.user_id).await?;
            let mut renewal_attempted = false;
            let mut renewal_successful = false;
            let mut nwc_error = String::new();

            #[cfg(feature = "nostr-nwc")]
            if vm.auto_renewal_enabled {
                if let Some(ref nwc_connection) = user.nwc_connection_string {
                    let nwc_string: String = nwc_connection.clone().into();
                    if !nwc_string.is_empty() {
                        info!(
                            "Attempting automatic renewal for VM {} via NWC (user has NWC configured and VM auto-renewal is enabled)",
                            vm.id
                        );
                        renewal_attempted = true;

                        match self
                            .provisioner
                            .auto_renew_via_nwc(vm.id, &nwc_string)
                            .await
                        {
                            Ok(_) => {
                                renewal_successful = true;
                                info!("Successfully auto-renewed VM {} via NWC", vm.id);
                                self.queue_notification(vm.user_id, format!("Your VM #{} has been automatically renewed via Nostr Wallet Connect and will continue running.", vm.id), Some(format!("[VM{}] Auto-Renewed", vm.id))).await;
                            }
                            Err(e) => {
                                warn!("Auto-renewal error for VM {}: {}", vm.id, e);
                                nwc_error = e.to_string();
                            }
                        }
                    } else {
                        info!(
                            "VM {} has auto-renewal enabled but user has no NWC connection configured",
                            vm.id
                        );
                    }
                } else {
                    info!(
                        "VM {} has auto-renewal enabled but user has no NWC connection configured",
                        vm.id
                    );
                }
            }

            // If no renewal was attempted or renewal failed, send the expiry notification
            if !renewal_attempted || !renewal_successful {
                info!("Sending expire soon notification VM {}", vm.id);
                let message = if renewal_attempted {
                    format!(
                        "Your VM #{} will expire soon.\nAutomatic renewal failed, please manually renew in the next {} days or your VM will be stopped.\nError: '{}'",
                        vm.id, BEFORE_EXPIRE_NOTIFICATION, nwc_error
                    )
                } else {
                    format!(
                        "Your VM #{} will expire soon, please renew in the next {} days or your VM will be stopped.",
                        vm.id, BEFORE_EXPIRE_NOTIFICATION
                    )
                };

                self.queue_notification(
                    vm.user_id,
                    message,
                    Some(format!("[VM{}] Expiring Soon", vm.id)),
                )
                    .await;
            }
        }

        // Stop VM if expired and is running
        if vm.expires < Utc::now() && state.state == VmRunningStates::Running {
            info!("Stopping expired VM {}", vm.id);
            if let Err(e) = self.provisioner.stop_vm(vm.id).await {
                warn!("Failed to stop VM {}: {}", vm.id, e);
            } else if let Err(e) = self.vm_history_logger.log_vm_expired(vm.id, None).await {
                warn!("Failed to log VM {} expiration: {}", vm.id, e);
            }
            self.queue_notification(
                vm.user_id,
                format!("Your VM #{} has expired and is now stopped, please renew in the next {} days or your VM will be deleted.", vm.id, self.settings.delete_after),
                Some(format!("[VM{}] Expired", vm.id)),
            ).await;
        }

        // Delete VM if expired > self.settings.delete_after days
        if vm.expires.add(Days::new(self.settings.delete_after as u64)) < Utc::now() && !vm.deleted
        {
            info!("Deleting expired VM {}", vm.id);
            self.provisioner.delete_vm(vm.id).await?;

            // Log VM deletion
            if let Err(e) = self
                .vm_history_logger
                .log_vm_deleted(vm.id, None, Some("expired and exceeded grace period"), None)
                .await
            {
                warn!("Failed to log VM {} deletion: {}", vm.id, e);
            }

            let title = Some(format!("[VM{}] Deleted", vm.id));
            self.queue_notification(
                vm.user_id,
                format!("Your VM #{} has been deleted!", vm.id),
                title.clone(),
            )
                .await;
            self.queue_admin_notification(format!("VM{} is ready for deletion", vm.id), title)
                .await;
        }

        Ok(())
    }

    /// Check a VM's status
    async fn check_vm(&self, vm: &Vm) -> Result<()> {
        debug!("Checking VM: {}", vm.id);
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        match client.get_vm_state(vm).await {
            Ok(s) => {
                self.handle_vm_state(vm, &s).await?;
                self.vm_state_cache.set_state(vm.id, s).await?;
            }
            Err(e) => {
                warn!("Failed to get VM{} state: {}", vm.id, e);
                if vm.expires > Utc::now() {
                    self.spawn_vm_internal(vm).await?;
                }
            }
        }
        Ok(())
    }

    /// Check multiple VMs on a single host using bulk API
    async fn check_vms_on_host(&self, host_id: u64, vms: &[&Vm]) -> Result<()> {
        debug!("Checking {} VMs on host {}", vms.len(), host_id);
        let host = self.db.get_host(host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        let states = client.get_all_vm_states().await?;
        // Create a map of VM states by VM ID for quick lookup
        let state_map: HashMap<u64, VmRunningState> = states.into_iter().collect();

        for vm in vms {
            if let Some(state) = state_map.get(&vm.id) {
                // Use the bulk-fetched state
                self.handle_vm_state(vm, state).await?;
                self.vm_state_cache.set_state(vm.id, state.clone()).await?;
            } else {
                // VM not found in bulk response, handle as missing
                warn!("VM {} not found in bulk response", vm.id);
                if vm.expires > Utc::now() {
                    self.spawn_vm_internal(vm).await?;
                }
            }
        }
        Ok(())
    }

    /// Spawn a VM and send notifications
    async fn spawn_vm_internal(&self, vm: &Vm) -> Result<()> {
        let pipeline = self.provisioner.spawn_vm_pipeline(vm.id).await?;
        pipeline.execute().await?;

        // Log VM created
        if let Err(e) = self
            .vm_history_logger
            .log_vm_started(vm.id, None, None)
            .await
        {
            warn!("Failed to log VM {} creation: {}", vm.id, e);
        }

        let vm_ips = self.db.list_vm_ip_assignments(vm.id).await?;
        let image = self.db.get_os_image(vm.image_id).await?;
        let user = self.db.get_user(vm.user_id).await?;
        let resources = FullVmInfo::vm_resources(vm.id, self.db.clone()).await?;

        let msg = format!(
            "VM #{} been created!\n\nOS: {}\nCPU: {}\nRAM: {}GB\nDisk: {}GB\n{}\n\nNPUB: {}",
            vm.id,
            image,
            resources.cpu,
            resources.memory / crate::GB,
            resources.disk_size / crate::GB,
            vm_ips
                .iter()
                .map(|i| if let Some(fwd) = &i.dns_forward {
                    format!("IP: {} ({})", i.ip, fwd)
                } else {
                    format!("IP: {}", i.ip)
                })
                .collect::<Vec<String>>()
                .join("\n"),
            PublicKey::from_slice(&user.pubkey)?.to_bech32()?
        );
        self.queue_notification(
            vm.user_id,
            format!("Your {}", &msg),
            Some(format!("[VM{}] Created", vm.id)),
        )
            .await;
        self.queue_admin_notification(msg, Some(format!("[VM{}] Created", vm.id)))
            .await;
        Ok(())
    }

    pub async fn send(&self, job: WorkJob) -> Result<()> {
        self.work_commander.send(job).await?;
        Ok(())
    }

    pub fn spawn_job_interval(&self, job: WorkJob, interval: Duration) -> JoinHandle<()> {
        let sender = self.work_commander.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = sender.send(job.clone()).await {
                    error!("failed to send check vm: {}", e);
                }
                tokio::time::sleep(interval).await;
            }
        })
    }

    pub fn spawn_handler_loop(&self) -> JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = this.handle().await {
                    error!("Worker handler failed: {}", e);
                }
                error!("Worker thread exited!")
            }
        })
    }

    pub async fn check_vms(&self) -> Result<()> {
        // Check if enough time has passed since last check to prevent rapid back-to-back calls
        let last_check = self.get_last_check_vms().await?;
        let time_since_last_check = Utc::now().signed_duration_since(last_check);

        if time_since_last_check.num_seconds() < Self::CHECK_VMS_SECONDS as i64 {
            debug!(
                "Skipping CheckVms job - only {}s since last check (rate limit: {}s)",
                time_since_last_check.num_seconds(),
                Self::CHECK_VMS_SECONDS
            );
            return Ok(());
        }

        // check VM status from db vm list
        let db_vms = self.db.list_vms().await?;

        // Group VMs by host for bulk checking
        let mut vms_by_host: HashMap<u64, Vec<&Vm>> = HashMap::new();
        let mut vms_to_delete = Vec::new();

        for vm in &db_vms {
            let is_new_vm = vm.created == vm.expires;

            // only check spawned vms
            if !is_new_vm {
                vms_by_host.entry(vm.host_id).or_default().push(vm);
            }

            // delete vm if not paid (in new state)
            if is_new_vm && !vm.deleted && vm.expires < Utc::now().sub(Days::new(1)) {
                vms_to_delete.push(vm);
            }
        }

        // Process deletions first
        for vm in vms_to_delete {
            info!("Deleting unpaid VM {}", vm.id);
            if let Err(e) = self.provisioner.delete_vm(vm.id).await {
                error!("Failed to delete unpaid VM {}: {}", vm.id, e);
                self.queue_admin_notification(
                    format!("Failed to delete unpaid VM {}:\n{}", vm.id, e),
                    Some(format!("VM {} Deletion Failed", vm.id)),
                )
                    .await
            }
        }

        // Now check VMs grouped by host
        for (host_id, vms) in vms_by_host {
            if let Err(e) = self.check_vms_on_host(host_id, &vms).await {
                error!("Failed to check VMs on host {}: {}", host_id, e);
                // Fall back to individual checking for this host
                for vm in vms {
                    if let Err(e) = self.check_vm(vm).await {
                        error!("Failed to check VM {}: {}", vm.id, e);
                        self.queue_admin_notification(
                            format!("Failed to check VM {}:\n{}", vm.id, e),
                            Some(format!("VM {} Check Failed", vm.id)),
                        )
                            .await
                    }
                }
            }
        }

        self.set_last_check_vms(Utc::now()).await?;
        Ok(())
    }

    async fn send_notification(
        &self,
        user_id: u64,
        message: String,
        title: Option<String>,
    ) -> Result<()> {
        let user = self.db.get_user(user_id).await?;
        if let Some(smtp) = self.settings.smtp.as_ref()
            && user.contact_email
            && user.email.is_some()
        {
            // send email
            let mut b = MessageBuilder::new().to(user.email.unwrap().as_str().parse()?);
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
                .timeout(Some(Duration::from_secs(10)))
                .build();

            sender.send(msg).await?;
        }
        if user.contact_nip17
            && let Some(c) = self.nostr.as_ref()
        {
            let sig = c.signer().await?;
            let ev = EventBuilder::private_msg(
                &sig,
                PublicKey::from_slice(&user.pubkey)?,
                message,
                None,
            )
                .await?;
            c.send_event(&ev).await?;
        }
        Ok(())
    }

    async fn queue_notification(&self, user_id: u64, message: String, title: Option<String>) {
        if let Err(e) = self
            .work_commander
            .send(WorkJob::SendNotification {
                user_id,
                message,
                title,
            })
            .await
        {
            error!("Failed to queue notification: {}", e);
        }
    }

    async fn process_bulk_message(
        &self,
        subject: String,
        message: String,
        admin_user_id: u64,
    ) -> Result<()> {
        info!("Processing bulk message: '{}'", subject);

        // Get all active customers with contact preferences
        let active_customers = self.db.get_active_customers_with_contact_prefs().await?;
        let total_customers = active_customers.len();

        if total_customers == 0 {
            info!("No active customers found for bulk message");
            return Ok(());
        }

        info!(
            "Sending bulk message to {} active customers",
            total_customers
        );

        let mut sent_count = 0;
        let mut failed_count = 0;

        for customer in active_customers {
            // Personalize the message with customer name if available
            let personalized_message = if let Some(ref name) = customer.billing_name {
                format!("Dear {},\n\n{}", name, message)
            } else {
                format!("Dear Customer,\n\n{}", message)
            };

            // Use the existing send_notification method which handles both email and NIP-17
            match self
                .send_notification(customer.id, personalized_message, Some(subject.clone()))
                .await
            {
                Ok(_) => {
                    sent_count += 1;
                    info!("Bulk message sent to user ID: {}", customer.id);
                }
                Err(e) => {
                    failed_count += 1;
                    warn!(
                        "Failed to send bulk message to user ID {}: {}",
                        customer.id, e
                    );
                }
            }
        }

        info!(
            "Bulk message completed: {} sent, {} failed out of {} total recipients",
            sent_count, failed_count, total_customers
        );

        // Send completion notification to admin
        self.queue_notification(
            admin_user_id,
            format!(
                "Bulk message '{}' completed.\nSent: {}\nFailed: {}\nTotal recipients: {}",
                subject, sent_count, failed_count, total_customers
            ),
            Some("Bulk Message Complete".to_string()),
        )
            .await;

        Ok(())
    }

    async fn queue_admin_notification(&self, message: String, title: Option<String>) {
        if let Err(e) = self
            .work_commander
            .send(WorkJob::SendAdminNotification { message, title })
            .await
        {
            warn!("Failed to send admin notification: {}", e);
        }
    }

    async fn patch_host(&self, host: &mut VmHost) -> Result<()> {
        let client = match get_host_client(host, &self.settings.provisioner_config) {
            Ok(h) => h,
            Err(e) => bail!("Failed to get host client: {} {}", host.name, e),
        };
        let info = client.get_info().await?;
        let needs_update = info.cpu != host.cpu || info.memory != host.memory;
        if needs_update {
            host.cpu = info.cpu;
            host.memory = info.memory;
            self.db.update_host(host).await?;
            info!(
                "Updated host {}: cpu={}, memory={}",
                host.name, host.cpu, host.memory
            );
        }

        let mut host_disks = self.db.list_host_disks(host.id).await?;
        for disk in &info.disks {
            if let Some(hd) = host_disks.iter_mut().find(|d| d.name == disk.name) {
                if hd.size != disk.size {
                    hd.size = disk.size;
                    self.db.update_host_disk(hd).await?;
                    info!(
                        "Updated host disk {}: size={},type={},interface={}",
                        hd.name, hd.size, hd.kind, hd.interface
                    );
                }
            } else {
                warn!("Un-mapped host disk {}", disk.name);
            }
        }

        // Patch firewall configuration for all VMs on this host
        let vms = self.db.list_vms_on_host(host.id).await?;
        for vm in &vms {
            if !vm.deleted && vm.expires > Utc::now() {
                info!("Patching firewall for VM {} on host {}", vm.id, host.name);
                match FullVmInfo::load(vm.id, self.db.clone()).await {
                    Ok(vm_config) => {
                        if let Err(e) = client.patch_firewall(&vm_config).await {
                            warn!("Failed to patch firewall for VM {}: {}", vm.id, e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to load VM config for VM {}: {}", vm.id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a domain has a DNS record pointing to the configured nostr hostname or resolves to the same IP
    async fn check_domain_dns(&self, domain: &str) -> Result<bool> {
        let Some(expected_hostname) = &self.settings.nostr_hostname else {
            warn!("No nostr hostname configured, skipping DNS record check");
            return Ok(false);
        };

        // Create a resolver using system configuration
        let resolver = TokioResolver::builder_tokio()?.build();

        // Resolve both domain and expected hostname to IP addresses
        // lookup_ip automatically follows DNS records to get final IPs
        debug!(
            "Checking IP resolution for {} vs {}",
            domain, expected_hostname
        );

        // Resolve our expected hostname to IP addresses
        let expected_ips = match resolver.lookup_ip(expected_hostname).await {
            Ok(ips) => {
                let ip_addrs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                debug!(
                    "Expected hostname {} resolves to IPs: {:?}",
                    expected_hostname, ip_addrs
                );
                ip_addrs
            }
            Err(e) => {
                debug!(
                    "Failed to resolve expected hostname {} to IP: {}",
                    expected_hostname, e
                );
                return Ok(false);
            }
        };

        // Resolve the domain to IP addresses (follows DNS records automatically)
        match resolver.lookup_ip(domain).await {
            Ok(domain_ips) => {
                let domain_ip_addrs: Vec<String> =
                    domain_ips.iter().map(|ip| ip.to_string()).collect();
                debug!("Domain {} resolves to IPs: {:?}", domain, domain_ip_addrs);

                // Check if any of the domain's IPs match any of our expected IPs
                for domain_ip in &domain_ip_addrs {
                    if expected_ips.contains(domain_ip) {
                        debug!(
                            "Domain {} IP check: {} matches expected hostname {} (matches: true)",
                            domain, domain_ip, expected_hostname
                        );
                        return Ok(true);
                    }
                }

                debug!(
                    "Domain {} IP check: no IP overlap with expected hostname {} (matches: false)",
                    domain, expected_hostname
                );
                Ok(false)
            }
            Err(e) => {
                debug!("DNS IP lookup error for {}: {}", domain, e);
                Ok(false)
            }
        }
    }

    /// Check if a domain can be activated via path-based activation
    /// by checking if the activation URL is accessible
    async fn check_path_activation(&self, domain: &lnvps_db::NostrDomain) -> Result<bool> {
        let Some(activation_hash) = &domain.activation_hash else {
            debug!("Domain {} has no activation hash", domain.name);
            return Ok(false);
        };

        // Build the activation URL: http://<domain>/.well-known/nostr.json?name=<hash>
        let activation_url = format!(
            "http://{}/.well-known/nostr.json?name={}",
            domain.name, activation_hash
        );

        debug!("Checking path activation for domain {} at {}", domain.name, activation_url);

        // Try to fetch the activation URL
        #[cfg(any(feature = "mikrotik", feature = "proxmox", feature = "cloudflare"))]
        {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?;

            match client.get(&activation_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        debug!("Path activation check succeeded for domain {}", domain.name);
                        Ok(true)
                    } else {
                        debug!(
                            "Path activation check failed for domain {} - got status {}",
                            domain.name,
                            response.status()
                        );
                        Ok(false)
                    }
                }
                Err(e) => {
                    debug!(
                        "Path activation check failed for domain {} - error: {}",
                        domain.name, e
                    );
                    Ok(false)
                }
            }
        }
        
        #[cfg(not(any(feature = "mikrotik", feature = "proxmox", feature = "cloudflare")))]
        {
            warn!("Path activation check skipped - reqwest feature not enabled");
            Ok(false)
        }
    }

    /// Check all nostr domains for DNS records - enable disabled domains with DNS records, disable active domains without DNS records
    async fn check_nostr_domains(&self) -> Result<()> {
        let Some(expected_hostname) = &self.settings.nostr_hostname else {
            info!("No nostr hostname configured, skipping nostr domain DNS record checks");
            return Ok(());
        };

        info!(
            "Checking all nostr domains for DNS records or A record IP matches pointing to {}",
            expected_hostname
        );

        // Get all domains in a single query
        let all_domains = self.db.list_all_domains().await?;
        info!("Found {} total nostr domains to check", all_domains.len());

        let mut domains_activated = Vec::new();
        let mut domains_deactivated = Vec::new();
        let mut domains_deleted = Vec::new();

        for domain in &all_domains {
            // Check both DNS and path-based activation
            let has_dns_record = match self.check_domain_dns(&domain.name).await {
                Ok(result) => result,
                Err(e) => {
                    error!("DNS check error for {}: {}", domain.name, e);
                    false
                }
            };
            
            let has_path_activation = match self.check_path_activation(domain).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Path activation check error for {}: {}", domain.name, e);
                    false
                }
            };

            // If domain is disabled but has either DNS or path activation, enable it
            if !domain.enabled && (has_dns_record || has_path_activation) {
                if has_dns_record {
                    info!(
                        "Domain {} has DNS record pointing to {} - activating with HTTPS",
                        domain.name, expected_hostname
                    );

                    // Enable the domain with HTTPS support (DNS-based activation)
                    match self.db.enable_domain_with_https(domain.id).await {
                        Ok(()) => {
                            info!(
                                "Successfully enabled domain {} (ID: {}) with HTTPS",
                                domain.name, domain.id
                            );
                            domains_activated.push(&domain.name);

                            // Send notification to the domain owner
                            let notification_message = format!(
                                "Your nostr domain '{}' has been automatically activated with HTTPS! \n\n\
                                We detected that you've set up the required DNS record pointing to {}. \
                                Your domain is now active with SSL/TLS encryption and ready to use for nostr addresses.",
                                domain.name, expected_hostname
                            );

                            self.queue_notification(
                                domain.owner_id,
                                notification_message,
                                Some(format!("Nostr Domain '{}' Activated (HTTPS)", domain.name)),
                            )
                                .await;
                        }
                        Err(e) => {
                            error!(
                                "Failed to enable domain {} (ID: {}) with HTTPS: {}",
                                domain.name, domain.id, e
                            );

                            self.queue_admin_notification(
                                format!("Failed to enable domain '{}' (ID: {}) with HTTPS despite DNS record: {}",
                                        domain.name, domain.id, e),
                                Some(format!("Domain Activation Failed: {}", domain.name)),
                            ).await;
                        }
                    }
                } else {
                    // Path activation only (HTTP-only)
                    info!(
                        "Domain {} has path activation - activating as HTTP-only",
                        domain.name
                    );

                    match self.db.enable_domain_http_only(domain.id).await {
                        Ok(()) => {
                            info!(
                                "Successfully enabled domain {} (ID: {}) as HTTP-only",
                                domain.name, domain.id
                            );
                            domains_activated.push(&domain.name);

                            // Send notification to the domain owner
                            let notification_message = format!(
                                "Your nostr domain '{}' has been activated (HTTP-only)! \n\n\
                                We detected that the activation path is accessible. \
                                Your domain is now active for nostr addresses. \
                                To enable HTTPS, please set up a DNS record pointing to {}.",
                                domain.name, expected_hostname
                            );

                            self.queue_notification(
                                domain.owner_id,
                                notification_message,
                                Some(format!("Nostr Domain '{}' Activated (HTTP)", domain.name)),
                            )
                                .await;
                        }
                        Err(e) => {
                            error!(
                                "Failed to enable domain {} (ID: {}) as HTTP-only: {}",
                                domain.name, domain.id, e
                            );

                            self.queue_admin_notification(
                                format!("Failed to enable domain '{}' (ID: {}) as HTTP-only despite path activation: {}",
                                        domain.name, domain.id, e),
                                Some(format!("Domain Activation Failed: {}", domain.name)),
                            ).await;
                        }
                    }
                }
            }
            // If domain is active but has no DNS record and no path activation, deactivate it
            else if domain.enabled && !has_dns_record && !has_path_activation {
                info!(
                    "Domain {} no longer has DNS record or path activation - deactivating domain",
                    domain.name
                );

                // Disable the domain in the database
                match self.db.disable_domain(domain.id).await {
                    Ok(()) => {
                        info!(
                            "Successfully disabled domain {} (ID: {})",
                            domain.name, domain.id
                        );
                        domains_deactivated.push(&domain.name);

                        // Send notification to the domain owner
                        let notification_message = format!(
                            "Your nostr domain '{}' has been automatically deactivated. \n\n\
                            We detected that the required DNS record or path activation is no longer available. \
                            To reactivate your domain, please ensure your DNS record is correctly set up or path activation is available.",
                            domain.name
                        );

                        self.queue_notification(
                            domain.owner_id,
                            notification_message,
                            Some(format!("Nostr Domain '{}' Deactivated", domain.name)),
                        )
                            .await;
                    }
                    Err(e) => {
                        error!(
                            "Failed to disable domain {} (ID: {}): {}",
                            domain.name, domain.id, e
                        );

                        // Send admin notification about the failure
                        self.queue_admin_notification(
                            format!("Failed to disable domain '{}' (ID: {}) despite missing DNS/path: {}",
                                    domain.name, domain.id, e),
                            Some(format!("Domain Deactivation Failed: {}", domain.name)),
                        ).await;
                    }
                }
            }
            // If domain is HTTP-only but now has DNS, upgrade to HTTPS
            else if domain.enabled && domain.http_only && has_dns_record {
                info!(
                    "Domain {} is HTTP-only but now has DNS - upgrading to HTTPS",
                    domain.name
                );

                match self.db.enable_domain_with_https(domain.id).await {
                    Ok(()) => {
                        info!(
                            "Successfully upgraded domain {} (ID: {}) to HTTPS",
                            domain.name, domain.id
                        );

                        // Send notification to the domain owner
                        let notification_message = format!(
                            "Your nostr domain '{}' has been upgraded to HTTPS! \n\n\
                            We detected that you've set up the required DNS record pointing to {}. \
                            Your domain now has SSL/TLS encryption enabled.",
                            domain.name, expected_hostname
                        );

                        self.queue_notification(
                            domain.owner_id,
                            notification_message,
                            Some(format!("Nostr Domain '{}' Upgraded to HTTPS", domain.name)),
                        )
                            .await;
                    }
                    Err(e) => {
                        error!(
                            "Failed to upgrade domain {} (ID: {}) to HTTPS: {}",
                            domain.name, domain.id, e
                        );

                        self.queue_admin_notification(
                            format!("Failed to upgrade domain '{}' (ID: {}) to HTTPS: {}",
                                    domain.name, domain.id, e),
                            Some(format!("Domain HTTPS Upgrade Failed: {}", domain.name)),
                        ).await;
                    }
                }
            }
            // Domain status is correct - no change needed
            else if domain.enabled && (has_dns_record || has_path_activation) {
                debug!(
                    "Domain {} is correctly active (DNS: {}, Path: {}, HTTP-only: {})",
                    domain.name, has_dns_record, has_path_activation, domain.http_only
                );
            } 
            else if !domain.enabled && !has_dns_record && !has_path_activation {
                debug!(
                    "Domain {} is correctly inactive without DNS or path activation",
                    domain.name
                );

                // Check if domain has been disabled for more than 1 week - if so, delete it
                let one_week_ago = Utc::now().sub(Days::new(7));
                if domain.last_status_change < one_week_ago {
                    info!(
                        "Domain {} has been disabled for more than 1 week (since {}) - deleting domain",
                        domain.name, domain.last_status_change
                    );

                    // Delete the domain
                    match self.db.delete_domain(domain.id).await {
                        Ok(()) => {
                            info!(
                                "Successfully deleted domain {} (ID: {})",
                                domain.name, domain.id
                            );
                            domains_deleted.push(&domain.name);

                            // Send notification to the domain owner
                            let notification_message = format!(
                                "Your nostr domain '{}' has been permanently deleted. \n\n\
                                The domain was disabled for more than 1 week without the required DNS record or path activation. \
                                If you wish to use this domain again, you will need to register it again.",
                                domain.name
                            );

                            self.queue_notification(
                                domain.owner_id,
                                notification_message,
                                Some(format!("Nostr Domain '{}' Deleted", domain.name)),
                            )
                                .await;
                        }
                        Err(e) => {
                            error!(
                                "Failed to delete domain {} (ID: {}): {}",
                                domain.name, domain.id, e
                            );

                            // Send admin notification about the failure
                            self.queue_admin_notification(
                                format!("Failed to delete old disabled domain '{}' (ID: {}) that was disabled since {}: {}",
                                        domain.name, domain.id, domain.last_status_change, e),
                                Some(format!("Domain Deletion Failed: {}", domain.name)),
                            ).await;
                        }
                    }
                }
            }
        }

        // Send single admin notification with summary of all changes
        if !domains_activated.is_empty()
            || !domains_deactivated.is_empty()
            || !domains_deleted.is_empty()
        {
            let mut message_parts = Vec::new();

            if !domains_activated.is_empty() {
                message_parts.push(format!(
                    "ACTIVATED {} domains with DNS record entries pointing to {}:\n{}",
                    domains_activated.len(),
                    expected_hostname,
                    domains_activated
                        .iter()
                        .map(|s| format!("  • {}", s))
                        .collect::<Vec<String>>()
                        .join("\n")
                ));
            }

            if !domains_deactivated.is_empty() {
                message_parts.push(format!(
                    "DEACTIVATED {} domains without DNS record entries pointing to {}:\n{}",
                    domains_deactivated.len(),
                    expected_hostname,
                    domains_deactivated
                        .iter()
                        .map(|s| format!("  • {}", s))
                        .collect::<Vec<String>>()
                        .join("\n")
                ));
            }

            if !domains_deleted.is_empty() {
                message_parts.push(format!(
                    "DELETED {} domains that were disabled for more than 1 week:\n{}",
                    domains_deleted.len(),
                    domains_deleted
                        .iter()
                        .map(|s| format!("  • {}", s))
                        .collect::<Vec<String>>()
                        .join("\n")
                ));
            }

            let message = format!(
                "Nostr Domain Status Changes:\n\n{}",
                message_parts.join("\n\n")
            );

            info!("{}", message.replace('\n', " | "));
            self.queue_admin_notification(message, Some("Nostr Domains Status Update".to_string()))
                .await;
        } else {
            info!(
                "No nostr domain changes required - all domains have correct DNS configuration and no old disabled domains to delete"
            );
        }

        Ok(())
    }

    async fn try_job(&self, job: &WorkJob) -> Result<Option<String>> {
        info!("Starting job: {}", job);
        match job {
            WorkJob::PatchHosts => {
                let mut hosts = self.db.list_hosts().await?;
                for host in &mut hosts {
                    info!("Patching host {}", host.name);
                    self.patch_host(host).await?;
                }
            }
            WorkJob::CheckVm { vm_id } => {
                let vm = self.db.get_vm(*vm_id).await?;
                self.check_vm(&vm).await?;
            }
            WorkJob::SendNotification {
                user_id,
                message,
                title,
            } => {
                self.send_notification(*user_id, message.clone(), title.clone())
                    .await?;
            }
            WorkJob::SendAdminNotification { message, title } => {
                // Look up all admin users and queue individual notifications
                match self.db.list_admin_user_ids().await {
                    Ok(admin_ids) => {
                        if admin_ids.is_empty() {
                            warn!("No admin users found to send notification to");
                        } else {
                            info!("Sending admin notification to {} admin(s)", admin_ids.len());
                            for admin_id in admin_ids {
                                self.queue_notification(admin_id, message.clone(), title.clone())
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to list admin users: {}", e);
                    }
                }
            }
            WorkJob::BulkMessage {
                subject,
                message,
                admin_user_id,
            } => {
                self.process_bulk_message(subject.clone(), message.clone(), *admin_user_id)
                    .await?;

                return Ok(Some(format!(
                    "Bulk message '{}' sent successfully",
                    subject.trim()
                )));
            }
            WorkJob::CheckVms => {
                self.check_vms().await?;
            }
            WorkJob::DeleteVm {
                vm_id,
                reason,
                admin_user_id,
            } => {
                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    return Ok(None);
                }

                // Delete the VM via provisioner
                self.provisioner.delete_vm(*vm_id).await?;

                // Log VM deletion
                let metadata = if let Some(admin_id) = admin_user_id {
                    Some(serde_json::json!({
                        "admin_user_id": admin_id,
                        "admin_action": true
                    }))
                } else {
                    Some(serde_json::json!({
                        "admin_action": true
                    }))
                };

                self.vm_history_logger
                    .log_vm_deleted(*vm_id, *admin_user_id, reason.as_deref(), metadata)
                    .await?;

                // Send notifications
                let reason_text = reason.as_deref().unwrap_or("Admin requested deletion");
                let title = Some(format!("[VM{}] Deleted by Admin", vm_id));

                // Notify user
                self.queue_notification(
                    vm.user_id,
                    format!(
                        "Your VM #{} has been deleted by an administrator.\nReason: {}",
                        vm_id, reason_text
                    ),
                    title.clone(),
                )
                    .await;

                // Notify admin
                self.queue_admin_notification(
                    format!(
                        "VM {} has been successfully deleted.\nUser ID: {}\nReason: {}",
                        vm_id, vm.user_id, reason_text
                    ),
                    title,
                )
                    .await;

                return Ok(Some(format!("VM {} deleted successfully", vm_id)));
            }
            WorkJob::StartVm {
                vm_id,
                admin_user_id,
            } => {
                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    bail!("Cannot start deleted VM {}", vm_id);
                }

                // Check if VM is expired
                if vm.expires < Utc::now() {
                    bail!(
                        "Cannot start expired VM {} - it has expired (expires: {})",
                        vm_id,
                        vm.expires
                    );
                }

                // Start the VM via provisioner
                self.provisioner.start_vm(*vm_id).await?;

                // Log VM start
                let metadata = if let Some(admin_id) = admin_user_id {
                    Some(serde_json::json!({
                        "admin_user_id": admin_id,
                        "admin_action": true
                    }))
                } else {
                    Some(serde_json::json!({
                        "admin_action": true
                    }))
                };

                self.vm_history_logger
                    .log_vm_started(*vm_id, *admin_user_id, metadata)
                    .await?;

                let title = Some(format!("[VM{}] Started by Admin", vm_id));

                // Notify user
                self.queue_notification(
                    vm.user_id,
                    format!("Your VM #{} has been started by an administrator.", vm_id),
                    title.clone(),
                )
                    .await;

                // Notify admin
                self.queue_admin_notification(
                    format!(
                        "VM {} has been successfully started.\nUser ID: {}",
                        vm_id, vm.user_id
                    ),
                    title,
                )
                    .await;

                return Ok(Some(format!("VM {} started successfully", vm_id)));
            }
            WorkJob::StopVm {
                vm_id,
                admin_user_id,
            } => {
                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    bail!("Cannot stop deleted VM {}", vm_id);
                }

                // Stop the VM via provisioner
                self.provisioner.stop_vm(*vm_id).await?;

                // Log VM stop
                let metadata = if let Some(admin_id) = admin_user_id {
                    Some(serde_json::json!({
                        "admin_user_id": admin_id,
                        "admin_action": true
                    }))
                } else {
                    Some(serde_json::json!({
                        "admin_action": true
                    }))
                };

                self.vm_history_logger
                    .log_vm_stopped(*vm_id, *admin_user_id, metadata)
                    .await?;

                let title = Some(format!("[VM{}] Stopped by Admin", vm_id));

                // Notify user
                self.queue_notification(
                    vm.user_id,
                    format!("Your VM #{} has been stopped by an administrator.", vm_id),
                    title.clone(),
                )
                    .await;

                // Notify admin
                self.queue_admin_notification(
                    format!(
                        "VM {} has been successfully stopped.\nUser ID: {}",
                        vm_id, vm.user_id
                    ),
                    title,
                )
                    .await;

                return Ok(Some(format!("VM {} stopped successfully", vm_id)));
            }
            WorkJob::ProcessVmUpgrade { vm_id, config } => {
                self.process_vm_upgrade(*vm_id, config).await?;
            }
            WorkJob::ConfigureVm {
                vm_id,
                admin_user_id,
            } => {
                self.configure_vm(*vm_id, *admin_user_id).await?;
            }
            WorkJob::CheckNostrDomains => {
                self.check_nostr_domains().await?;
            }
            WorkJob::AssignVmIp {
                vm_id,
                ip_range_id,
                ip,
                admin_user_id,
            } => {
                self.assign_vm_ip(*vm_id, *ip_range_id, ip.clone(), *admin_user_id)
                    .await?;

                return Ok(Some(format!(
                    "IP assignment to VM {} completed successfully",
                    vm_id
                )));
            }
            WorkJob::UnassignVmIp {
                assignment_id,
                admin_user_id,
            } => {
                self.unassign_vm_ip(*assignment_id, *admin_user_id).await?;
                return Ok(Some(
                    "IP unassignment from VM completed successfully".to_string(),
                ));
            }
            WorkJob::UpdateVmIp {
                assignment_id,
                admin_user_id,
            } => {
                self.update_vm_ip(*assignment_id, *admin_user_id).await?;
                return Ok(Some("IP configuration updated successfully".to_string()));
            }
            WorkJob::ProcessVmRefund {
                vm_id: _,
                admin_user_id: _,
                refund_from_date: _,
                reason: _,
                payment_method: _,
                lightning_invoice: _,
            } => {
                // TODO: Implement the actual refund processing logic
                bail!("Refund processing is not yet implemented");
            }
            WorkJob::CreateVm {
                user_id,
                template_id,
                image_id,
                ssh_key_id,
                ref_code,
                admin_user_id,
                reason,
            } => {
                info!("Admin {} creating VM for user {}", admin_user_id, user_id);

                let vm = self
                    .provisioner
                    .provision(
                        *user_id,
                        *template_id,
                        *image_id,
                        *ssh_key_id,
                        ref_code.clone(),
                    )
                    .await?;

                // Log VM creation with admin metadata
                let metadata = Some(serde_json::json!({
                    "admin_user_id": admin_user_id,
                    "admin_action": true,
                    "reason": reason
                }));

                if let Err(e) = self
                    .vm_history_logger
                    .log_vm_created(&vm, Some(*user_id), metadata)
                    .await
                {
                    error!("Failed to log VM {} creation: {}", vm.id, e);
                }

                info!(
                    "Admin {} successfully created VM {} for user {}",
                    admin_user_id, vm.id, user_id
                );

                return Ok(Some(format!(
                    "VM {} created successfully for user {}",
                    vm.id, user_id
                )));
            }
        }
        Ok(None)
    }

    async fn process_vm_upgrade(&self, vm_id: u64, cfg: &UpgradeConfig) -> Result<()> {
        info!("Processing VM {} upgrade with new specs", vm_id);

        // Context struct for the pipeline
        struct UpgradeContext {
            vm_id: u64,
            cfg: UpgradeConfig,
            db: Arc<dyn LNVpsDb>,
            provisioner: Arc<LNVpsProvisioner>,
            settings: WorkerSettings,
            vm_history_logger: VmHistoryLogger,
        }

        let ctx = UpgradeContext {
            vm_id,
            cfg: cfg.clone(),
            db: self.db.clone(),
            provisioner: self.provisioner.clone(),
            settings: self.settings.clone(),
            vm_history_logger: self.vm_history_logger.clone(),
        };

        Pipeline::new(ctx)
            .with_retry_policy(RetryPolicy::default())
            .step("update_template", |ctx| {
                Box::pin(async move {
                    let vm_before = ctx.db.get_vm(ctx.vm_id).await?;

                    if vm_before.custom_template_id.is_some() {
                        // VM already uses custom template - update the existing template
                        info!(
                            "VM {} already uses custom template, updating existing template",
                            ctx.vm_id
                        );

                        let custom_template_id = vm_before.custom_template_id.unwrap();
                        let old_template = ctx.db.get_custom_vm_template(custom_template_id).await?;
                        let mut new_template = old_template.clone();

                        // Update the template with new specifications
                        if let Some(new_cpu) = ctx.cfg.new_cpu {
                            new_template.cpu = new_cpu;
                        }
                        if let Some(new_memory) = ctx.cfg.new_memory {
                            new_template.memory = new_memory;
                        }
                        if let Some(new_disk) = ctx.cfg.new_disk {
                            new_template.disk_size = new_disk;
                        }

                        if old_template.cpu > new_template.cpu {
                            op_fatal!("Cannot downgrade CPU");
                        }
                        if old_template.memory > new_template.memory {
                            op_fatal!("Cannot downgrade memory");
                        }
                        if old_template.disk_size > new_template.disk_size {
                            op_fatal!("Cannot downgrade disk size");
                        }

                        // Skip if no changes needed
                        if old_template.cpu == new_template.cpu
                            && old_template.memory == new_template.memory
                            && old_template.disk_size == new_template.disk_size
                        {
                            info!(
                                "Custom template {} for VM {} already has the requested specs, skipping template update",
                                custom_template_id, ctx.vm_id
                            );
                            return Ok(());
                        }

                        // Update the custom template in the database
                        ctx.db.update_custom_vm_template(&new_template).await?;

                        // Log the upgrade in VM history
                        let upgrade_metadata = serde_json::json!({
                            "upgrade_type": "custom_template_update",
                            "old_specs": {
                                "cpu": old_template.cpu,
                                "memory": old_template.memory,
                                "disk_size": old_template.disk_size
                            },
                            "new_specs": {
                                "cpu": new_template.cpu,
                                "memory": new_template.memory,
                                "disk_size": new_template.disk_size
                            }
                        });

                        if let Err(e) = ctx
                            .vm_history_logger
                            .log_vm_configuration_changed(
                                ctx.vm_id,
                                None, // System-initiated upgrade
                                &vm_before,
                                &vm_before, // VM record doesn't change, only the template
                                Some(upgrade_metadata),
                            )
                            .await
                        {
                            warn!("Failed to log VM upgrade history for VM {}: {}", ctx.vm_id, e);
                        }

                        info!(
                            "Successfully updated custom template {} for VM {}",
                            custom_template_id, ctx.vm_id
                        );
                    } else {
                        // VM uses standard template - convert to custom template
                        info!(
                            "VM {} uses standard template, converting to custom template",
                            ctx.vm_id
                        );
                        ctx.provisioner
                            .convert_to_custom_template(ctx.vm_id, &ctx.cfg)
                            .await?;

                        // Get the VM after conversion to see the changes
                        let vm_after = ctx.db.get_vm(ctx.vm_id).await?;

                        // Log the conversion in VM history
                        let upgrade_metadata = serde_json::json!({
                            "upgrade_type": "standard_to_custom_conversion",
                            "changes": {
                                "cpu": ctx.cfg.new_cpu,
                                "memory": ctx.cfg.new_memory,
                                "disk": ctx.cfg.new_disk
                            },
                            "converted_from_template_id": vm_before.template_id,
                            "new_custom_template_id": vm_after.custom_template_id
                        });

                        if let Err(e) = ctx
                            .vm_history_logger
                            .log_vm_configuration_changed(
                                ctx.vm_id,
                                None, // System-initiated upgrade
                                &vm_before,
                                &vm_after,
                                Some(upgrade_metadata),
                            )
                            .await
                        {
                            warn!("Failed to log VM upgrade history for VM {}: {}", ctx.vm_id, e);
                        }

                        info!("Successfully converted VM {} to custom template", ctx.vm_id);
                    }
                    Ok(())
                })
            })
            .step("stop_vm", |ctx| {
                Box::pin(async move {
                    let vm = ctx.db.get_vm(ctx.vm_id).await?;
                    let host = ctx.db.get_host(vm.host_id).await?;
                    let client = get_host_client(&host, &ctx.settings.provisioner_config)?;

                    info!("Stopping VM {} for upgrade", ctx.vm_id);
                    if let Err(e) = client.stop_vm(&vm).await {
                        // Ignore errors - VM might already be stopped
                        warn!("Failed to stop VM {} (may already be stopped): {}", ctx.vm_id, e);
                    }
                    Ok::<_, OpError<anyhow::Error>>(())
                })
            })
            .step("resize_disk", |ctx| {
                Box::pin(async move {
                    if ctx.cfg.new_disk.is_some() {
                        let full_info = FullVmInfo::load(ctx.vm_id, ctx.db.clone()).await?;
                        let host = ctx.db.get_host(full_info.host.id).await?;
                        let client = get_host_client(&host, &ctx.settings.provisioner_config)?;

                        info!("Resizing disk for VM {}", ctx.vm_id);
                        client.resize_disk(&full_info).await?;
                    }
                    Ok(())
                })
            })
            .step("configure_cpu_memory", |ctx| {
                Box::pin(async move {
                    if ctx.cfg.new_cpu.is_some() || ctx.cfg.new_memory.is_some() {
                        let full_info = FullVmInfo::load(ctx.vm_id, ctx.db.clone()).await?;
                        let host = ctx.db.get_host(full_info.host.id).await?;
                        let client = get_host_client(&host, &ctx.settings.provisioner_config)?;

                        info!("Updating CPU/memory configuration for VM {}", ctx.vm_id);
                        client.configure_vm(&full_info).await?;
                    }
                    Ok(())
                })
            })
            .step("start_vm", |ctx| {
                Box::pin(async move {
                    let vm = ctx.db.get_vm(ctx.vm_id).await?;
                    let host = ctx.db.get_host(vm.host_id).await?;
                    let client = get_host_client(&host, &ctx.settings.provisioner_config)?;

                    info!("Starting VM {} after upgrade", ctx.vm_id);
                    client.start_vm(&vm).await?;
                    Ok::<_, OpError<anyhow::Error>>(())
                })
            })
            .execute()
            .await?;

        self.queue_notification(
            self.db.get_vm(vm_id).await?.user_id,
            format!(
                "Your VM #{} has been successfully upgraded. The new specifications are now active.",
                vm_id
            ),
            Some(format!("[VM{}] Upgrade Complete", vm_id)),
        ).await;

        info!("Successfully completed upgrade for VM {}", vm_id);
        Ok(())
    }

    async fn configure_vm(&self, vm_id: u64, _admin_user_id: Option<u64>) -> Result<()> {
        info!(
            "Re-configuring VM {} using current database configuration",
            vm_id
        );

        let vm = self.db.get_vm(vm_id).await?;
        if vm.deleted {
            bail!("Cannot configure deleted VM {}", vm_id);
        }

        let full_info = FullVmInfo::load(vm_id, self.db.clone()).await?;
        let host = self.db.get_host(full_info.host.id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        client.configure_vm(&full_info).await?;

        info!(
            "Successfully re-configured VM {} using current database settings",
            vm_id
        );
        Ok(())
    }

    async fn assign_vm_ip(
        &self,
        vm_id: u64,
        ip_range_id: u64,
        ip: Option<String>,
        admin_user_id: Option<u64>,
    ) -> Result<()> {
        info!(
            "Assigning IP to VM {} from range {} using provisioner",
            vm_id, ip_range_id
        );

        // Validate VM exists and is not deleted
        let vm = self.db.get_vm(vm_id).await?;
        if vm.deleted {
            bail!("Cannot assign IP to a deleted VM");
        }

        // Determine the IP to assign
        let assigned_ip = if let Some(ip_str) = &ip {
            ip_str.trim().to_string()
        } else {
            // Auto-assign IP from the range
            let network_provisioner = NetworkProvisioner::new(self.db.clone());
            let available_ip = network_provisioner
                .pick_ip_from_range_id(ip_range_id)
                .await
                .context("Failed to auto-assign IP from range")?;
            available_ip.ip.ip().to_string()
        };

        // Create the assignment (similar to admin API but without saving yet)
        let mut assignment = VmIpAssignment {
            id: 0,
            vm_id,
            ip_range_id,
            ip: assigned_ip,
            deleted: false,
            arp_ref: None,
            dns_forward: None,
            dns_forward_ref: None,
            dns_reverse: None,
            dns_reverse_ref: None,
        };

        self.provisioner
            .network
            .save_ip_assignment(&mut assignment)
            .await?;

        // Log the assignment
        let metadata = if let Some(admin_id) = admin_user_id {
            Some(serde_json::json!({
                "admin_user_id": admin_id,
                "admin_action": true,
                "ip_range_id": ip_range_id,
                "assigned_ip": assignment.ip
            }))
        } else {
            Some(serde_json::json!({
                "admin_action": true,
                "ip_range_id": ip_range_id,
                "assigned_ip": assignment.ip
            }))
        };

        if let Err(e) = self
            .vm_history_logger
            .log_vm_configuration_changed(vm_id, admin_user_id, &vm, &vm, metadata)
            .await
        {
            warn!("Failed to log IP assignment for VM {}: {}", vm_id, e);
        }

        // Send ConfigureVm job to update VM network configuration
        self.work_commander
            .send(WorkJob::ConfigureVm {
                vm_id,
                admin_user_id,
            })
            .await?;

        info!(
            "Successfully assigned IP {} to VM {} from range {}",
            assignment.ip, vm_id, ip_range_id
        );

        Ok(())
    }

    async fn unassign_vm_ip(&self, assignment_id: u64, admin_user_id: Option<u64>) -> Result<()> {
        info!(
            "Unassigning IP assignment {} using provisioner",
            assignment_id
        );

        // Get the assignment to verify it exists and get VM info
        let mut assignment = self.db.get_vm_ip_assignment(assignment_id).await?;
        let range = self.db.get_ip_range(assignment.ip_range_id).await?;

        self.provisioner
            .network
            .delete_ip_assignment(&mut assignment, &range)
            .await?;

        // Log the unassignment
        let metadata = if let Some(admin_id) = admin_user_id {
            Some(serde_json::json!({
                "admin_user_id": admin_id,
                "admin_action": true,
                "unassigned_ip": assignment.ip,
                "ip_range_id": assignment.ip_range_id
            }))
        } else {
            Some(serde_json::json!({
                "admin_action": true,
                "unassigned_ip": assignment.ip,
                "ip_range_id": assignment.ip_range_id
            }))
        };

        let vm = self.db.get_vm(assignment.vm_id).await?;
        if let Err(e) = self
            .vm_history_logger
            .log_vm_configuration_changed(vm.id, admin_user_id, &vm, &vm, metadata)
            .await
        {
            warn!(
                "Failed to log IP unassignment for VM {}: {}",
                assignment.vm_id, e
            );
        }

        // Send ConfigureVm job to update VM network configuration
        self.work_commander
            .send(WorkJob::ConfigureVm {
                vm_id: vm.id,
                admin_user_id,
            })
            .await?;

        info!(
            "Successfully unassigned IP {} (assignment {}) from VM {}",
            assignment.ip, assignment_id, assignment.vm_id
        );
        Ok(())
    }

    async fn update_vm_ip(&self, assignment_id: u64, admin_user_id: Option<u64>) -> Result<()> {
        info!("Updating IP assignment {} using provisioner", assignment_id);

        // Get the assignment to verify it exists and get VM info
        let mut assignment = self.db.get_vm_ip_assignment(assignment_id).await?;
        let range = self.db.get_ip_range(assignment.ip_range_id).await?;

        self.provisioner
            .network
            .update_ip_assignment_policy(&mut assignment, &range)
            .await?;

        let vm = self.db.get_vm(assignment.vm_id).await?;
        if let Err(e) = self
            .vm_history_logger
            .log_vm_configuration_changed(vm.id, admin_user_id, &vm, &vm, None)
            .await
        {
            warn!(
                "Failed to log IP unassignment for VM {}: {}",
                assignment.vm_id, e
            );
        }

        // Send ConfigureVm job to update VM network configuration
        self.work_commander
            .send(WorkJob::ConfigureVm {
                vm_id: vm.id,
                admin_user_id,
            })
            .await?;

        info!(
            "Successfully unassigned IP {} (assignment {}) from VM {}",
            assignment.ip, assignment_id, assignment.vm_id
        );
        Ok(())
    }

    pub async fn handle(&self) -> Result<()> {
        loop {
            match self.work_commander.recv().await {
                Ok(jobs) => {
                    for msg in jobs {
                        self.handle_job(msg).await?;
                    }
                }
                Err(e) => {
                    error!("Failed to listen on commander channel: {}", e);
                }
            }
        }
    }

    async fn handle_job(&self, msg: WorkJobMessage) -> Result<()> {
        let job = &msg.job;
        let stream_id = &msg.id;
        let job_type = job.to_string();

        self.feedback
            .publish(JobFeedback::create_job_started_feedback(
                stream_id.clone(),
                job_type.clone(),
            ))
            .await?;

        // Execute the job
        let job_result = self.try_job(job).await;

        // Handle feedback based on result
        match job_result {
            Ok(desc) => {
                let feedback = JobFeedback::create_job_completed_feedback(
                    stream_id.to_string(),
                    job_type.clone(),
                    desc,
                );
                if let Err(e) = self.feedback.publish(feedback).await {
                    warn!("Failed to publish UpdateVmIp job feedback: {}", e);
                }
                if let Err(e) = self.work_commander.ack(&msg.id).await {
                    error!("Failed to acknowledge job {}: {}", stream_id, e);
                }
            }
            Err(ref e) => {
                error!("Failed to process Redis stream job: {:?} {}", job, e);
                let failed_feedback = JobFeedback::create_job_failed_feedback(
                    stream_id.clone(),
                    job_type.clone(),
                    e.to_string(),
                );
                if let Err(feedback_err) = self.feedback.publish(failed_feedback).await {
                    warn!(
                        "Failed to publish job failed feedback for {}: {}",
                        stream_id, feedback_err
                    );
                }
                // if job can be skipped, just acknowledge job
                if msg.job.can_skip()
                    && let Err(e) = self.work_commander.ack(&msg.id).await
                {
                    error!("Failed to acknowledge job {}: {}", stream_id, e);
                }
            }
        }
        Ok(())
    }
}
