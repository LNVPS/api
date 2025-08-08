use crate::host::{get_host_client, FullVmInfo};
use crate::provisioner::LNVpsProvisioner;
use crate::settings::{ProvisionerConfig, Settings, SmtpConfig};
use anyhow::{bail, Result};
use chrono::{DateTime, Datelike, Days, Utc};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{
    name_server::TokioConnectionProvider, system_conf, Resolver, TokioResolver,
};
use lettre::message::{MessageBuilder, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::AsyncTransport;
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use lnvps_api_common::{
    RedisConfig, VmHistoryLogger, VmRunningState, VmRunningStates, VmStateCache, WorkCommander,
    WorkJob,
};
use lnvps_db::{LNVpsDb, Vm, VmHost};
use log::{debug, error, info, warn};
use nostr::{EventBuilder, PublicKey, ToBech32};
use nostr_sdk::Client;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Primary background worker logic
/// Handles deleting expired VMs and sending notifications
pub struct Worker {
    settings: WorkerSettings,

    db: Arc<dyn LNVpsDb>,
    provisioner: Arc<LNVpsProvisioner>,
    nostr: Option<Client>,
    vm_history_logger: VmHistoryLogger,

    vm_state_cache: VmStateCache,
    tx: UnboundedSender<WorkJob>,
    rx: UnboundedReceiver<WorkJob>,
    work_commander: Option<WorkCommander>,
    last_check_vms: DateTime<Utc>,
}

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
    pub fn new(
        db: Arc<dyn LNVpsDb>,
        provisioner: Arc<LNVpsProvisioner>,
        settings: impl Into<WorkerSettings>,
        vm_state_cache: VmStateCache,
        nostr: Option<Client>,
    ) -> Result<Self> {
        let (tx, rx) = unbounded_channel();
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        let settings = settings.into();

        // Initialize WorkCommander if Redis is configured
        let work_commander = if let Some(redis_config) = &settings.redis {
            Some(WorkCommander::new(
                &redis_config.url,
                "workers",
                "api-worker",
            )?)
        } else {
            None
        };

        Ok(Self {
            db,
            provisioner,
            vm_state_cache,
            nostr,
            vm_history_logger,
            settings,
            tx,
            rx,
            work_commander,
            last_check_vms: Utc::now(),
        })
    }

    pub fn sender(&self) -> UnboundedSender<WorkJob> {
        self.tx.clone()
    }

    /// Handle VM state
    /// 1. Expire VM and send notification
    /// 2. Stop VM if expired and still running
    /// 3. Send notification for expiring soon
    async fn handle_vm_state(&self, vm: &Vm, state: &VmRunningState) -> Result<()> {
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
        if vm.expires < Utc::now() && state.state == VmRunningStates::Running {
            info!("Stopping expired VM {}", vm.id);
            if let Err(e) = self.provisioner.stop_vm(vm.id).await {
                warn!("Failed to stop VM {}: {}", vm.id, e);
            } else if let Err(e) = self.vm_history_logger.log_vm_expired(vm.id, None).await {
                warn!("Failed to log VM {} expiration: {}", vm.id, e);
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

            // Log VM deletion
            if let Err(e) = self
                .vm_history_logger
                .log_vm_deleted(vm.id, None, Some("expired and exceeded grace period"), None)
                .await
            {
                warn!("Failed to log VM {} deletion: {}", vm.id, e);
            }

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
        self.provisioner.spawn_vm(vm.id).await?;

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
        self.tx.send(WorkJob::SendNotification {
            user_id: vm.user_id,
            title: Some(format!("[VM{}] Created", vm.id)),
            message: format!("Your {}", &msg),
        })?;
        self.queue_admin_notification(msg, Some(format!("[VM{}] Created", vm.id)))?;
        Ok(())
    }

    pub async fn check_vms(&mut self) -> Result<()> {
        // check VM status from db vm list
        let db_vms = self.db.list_vms().await?;

        // Group VMs by host for bulk checking
        let mut vms_by_host: HashMap<u64, Vec<&Vm>> = HashMap::new();
        let mut vms_to_delete = Vec::new();

        for vm in &db_vms {
            let is_new_vm = vm.created == vm.expires;

            // only check spawned vms
            if !is_new_vm {
                vms_by_host
                    .entry(vm.host_id)
                    .or_insert_with(Vec::new)
                    .push(vm);
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
                if let Err(notification_err) = self.queue_admin_notification(
                    format!("Failed to delete unpaid VM {}:\n{}", vm.id, e),
                    Some(format!("VM {} Deletion Failed", vm.id)),
                ) {
                    error!("Failed to queue admin notification: {}", notification_err);
                }
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
                        if let Err(notification_err) = self.queue_admin_notification(
                            format!("Failed to check VM {}:\n{}", vm.id, e),
                            Some(format!("VM {} Check Failed", vm.id)),
                        ) {
                            error!("Failed to queue admin notification: {}", notification_err);
                        }
                    }
                }
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
                    .timeout(Some(Duration::from_secs(10)))
                    .build();

                sender.send(msg).await?;
            }
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
                c.send_event(&ev).await?;
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
        debug!("Checking IP resolution for {} vs {}", domain, expected_hostname);

        // Resolve our expected hostname to IP addresses
        let expected_ips = match resolver.lookup_ip(expected_hostname).await {
            Ok(ips) => {
                let ip_addrs: Vec<String> = ips.iter()
                    .map(|ip| ip.to_string())
                    .collect();
                debug!("Expected hostname {} resolves to IPs: {:?}", expected_hostname, ip_addrs);
                ip_addrs
            }
            Err(e) => {
                debug!("Failed to resolve expected hostname {} to IP: {}", expected_hostname, e);
                return Ok(false);
            }
        };

        // Resolve the domain to IP addresses (follows DNS records automatically)
        match resolver.lookup_ip(domain).await {
            Ok(domain_ips) => {
                let domain_ip_addrs: Vec<String> = domain_ips.iter()
                    .map(|ip| ip.to_string())
                    .collect();
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
            match self.check_domain_dns(&domain.name).await {
                Ok(has_dns_record) => {
                    // If domain is disabled but has DNS record, activate it
                    if !domain.enabled && has_dns_record {
                        info!(
                            "Domain {} has DNS record or matching A record pointing to {} - activating domain",
                            domain.name, expected_hostname
                        );

                        // Enable the domain in the database
                        match self.db.enable_domain(domain.id).await {
                            Ok(()) => {
                                info!("Successfully enabled domain {} (ID: {})", domain.name, domain.id);
                                domains_activated.push(&domain.name);

                                // Send notification to the domain owner
                                let notification_message = format!(
                                    "Your nostr domain '{}' has been automatically activated! \n\n\
                                    We detected that you've set up the required DNS record pointing to {}. \
                                    Your domain is now active and ready to use for nostr addresses.",
                                    domain.name, expected_hostname
                                );

                                if let Err(e) = self.tx.send(WorkJob::SendNotification {
                                    user_id: domain.owner_id,
                                    title: Some(format!("Nostr Domain '{}' Activated", domain.name)),
                                    message: notification_message,
                                }) {
                                    error!("Failed to queue user notification for domain {}: {}", domain.name, e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to enable domain {} (ID: {}): {}", domain.name, domain.id, e);
                                
                                // Send admin notification about the failure
                                if let Err(notification_err) = self.queue_admin_notification(
                                    format!("Failed to enable domain '{}' (ID: {}) despite DNS record being detected: {}", 
                                           domain.name, domain.id, e),
                                    Some(format!("Domain Activation Failed: {}", domain.name)),
                                ) {
                                    error!("Failed to queue admin notification: {}", notification_err);
                                }
                            }
                        }
                    }
                    // If domain is active but has no DNS record, deactivate it
                    else if domain.enabled && !has_dns_record {
                        info!(
                            "Domain {} no longer has DNS record or matching A record pointing to {} - deactivating domain",
                            domain.name, expected_hostname
                        );

                        // Disable the domain in the database
                        match self.db.disable_domain(domain.id).await {
                            Ok(()) => {
                                info!("Successfully disabled domain {} (ID: {})", domain.name, domain.id);
                                domains_deactivated.push(&domain.name);

                                // Send notification to the domain owner
                                let notification_message = format!(
                                    "Your nostr domain '{}' has been automatically deactivated. \n\n\
                                    We detected that the required DNS record pointing to {} is no longer configured. \
                                    To reactivate your domain, please ensure your DNS record is correctly set up.",
                                    domain.name, expected_hostname
                                );

                                if let Err(e) = self.tx.send(WorkJob::SendNotification {
                                    user_id: domain.owner_id,
                                    title: Some(format!("Nostr Domain '{}' Deactivated", domain.name)),
                                    message: notification_message,
                                }) {
                                    error!("Failed to queue user notification for domain {}: {}", domain.name, e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to disable domain {} (ID: {}): {}", domain.name, domain.id, e);
                                
                                // Send admin notification about the failure
                                if let Err(notification_err) = self.queue_admin_notification(
                                    format!("Failed to disable domain '{}' (ID: {}) despite missing DNS record: {}", 
                                           domain.name, domain.id, e),
                                    Some(format!("Domain Deactivation Failed: {}", domain.name)),
                                ) {
                                    error!("Failed to queue admin notification: {}", notification_err);
                                }
                            }
                        }
                    }
                    // Domain status matches DNS record status - no change needed
                    else if domain.enabled && has_dns_record {
                        debug!("Domain {} is correctly active with DNS record pointing to {}", domain.name, expected_hostname);
                    } else if !domain.enabled && !has_dns_record {
                        debug!("Domain {} is correctly inactive without DNS record pointing to {}", domain.name, expected_hostname);
                        
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
                                    info!("Successfully deleted domain {} (ID: {})", domain.name, domain.id);
                                    domains_deleted.push(&domain.name);

                                    // Send notification to the domain owner
                                    let notification_message = format!(
                                        "Your nostr domain '{}' has been permanently deleted. \n\n\
                                        The domain was disabled for more than 1 week without the required DNS record. \
                                        If you wish to use this domain again, you will need to register it again.",
                                        domain.name
                                    );

                                    if let Err(e) = self.tx.send(WorkJob::SendNotification {
                                        user_id: domain.owner_id,
                                        title: Some(format!("Nostr Domain '{}' Deleted", domain.name)),
                                        message: notification_message,
                                    }) {
                                        error!("Failed to queue user notification for deleted domain {}: {}", domain.name, e);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to delete domain {} (ID: {}): {}", domain.name, domain.id, e);
                                    
                                    // Send admin notification about the failure
                                    if let Err(notification_err) = self.queue_admin_notification(
                                        format!("Failed to delete old disabled domain '{}' (ID: {}) that was disabled since {}: {}", 
                                               domain.name, domain.id, domain.last_status_change, e),
                                        Some(format!("Domain Deletion Failed: {}", domain.name)),
                                    ) {
                                        error!("Failed to queue admin notification: {}", notification_err);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to check DNS record for domain {}: {}", domain.name, e);
                }
            }
        }

        // Send single admin notification with summary of all changes
        if !domains_activated.is_empty() || !domains_deactivated.is_empty() || !domains_deleted.is_empty() {
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
            self.queue_admin_notification(
                message,
                Some("Nostr Domains Status Update".to_string()),
            )?;
        } else {
            info!("No nostr domain changes required - all domains have correct DNS configuration and no old disabled domains to delete");
        }

        Ok(())
    }

    async fn try_job(&mut self, job: &WorkJob) -> Result<()> {
        match job {
            WorkJob::PatchHosts => {
                let mut hosts = self.db.list_hosts().await?;
                for host in &mut hosts {
                    info!("Patching host {}", host.name);
                    if let Err(e) = self.patch_host(host).await {
                        error!("Failed to patch host {}: {}", host.name, e);
                    }
                }
            }
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
                    // queue again for sending
                    self.queue_notification(*user_id, message.clone(), title.clone())?;
                }
            }
            WorkJob::CheckVms => {
                if let Err(e) = self.check_vms().await {
                    error!("Failed to check VMs: {}", e);
                    self.queue_admin_notification(
                        format!("Failed to check VMs:\n{:?}\n{}", &job, e),
                        Some("CheckVms Job Failed".to_string()),
                    )?
                }
            }
            WorkJob::DeleteVm {
                vm_id,
                reason,
                admin_user_id,
            } => {
                info!("Processing admin delete request for VM {}", vm_id);

                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    info!("VM {} is already marked as deleted", vm_id);
                    return Ok(());
                }

                // Delete the VM via provisioner
                if let Err(e) = self.provisioner.delete_vm(*vm_id).await {
                    error!("Failed to delete VM {} via provisioner: {}", vm_id, e);
                    self.queue_admin_notification(
                        format!("Failed to delete VM {} via provisioner:\n{}", vm_id, e),
                        Some(format!("VM {} Deletion Failed", vm_id)),
                    )?;
                    return Err(e);
                }

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

                if let Err(e) = self
                    .vm_history_logger
                    .log_vm_deleted(*vm_id, *admin_user_id, reason.as_deref(), metadata)
                    .await
                {
                    warn!("Failed to log VM {} deletion: {}", vm_id, e);
                }

                // Send notifications
                let reason_text = reason.as_deref().unwrap_or("Admin requested deletion");
                let title = Some(format!("[VM{}] Deleted by Admin", vm_id));

                // Notify user
                self.tx.send(WorkJob::SendNotification {
                    user_id: vm.user_id,
                    title: title.clone(),
                    message: format!(
                        "Your VM #{} has been deleted by an administrator.\nReason: {}",
                        vm_id, reason_text
                    ),
                })?;

                // Notify admin
                self.queue_admin_notification(
                    format!(
                        "VM {} has been successfully deleted.\nUser ID: {}\nReason: {}",
                        vm_id, vm.user_id, reason_text
                    ),
                    title,
                )?;

                info!("Successfully deleted VM {} at admin request", vm_id);
            }
            WorkJob::StartVm {
                vm_id,
                admin_user_id,
            } => {
                info!("Processing admin start request for VM {}", vm_id);

                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    error!("Cannot start deleted VM {}", vm_id);
                    return Ok(());
                }

                // Check if VM is expired
                if vm.expires < Utc::now() {
                    warn!("Attempting to start expired VM {}", vm_id);
                    // Send notification to admin about the expired VM
                    self.queue_admin_notification(
                        format!(
                            "Cannot start VM {} - it has expired (expires: {})",
                            vm_id, vm.expires
                        ),
                        Some(format!("VM {} Start Failed - Expired", vm_id)),
                    )?;
                    return Ok(());
                }

                // Start the VM via provisioner
                if let Err(e) = self.provisioner.start_vm(*vm_id).await {
                    error!("Failed to start VM {} via provisioner: {}", vm_id, e);
                    self.queue_admin_notification(
                        format!("Failed to start VM {} via provisioner:\n{}", vm_id, e),
                        Some(format!("VM {} Start Failed", vm_id)),
                    )?;
                    return Err(e);
                }

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

                if let Err(e) = self
                    .vm_history_logger
                    .log_vm_started(*vm_id, *admin_user_id, metadata)
                    .await
                {
                    warn!("Failed to log VM {} start: {}", vm_id, e);
                }

                let title = Some(format!("[VM{}] Started by Admin", vm_id));

                // Notify user
                self.tx.send(WorkJob::SendNotification {
                    user_id: vm.user_id,
                    title: title.clone(),
                    message: format!("Your VM #{} has been started by an administrator.", vm_id),
                })?;

                // Notify admin
                self.queue_admin_notification(
                    format!(
                        "VM {} has been successfully started.\nUser ID: {}",
                        vm_id, vm.user_id
                    ),
                    title,
                )?;

                info!("Successfully started VM {} at admin request", vm_id);
            }
            WorkJob::StopVm {
                vm_id,
                admin_user_id,
            } => {
                info!("Processing admin stop request for VM {}", vm_id);

                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    error!("Cannot stop deleted VM {}", vm_id);
                    return Ok(());
                }

                // Stop the VM via provisioner
                if let Err(e) = self.provisioner.stop_vm(*vm_id).await {
                    error!("Failed to stop VM {} via provisioner: {}", vm_id, e);
                    self.queue_admin_notification(
                        format!("Failed to stop VM {} via provisioner:\n{}", vm_id, e),
                        Some(format!("VM {} Stop Failed", vm_id)),
                    )?;
                    return Err(e);
                }

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

                if let Err(e) = self
                    .vm_history_logger
                    .log_vm_stopped(*vm_id, *admin_user_id, metadata)
                    .await
                {
                    warn!("Failed to log VM {} stop: {}", vm_id, e);
                }

                let title = Some(format!("[VM{}] Stopped by Admin", vm_id));

                // Notify user
                self.tx.send(WorkJob::SendNotification {
                    user_id: vm.user_id,
                    title: title.clone(),
                    message: format!("Your VM #{} has been stopped by an administrator.", vm_id),
                })?;

                // Notify admin
                self.queue_admin_notification(
                    format!(
                        "VM {} has been successfully stopped.\nUser ID: {}",
                        vm_id, vm.user_id
                    ),
                    title,
                )?;

                info!("Successfully stopped VM {} at admin request", vm_id);
            }
            WorkJob::CheckNostrDomains => {
                info!("Processing check nostr domains job");
                if let Err(e) = self.check_nostr_domains().await {
                    error!("Failed to check nostr domains: {}", e);
                    self.queue_admin_notification(
                        format!("Failed to check nostr domains:\n{}", e),
                        Some("Nostr Domains Check Failed".to_string()),
                    )?
                }
            }
        }
        Ok(())
    }

    pub async fn handle(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                // Handle local channel jobs
                job = self.rx.recv() => {
                    if let Some(job) = job {
                        if let Err(e) = self.try_job(&job).await {
                            error!("Job failed to execute: {:?} {}", job, e);
                        }
                    }
                }
                // Handle Redis stream jobs (only if Redis is configured)
                redis_result = async {
                    self.work_commander.as_ref().unwrap().listen_for_jobs().await
                }, if self.work_commander.is_some() => {
                    match redis_result {
                        Ok(jobs) => {
                            for (stream_id, job) in jobs {
                                if let Err(e) = self.try_job(&job).await {
                                    error!("Failed to process Redis stream job: {:?} {}", job, e);
                                }

                                // Always try to acknowledge the job
                                if let Err(e) = self.work_commander.as_ref().unwrap().acknowledge_job(&stream_id).await {
                                    error!("Failed to acknowledge job {}: {}", stream_id, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to listen for Redis stream jobs: {}", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }
}
