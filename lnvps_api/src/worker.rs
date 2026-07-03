use crate::host::{FullVmInfo, VmHostClient, get_host_client};
use crate::notifications::{
    Notification, NotificationChannel, build_channels, send_email,
};
use crate::provisioner::VmProvisioner;
use crate::settings::{ProvisionerConfig, Settings, SmtpConfig, TelegramConfig, WhatsAppConfig};
use crate::ssh_client::SshClient;
use crate::subscription::SubscriptionHandler;
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Days, TimeDelta, Utc};
use hickory_resolver::TokioResolver;
use lnvps_api_common::{
    BlackholeWorkFeedback, ChannelWorkCommander, InMemoryKeyValueStore, JobFeedback, KeyValueStore,
    NetworkProvisioner, RedisConfig, RedisKeyValueStore, RedisWorkCommander, RedisWorkFeedback,
    UpgradeConfig, VmHistoryLogger, VmRunningState, VmStateCache, WorkCommander, WorkFeedback,
    WorkJob, WorkJobMessage, op_fatal,
    retry::{OpError, Pipeline, RetryPolicy},
};
use lnvps_db::{
    CpuArch, CpuFeature, CpuMfg, IntervalType, LNVpsDb, RouterTunnelTraffic, Subscription,
    SubscriptionLineItem, SubscriptionType, Vm, VmHistoryActionType, VmHost, VmHostKind,
    VmIpAssignment, VmOsImage,
};
use log::{debug, error, info, warn};
use nostr_sdk::{Client, PublicKey, ToBech32};
use payments_rs::currency::{Currency, CurrencyAmount};
use serde::Deserialize;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// Name of the host-info binary for x86_64 (expected in same directory as current executable)
const HOST_INFO_BINARY_NAME_X86_64: &str = "lnvps-host-info";
/// Name of the host-info binary for arm64 (expected in same directory as current executable)
const HOST_INFO_BINARY_NAME_ARM64: &str = "lnvps-host-info-arm64";
/// Remote path where the binary will be uploaded and executed on hosts
const HOST_INFO_REMOTE_PATH: &str = "/tmp/lnvps-host-info";

/// Get the path to the host-info binary for x86_64 (in same directory as current executable)
fn get_host_info_path() -> Option<std::path::PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let exe_dir = current_exe.parent()?;
    Some(exe_dir.join(HOST_INFO_BINARY_NAME_X86_64))
}

/// Get the path to the host-info binary for the specified architecture
fn get_host_info_path_for_arch(arch: CpuArch) -> Option<std::path::PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let exe_dir = current_exe.parent()?;
    let binary_name = match arch {
        CpuArch::ARM64 => HOST_INFO_BINARY_NAME_ARM64,
        _ => HOST_INFO_BINARY_NAME_X86_64, // Default to x86_64
    };
    Some(exe_dir.join(binary_name))
}

/// Extract hostname/IP from a URL or return the input if it's already a plain host
/// e.g. "https://192.168.1.1:8006/" -> "192.168.1.1"
///      "192.168.1.1" -> "192.168.1.1"
pub(crate) fn extract_host_from_url(input: &str) -> String {
    // Strip protocol prefix if present
    let without_protocol = input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))
        .unwrap_or(input);

    // Take everything before the first ':' or '/' (to strip port and path)
    without_protocol
        .split(|c| c == ':' || c == '/')
        .next()
        .unwrap_or(input)
        .to_string()
}

/// Host info output from lnvps-host-info utility
#[derive(Debug, Deserialize)]
struct HostInfoOutput {
    cpu_mfg: String,
    cpu_arch: String,
    cpu_features: Vec<String>,
    #[allow(dead_code)]
    cpu_model: Option<String>,
    #[allow(dead_code)]
    gpu_mfg: String,
    #[allow(dead_code)]
    gpu_model: Option<String>,
    #[allow(dead_code)]
    gpu_features: Vec<String>,
}

/// Primary background worker logic
/// Handles deleting expired VMs and sending notifications
#[derive(Clone)]
pub struct Worker {
    settings: WorkerSettings,
    db: Arc<dyn LNVpsDb>,
    subscription_handler: SubscriptionHandler,
    notification_channels: Vec<Arc<dyn NotificationChannel>>,
    vm_history_logger: VmHistoryLogger,
    vm_state_cache: VmStateCache,
    work_commander: Arc<dyn WorkCommander>,
    feedback: Arc<dyn WorkFeedback>,
    kv: Arc<dyn KeyValueStore>,
    http_client: reqwest::Client,
}

#[derive(Clone)]
pub struct WorkerSettings {
    pub delete_after: u16,
    pub smtp: Option<SmtpConfig>,
    pub telegram: Option<TelegramConfig>,
    pub whatsapp: Option<WhatsAppConfig>,
    pub provisioner_config: ProvisionerConfig,
    pub redis: Option<RedisConfig>,
    pub nostr_hostname: Option<String>,
}

impl From<&Settings> for WorkerSettings {
    fn from(val: &Settings) -> Self {
        WorkerSettings {
            delete_after: val.delete_after,
            smtp: val.smtp.clone(),
            telegram: val.telegram.clone(),
            whatsapp: val.whatsapp.clone(),
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
        work_commander: Arc<dyn WorkCommander>,
        subscription_handler: SubscriptionHandler,
        settings: impl Into<WorkerSettings>,
        vm_state_cache: VmStateCache,
        nostr: Option<Client>,
    ) -> Result<Self> {
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        let settings = settings.into();

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
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let notification_channels = build_channels(&settings, nostr.as_ref(), &http_client);

        Ok(Self {
            db,
            subscription_handler,
            vm_state_cache,
            notification_channels,
            kv,
            feedback,
            vm_history_logger,
            settings,
            work_commander,
            http_client,
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

    pub async fn get_last_check_subscriptions(&self) -> Result<DateTime<Utc>> {
        let Some(v) = self.kv.get("worker-last-check-subscriptions").await? else {
            return Ok(DateTime::UNIX_EPOCH);
        };
        let timestamp = if v.len() == 8 {
            u64::from_le_bytes(v.as_slice().try_into()?)
        } else {
            0
        };
        Ok(DateTime::from_timestamp(timestamp as _, 0).unwrap())
    }

    pub async fn set_last_check_subscriptions(&self, ts: DateTime<Utc>) -> Result<()> {
        let t = ts.timestamp() as u64;
        self.kv
            .store("worker-last-check-subscriptions", &t.to_le_bytes())
            .await?;
        Ok(())
    }

    /// Handle subscription lifecycle state by dispatching to per-line-item handlers.
    /// 1. Expiring soon: attempt NWC auto-renewal; notify user; call on_expiring_soon per line item
    /// 2. Expired: call on_expired per line item
    /// 3. Grace period exceeded: notify user; call on_grace_period_exceeded per line item
    async fn handle_subscription_state(
        &self,
        sub: &Subscription,
        last_check: DateTime<Utc>,
    ) -> Result<()> {
        const BEFORE_EXPIRE_NOTIFICATION_DAYS: u64 = 1;
        let Some(expires) = sub.expires else {
            return Ok(());
        };

        let line_items = self.db.list_subscription_line_items(sub.id).await?;
        let sub_notification_subject = self.sub_notification_subject(sub, &line_items).await;
        let sub_notification_descr = Self::sub_notification_message(sub, &line_items);

        // --- Expiring soon ---
        // Only subscriptions that have NOT yet expired can be "expiring soon".
        // The `expires > now` guard is important: without it, an already-expired
        // subscription would wrongly match this branch whenever `last_check` is
        // stale (e.g. a freshly-started worker whose last check defaults to the
        // unix epoch), starving the expired/grace branches below.
        let now = Utc::now();
        let expiry_window = now.add(Days::new(BEFORE_EXPIRE_NOTIFICATION_DAYS));
        if expires > now
            && expires < expiry_window
            && expires > last_check.add(Days::new(BEFORE_EXPIRE_NOTIFICATION_DAYS))
        {
            // Track whether NWC auto-renewal was attempted and succeeded (so we skip the
            // generic "expiring soon" notification below).
            let mut auto_renewed = false;

            #[cfg(feature = "nostr-nwc")]
            if sub.auto_renewal_enabled {
                let user = self.db.get_user(sub.user_id).await?;
                if let Some(ref nwc_connection) = user.nwc_connection_string {
                    let nwc_string: String = nwc_connection.clone().into();
                    if !nwc_string.is_empty() {
                        info!(
                            "Attempting auto-renewal for subscription {} via NWC",
                            sub.id
                        );
                        match self
                            .subscription_handler
                            .auto_renew_via_nwc(sub.id, &nwc_string)
                            .await
                        {
                            Ok(_) => {
                                info!("Successfully auto-renewed subscription {} via NWC", sub.id);
                                self.queue_notification(
                                    sub.user_id,
                                    format!("Your subscription has been automatically renewed via Nostr Wallet Connect.\n{}", sub_notification_descr),
                                    Some(format!("[{}] Auto-Renewed", sub_notification_subject)),
                                ).await;
                                auto_renewed = true;
                            }
                            Err(e) => {
                                warn!("Auto-renewal error for subscription {}: {}", sub.id, e);
                                self.queue_notification(
                                    sub.user_id,
                                    format!(
                                        "Your subscription will expire soon.\nAutomatic renewal failed: '{}'\nPlease renew manually in the next {} day(s).\n{}",
                                        e, BEFORE_EXPIRE_NOTIFICATION_DAYS, sub_notification_descr
                                    ),
                                    Some(format!("[{}] Expiring Soon", sub_notification_subject)),
                                )
                                    .await;
                                auto_renewed = true;
                            }
                        }
                    }
                }
            }

            // Send a plain expiry warning whenever NWC auto-renewal was not attempted
            // (feature disabled, auto_renewal off, or no NWC string configured).
            if !auto_renewed {
                self.queue_notification(
                    sub.user_id,
                    format!(
                        "Your subscription will expire soon. Please renew manually in the next {} day(s).\n{}",
                        BEFORE_EXPIRE_NOTIFICATION_DAYS, sub_notification_descr
                    ),
                    Some(format!("[{}] Expiring Soon", sub_notification_subject)),
                )
                .await;
            }
        } else if expires.add(Days::new(self.grace_period_days(sub) as u64)) < Utc::now() {
            // mark subscription as not-active
            let mut sub = sub.clone();
            sub.is_active = false;
            self.db.update_subscription(&sub).await?;

            self.queue_notification(
                sub.user_id,
                format!(
                    "Your subscription has been cancelled.\n{}",
                    sub_notification_descr
                ),
                Some(format!("[{}] Cancelled", sub_notification_subject)),
            )
            .await;
            for li in &line_items {
                match self.subscription_handler.make_line_item_handler(li).await {
                    Ok(h) => {
                        if let Err(e) = h.on_grace_period_exceeded(&sub, li).await {
                            warn!(
                                "on_grace_period_exceeded failed for line item {}: {}",
                                li.id, e
                            );
                        }
                    }
                    Err(e) => warn!("Failed to build handler for line item {}: {}", li.id, e),
                }
            }
        } else if expires < Utc::now() {
            // Subscription is expired but still within the grace window. Fire the
            // "expired" handling exactly once.
            //
            // For a real-time crossing this is the first check after `expires`
            // (`expires >= last_check`). For subscriptions that expired *before*
            // `last_check` — retroactive/admin expiry, clock changes, or worker
            // downtime — the simple `expires >= last_check` edge guard would never
            // fire, leaving the VM running until the grace period elapsed. We instead
            // detect whether the expiry was already handled (via VM history) so we act
            // once rather than re-stopping/re-notifying every CheckSubscriptions cycle.
            let already_handled = self
                .subscription_expiry_already_handled(sub, &line_items, last_check)
                .await;
            if !already_handled {
                self.queue_notification(
                    sub.user_id,
                    format!("Your subscription has expired.\n{}", sub_notification_descr),
                    Some(format!("[{}] Expired", sub_notification_subject)),
                )
                .await;
                for li in &line_items {
                    match self.subscription_handler.make_line_item_handler(li).await {
                        Ok(h) => {
                            if let Err(e) = h.on_expired(sub, li).await {
                                warn!("on_expired failed for line item {}: {}", li.id, e);
                            }
                        }
                        Err(e) => warn!("Failed to build handler for line item {}: {}", li.id, e),
                    }
                }
            }
        }

        Ok(())
    }

/// Grace period (days) for a subscription, tiered by how long the subscription
/// has existed (age-based). Newer subscriptions get shorter grace windows so
/// resources aren't held open for days after a brand-new VM expires.
///
/// | Age (days) | Grace (days) |
/// |------------|---------------|
/// | ≤ 1        | 1             |
/// | ≤ 7        | 2             |
/// | ≤ 28       | 7             |
/// | ≤ 180      | 14            |
/// | > 180      | delete_after  |
pub fn grace_period_days_for_sub(sub: &Subscription, now: DateTime<Utc>, delete_after: u16) -> u16 {
    let age_days = (now - sub.created).num_days().max(0);
    if age_days <= 1 {
        1
    } else if age_days <= 7 {
        2
    } else if age_days <= 28 {
        7
    } else if age_days <= 180 {
        14
    } else {
        delete_after
    }
}

    /// Grace period (in days) for a subscription, tiered by subscription age.
    /// Newer subscriptions get shorter grace windows so resources aren't held open
    /// for days after a brand-new VM expires.
    ///
    /// | Age (days) | Grace (days) |
    /// |------------|---------------|
    /// | ≤ 1        | 1             |
    /// | ≤ 7        | 2             |
    /// | ≤ 28       | 7             |
    /// | ≤ 180      | 14            |
    /// | > 180      | delete_after  |
    fn grace_period_days(&self, sub: &Subscription) -> u16 {
        grace_period_days_for_sub(sub, Utc::now(), self.settings.delete_after)
    }

    /// Whether the one-shot "expired" handling for `sub` has already run.
    ///
    /// VPS line items are authoritative: a VM-history `Expired` entry recorded at
    /// or after the subscription's `expires` means we already stopped/notified, so
    /// the worker must not fire again. For subscriptions without a VPS line item we
    /// fall back to the edge-trigger semantics (`expires < last_check` ⇒ a previous
    /// cycle handled it) since there is no VM history to consult.
    async fn subscription_expiry_already_handled(
        &self,
        sub: &Subscription,
        line_items: &[SubscriptionLineItem],
        last_check: DateTime<Utc>,
    ) -> bool {
        let Some(expires) = sub.expires else {
            return true;
        };
        let mut has_vps = false;
        for li in line_items {
            if li.subscription_type != SubscriptionType::Vps {
                continue;
            }
            has_vps = true;
            let Ok(vm) = self.db.get_vm_by_line_item(li.id).await else {
                continue;
            };
            if let Ok(history) = self.db.list_vm_history(vm.id).await
                && history.iter().any(|h| {
                    matches!(h.action_type, VmHistoryActionType::Expired) && h.timestamp >= expires
                })
            {
                return true;
            }
        }
        if has_vps {
            // VPS line item(s) present but no Expired entry yet — not handled.
            false
        } else {
            // No VM history to consult; approximate prior handling with the edge guard.
            expires < last_check
        }
    }

    /// Get the subscription notification subject line
    async fn sub_notification_subject(
        &self,
        sub: &Subscription,
        line_items: &Vec<SubscriptionLineItem>,
    ) -> String {
        if line_items
            .iter()
            .all(|l| l.subscription_type == SubscriptionType::Vps)
        {
            if let Ok(vm) = self.db.get_vm_by_subscription(sub.id).await {
                return format!("VM{}", vm.id);
            }
        }
        format!("Sub #{}", sub.id)
    }

    /// Get the subscription notification message body, describe the line items / services
    fn sub_notification_message(
        sub: &Subscription,
        line_items: &Vec<SubscriptionLineItem>,
    ) -> String {
        let interval_str = match sub.interval_type {
            IntervalType::Day => {
                if sub.interval_amount == 1 {
                    "per day".to_string()
                } else {
                    format!("every {} days", sub.interval_amount)
                }
            }
            IntervalType::Month => {
                if sub.interval_amount == 1 {
                    "per month".to_string()
                } else {
                    format!("every {} months", sub.interval_amount)
                }
            }
            IntervalType::Year => {
                if sub.interval_amount == 1 {
                    "per year".to_string()
                } else {
                    format!("every {} years", sub.interval_amount)
                }
            }
        };

        let mut msg = format!("Subscription: {}\n\nServices:\n", sub.name);

        for li in line_items {
            let formatted_amount = if let Ok(cur) = Currency::from_str(&sub.currency) {
                CurrencyAmount::from_u64(cur, li.amount).to_string()
            } else {
                li.amount.to_string()
            };

            let formatted_setup_amount = if let Ok(cur) = Currency::from_str(&sub.currency) {
                CurrencyAmount::from_u64(cur, li.setup_amount).to_string()
            } else {
                li.amount.to_string()
            };

            msg.push_str(&format!(
                "- {} — {} {}",
                li.name, formatted_amount, interval_str
            ));
            if li.setup_amount > 0 {
                msg.push_str(&format!(" + {} setup fee", formatted_setup_amount));
            }
            msg.push('\n');
            if let Some(ref desc) = li.description {
                msg.push_str(&format!("  {}\n", desc));
            }
        }

        if let Some(ref desc) = sub.description {
            msg.push_str(&format!("\nNote: {}\n", desc));
        }

        msg
    }

    /// Poll every enabled router to refresh cached tunnel/BGP session/route state
    /// and record per-tunnel traffic samples.
    ///
    /// Only tunnel traffic counters are sampled into the time-series table; BGP
    /// sessions and routes are refreshed as cached state (no byte counters exist
    /// for BGP). All route/tunnel queries used here are bounded and full-table safe.
    pub async fn sync_router_state(&self) -> Result<()> {
        let routers = self.db.list_routers().await?;
        for router in routers.iter().filter(|r| r.enabled) {
            if let Err(e) = self.sync_one_router(router.id).await {
                error!("Failed to sync router {}: {}", router.id, e);
            }
        }
        Ok(())
    }

    async fn sync_one_router(&self, router_id: u64) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;

        // Tunnels: refresh cached inventory and record traffic samples
        if let Some(tr) = router.tunnel() {
            match tr.list_tunnels().await {
                Ok(tunnels) => {
                    for t in &tunnels {
                        if let Err(e) = self.db.upsert_router_tunnel(&t.to_db(router_id)).await {
                            warn!(
                                "Failed to cache tunnel {} on router {}: {}",
                                t.name, router_id, e
                            );
                        }
                    }
                }
                Err(e) => warn!("Failed to list tunnels on router {}: {}", router_id, e),
            }
            match tr.tunnel_traffic().await {
                Ok(traffic) => {
                    for tt in traffic {
                        let sample = RouterTunnelTraffic {
                            id: 0,
                            router_id,
                            tunnel_name: tt.name,
                            rx_bytes: tt.rx_bytes,
                            tx_bytes: tt.tx_bytes,
                            sampled_at: Utc::now(),
                        };
                        if let Err(e) = self.db.insert_router_tunnel_traffic(&sample).await {
                            warn!("Failed to record traffic on router {}: {}", router_id, e);
                        }
                    }
                }
                Err(e) => warn!(
                    "Failed to read tunnel traffic on router {}: {}",
                    router_id, e
                ),
            }
        }

        // BGP: refresh cached session state (no traffic counters)
        if let Some(bgp) = router.bgp() {
            match bgp.list_sessions().await {
                Ok(sessions) => {
                    for s in &sessions {
                        if let Err(e) = self.db.upsert_router_bgp_session(&s.to_db(router_id)).await
                        {
                            warn!(
                                "Failed to cache BGP session {} on router {}: {}",
                                s.name, router_id, e
                            );
                        }
                    }
                }
                Err(e) => warn!("Failed to list BGP sessions on router {}: {}", router_id, e),
            }

            // Routes: refresh the cached route table (locally-originated prefixes
            // plus a detected default route). Passing an empty candidate set returns
            // all locally-originated prefixes, which is inherently small. The whole
            // snapshot is replaced atomically, so multiple routes to the same prefix
            // (ECMP / differing next-hops) are preserved.
            //
            // Only refresh the cache when the originated-routes query succeeds, so a
            // transient failure does not wipe the cached snapshot.
            match bgp.originated_routes(&[]).await {
                Ok(originated) => {
                    let mut routes: Vec<_> = originated
                        .iter()
                        .map(|r| r.to_db(router_id, false))
                        .collect();
                    match bgp.default_routes().await {
                        Ok(default_routes) => {
                            routes.extend(default_routes.iter().map(|r| r.to_db(router_id, true)))
                        }
                        Err(e) => warn!(
                            "Failed to detect default route on router {}: {}",
                            router_id, e
                        ),
                    }
                    if let Err(e) = self.db.replace_router_bgp_routes(router_id, &routes).await {
                        warn!("Failed to cache routes on router {}: {}", router_id, e);
                    }
                }
                Err(e) => warn!(
                    "Failed to list originated routes on router {}: {}",
                    router_id, e
                ),
            }
        }

        Ok(())
    }

    /// Enable/disable a BGP session on a router and refresh its cached state.
    pub async fn toggle_bgp_session(
        &self,
        router_id: u64,
        session_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;
        let bgp = router.bgp().context("router does not support BGP")?;
        bgp.set_session_enabled(session_id, enabled)
            .await
            .map_err(|e| anyhow!("failed to toggle BGP session: {}", e))?;
        // Refresh cached session state so the admin API reflects the change.
        // The upsert only sets `enabled` on first import; for existing rows the
        // database flag is authoritative, so persist the requested value here.
        //
        // The cache is keyed by session *name*, but `session_id` is the backend
        // id (the BIRD protocol name or RouterOS `.id`) — these differ on
        // Mikrotik. Resolve the cache key from the listing so the persist targets
        // the right row; fall back to `session_id` when the session can't be
        // found (on BIRD the id equals the name).
        let mut cache_name: Option<String> = None;
        if let Ok(sessions) = bgp.list_sessions().await {
            for s in &sessions {
                if s.id == session_id {
                    cache_name = Some(s.name.clone());
                }
                if let Err(e) = self.db.upsert_router_bgp_session(&s.to_db(router_id)).await {
                    warn!("Failed to refresh BGP session cache: {}", e);
                }
            }
        }
        let cache_name = cache_name.as_deref().unwrap_or(session_id);
        self.db
            .set_router_bgp_session_enabled(router_id, cache_name, enabled)
            .await
            .map_err(|e| anyhow!("failed to persist BGP session enabled flag: {}", e))?;
        Ok(())
    }

    /// Enable/disable a tunnel on a router and refresh its cached state.
    pub async fn toggle_tunnel(&self, router_id: u64, name: &str, enabled: bool) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;
        // The admin API addresses tunnels by name (the cache key), but the backend
        // toggles by its own id (interface name on Linux, `<kind>:<.id>` on
        // Mikrotik). Resolve the id from the live listing.
        let tunnels = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?;
        let target = tunnels
            .iter()
            .find(|t| t.name == name)
            .context("tunnel not found")?;
        let id = target.id.as_deref().unwrap_or(name);
        tr.set_tunnel_enabled(id, enabled)
            .await
            .map_err(|e| anyhow!("failed to toggle tunnel: {}", e))?;
        // Refresh the cached inventory so the admin API reflects the new state.
        // The tunnel `enabled` flag is discovery-authoritative (the interface
        // up/down state), so re-listing after the change is sufficient.
        if let Ok(tunnels) = tr.list_tunnels().await {
            for t in &tunnels {
                if let Err(e) = self.db.upsert_router_tunnel(&t.to_db(router_id)).await {
                    warn!("Failed to refresh tunnel cache: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Install or replace the static default route on a router, then refresh the
    /// cached route table so the admin API reflects the change.
    pub async fn set_router_default_route(&self, router_id: u64, next_hop: &str) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;
        let bgp = router.bgp().context("router does not support BGP")?;
        bgp.set_default_route(next_hop)
            .await
            .map_err(|e| anyhow!("failed to set default route: {}", e))?;
        if let Err(e) = self.sync_one_router(router_id).await {
            warn!(
                "Failed to refresh router {} state after set: {}",
                router_id, e
            );
        }
        Ok(())
    }

    /// Remove the static default route(s) from a router, then refresh the cached
    /// route table so the admin API reflects the change.
    pub async fn clear_router_default_route(&self, router_id: u64) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;
        let bgp = router.bgp().context("router does not support BGP")?;
        bgp.clear_default_route()
            .await
            .map_err(|e| anyhow!("failed to clear default route: {}", e))?;
        if let Err(e) = self.sync_one_router(router_id).await {
            warn!(
                "Failed to refresh router {} state after clear: {}",
                router_id, e
            );
        }
        Ok(())
    }

    pub async fn check_subscriptions(&self) -> Result<()> {
        let last_check = self.get_last_check_subscriptions().await?;
        let time_since = Utc::now().signed_duration_since(last_check);
        if time_since.num_seconds() < Self::CHECK_VMS_SECONDS as i64 {
            debug!(
                "Skipping CheckSubscriptions - only {}s since last check",
                time_since.num_seconds()
            );
            return Ok(());
        }

        let subscriptions = self.db.list_lifecycle_subscriptions().await?;
        for sub in &subscriptions {
            if let Err(e) = self.handle_subscription_state(sub, last_check).await {
                error!("Failed to handle subscription {} state: {}", sub.id, e);
            }
        }

        self.set_last_check_subscriptions(Utc::now()).await?;
        Ok(())
    }

    async fn handle_vm_state(&self, state: Result<VmRunningState>, vm: &Vm) -> Result<()> {
        match state {
            Ok(s) => {
                self.vm_state_cache.set_state(vm.id, s).await?;
            }
            Err(e) => {
                warn!("Failed to get VM{} state: {}", vm.id, e);
                if !vm.deleted
                    && self
                        .vm_expires(vm)
                        .await
                        .map(|e| e > Utc::now())
                        .unwrap_or(false)
                {
                    self.spawn_vm_internal(vm).await?;
                }
            }
        }
        Ok(())
    }

    /// Resolve the authoritative expiry for a VM from its subscription.
    async fn vm_expires(&self, vm: &Vm) -> Option<DateTime<Utc>> {
        self.db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await
            .ok()?
            .expires
    }

    /// Check VM state from hypervisor and update cache
    /// Lifecycle enforcement (stop/delete) is handled by subscription lifecycle handlers.
    async fn check_vm(&self, vm: &Vm) -> Result<()> {
        debug!("Checking VM: {}", vm.id);
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;
        self.handle_vm_state(
            client
                .get_vm_state(vm)
                .await
                .map_err(|e| anyhow!("VM state error {e}")),
            &vm,
        )
        .await?;
        Ok(())
    }

    /// Check multiple VMs on a single host using bulk API
    async fn check_vms_on_host(&self, host_id: u64, vms: &[&Vm]) -> Result<()> {
        debug!("Checking {} VMs on host {}", vms.len(), host_id);
        let host = self.db.get_host(host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        let states = client.get_all_vm_states().await?;
        let state_map: HashMap<u64, VmRunningState> = states.into_iter().collect();

        for vm in vms {
            self.handle_vm_state(
                state_map
                    .get(&vm.id)
                    .map(|s| s.clone())
                    .context("VM not found in bulk response"),
                &vm,
            )
            .await?;
        }
        Ok(())
    }

    /// Spawn a VM and send notifications
    async fn spawn_vm_internal(&self, vm: &Vm) -> Result<()> {
        let provisioner = self.subscription_handler.vm_provisioner();
        let pipeline = provisioner.spawn_vm_pipeline(vm.id).await?;
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

        let ip_lines = vm_ips
            .iter()
            .map(|i| {
                if let Some(fwd) = &i.dns_forward {
                    format!("IP: {} ({})", i.ip, fwd)
                } else {
                    format!("IP: {}", i.ip)
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        let user_msg = format!(
            "Your VM #{} has been created!\n\nOS: {}\nCPU: {} vCPU\nRAM: {} GB\nDisk: {} GB\n{}\n\nNPUB: {}",
            vm.id,
            image,
            resources.cpu,
            resources.memory / crate::GB,
            resources.disk_size / crate::GB,
            ip_lines,
            PublicKey::from_slice(&user.pubkey)?.to_bech32()?
        );
        let admin_msg = format!(
            "VM #{} has been created.\n\nOS: {}\nCPU: {} vCPU\nRAM: {} GB\nDisk: {} GB\n{}\n\nUser NPUB: {}",
            vm.id,
            image,
            resources.cpu,
            resources.memory / crate::GB,
            resources.disk_size / crate::GB,
            ip_lines,
            PublicKey::from_slice(&user.pubkey)?.to_bech32()?
        );
        self.queue_notification(vm.user_id, user_msg, Some(format!("[VM{}] Created", vm.id)))
            .await;
        self.queue_admin_notification(admin_msg, Some(format!("[VM{}] Created", vm.id)))
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
        let provisioner = self.subscription_handler.vm_provisioner();

        // Group VMs by host for bulk checking
        let mut vms_by_host: HashMap<u64, Vec<&Vm>> = HashMap::new();
        let mut vms_to_delete = Vec::new();

        for vm in &db_vms {
            if vm.deleted {
                continue;
            }

            // A VM is "new" (never paid) if its subscription has never been set up.
            let Some(sub) = self
                .db
                .get_subscription_by_line_item_id(vm.subscription_line_item_id)
                .await
                .ok()
            else {
                warn!("Skipping VM{}, no subscription found (corrupted?)", vm.id);
                continue;
            };

            let vm_old_enough_to_delete = Utc::now() - sub.created > TimeDelta::hours(1);
            if vm_old_enough_to_delete && !sub.is_setup {
                vms_to_delete.push(vm);
            } else if sub.is_setup {
                vms_by_host.entry(vm.host_id).or_default().push(vm);
            }
        }

        // Process deletions first
        for vm in vms_to_delete {
            // Re-read the subscription to guard against a race condition where a
            // payment was confirmed between the initial list_vms() snapshot and now.
            // Only proceed with deletion if the subscription is still not set up.
            let current_sub = match self
                .db
                .get_subscription_by_line_item_id(vm.subscription_line_item_id)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to re-read subscription for VM {} before deletion: {}",
                        vm.id, e
                    );
                    self.queue_admin_notification(
                        format!(
                            "Failed to re-read subscription for VM {} before deletion:\n{}",
                            vm.id, e
                        ),
                        Some(format!("VM {} Pre-Deletion Read Failed", vm.id)),
                    )
                    .await;
                    continue;
                }
            };
            if current_sub.is_setup {
                info!("VM {} was paid since last check, skipping deletion", vm.id);
                continue;
            }
            // Skip deletion if there are still pending (unexpired) payments outstanding.
            if self
                .db
                .list_pending_vm_subscription_payments(vm.id)
                .await
                .map(|p| !p.is_empty())
                .unwrap_or(false)
            {
                info!(
                    "VM {} has pending unpaid payments, skipping deletion",
                    vm.id
                );
                continue;
            }
            info!("Deleting unpaid VM {}", vm.id);
            if let Err(e) = provisioner.delete_vm(vm.id).await {
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
        let notification = Notification::new(title, message);
        for channel in &self.notification_channels {
            if !channel.wants(&user) {
                continue;
            }
            if let Err(e) = channel.send(&user, &notification).await {
                match e {
                    OpError::Fatal(e) => warn!(
                        "Permanent {} notification error for user {}, skipping: {}",
                        channel.name(),
                        user_id,
                        e
                    ),
                    OpError::Transient(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    async fn send_email_verification(
        &self,
        user_id: u64,
        verify_url: &str,
    ) -> Result<(), OpError<anyhow::Error>> {
        let user = self
            .db
            .get_user(user_id)
            .await
            .map_err(|e| OpError::Transient(anyhow::Error::from(e)))?;
        if user.email.is_empty() {
            return Ok(()); // No email, nothing to do
        }
        let Some(smtp) = self.settings.smtp.as_ref() else {
            return Ok(());
        };
        let plain_text = format!(
            "Please verify your email address by clicking the link below:\n\n{}",
            verify_url
        );
        let html_message = format!(
            r#"Please verify your email address by clicking the link below:<br><br><a href="{}">Verify Email Address</a>"#,
            verify_url
        );
        send_email(
            smtp,
            user.email.as_str(),
            "Verify your email address",
            &plain_text,
            Some(&html_message),
        )
        .await
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
        if host.kind == VmHostKind::Dummy {
            return Ok(());
        }
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

        // Run host-info utility to detect CPU/GPU features (only if binary exists)
        match get_host_info_path() {
            Some(p) if p.exists() => {
                if let Err(e) = self.run_host_info(host).await {
                    warn!("Failed to run host-info on {}: {:?}", host.name, e);
                }
            }
            _ => {
                warn!(
                    "Host-info detection disabled: binary not found (expected at {:?})",
                    get_host_info_path()
                );
            }
        }

        // Patch firewall configuration for all VMs on this host
        let vms = self.db.list_vms_on_host(host.id).await?;
        for vm in &vms {
            // Sweep up orphaned/unused disks for every live VM. Repeated
            // reinstalls can leave Proxmox `unused[n]` disks attached which
            // accumulate over time; this only removes detached disks and never
            // touches the live primary disk.
            if !vm.deleted {
                if let Err(e) = client.delete_unused_disks(vm).await {
                    warn!("Failed to delete unused disks for VM {}: {}", vm.id, e);
                }
            }

            if !vm.deleted
                && self
                    .vm_expires(vm)
                    .await
                    .map(|e| e > Utc::now())
                    .unwrap_or(false)
            {
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

    /// Install and run lnvps-host-info on a host to detect CPU/GPU features
    async fn run_host_info(&self, host: &mut VmHost) -> Result<()> {
        // Check if SSH credentials are configured
        let ssh_key = match &host.ssh_key {
            Some(key) => key.as_str().to_string(),
            None => {
                warn!(
                    "No SSH key configured for host {}, skipping host-info",
                    host.name
                );
                return Ok(());
            }
        };
        let ssh_user = host.ssh_user.as_deref().unwrap_or("root");

        // Extract hostname/IP from the host.ip field (may be a URL like https://1.2.3.4:8006/)
        let ssh_host = extract_host_from_url(&host.ip);

        // Connect to host via SSH
        let mut ssh = SshClient::new()?;
        ssh.connect_with_key((ssh_host.as_str(), 22), ssh_user, &ssh_key)
            .await
            .with_context(|| {
                format!(
                    "Failed to SSH connect to host {} ({}@{}:22)",
                    host.name, ssh_user, ssh_host
                )
            })?;

        // Detect the host's architecture via uname -m
        let (exit_code, arch_output) = ssh
            .execute("uname -m")
            .await
            .with_context(|| format!("Failed to detect architecture on host {}", host.name))?;

        if exit_code != 0 {
            bail!(
                "uname -m failed with exit code {} on {}",
                exit_code,
                host.name
            );
        }

        let remote_arch = match arch_output.trim() {
            "x86_64" | "amd64" => CpuArch::X86_64,
            "aarch64" | "arm64" => CpuArch::ARM64,
            other => {
                warn!(
                    "Unknown architecture '{}' on host {}, skipping host-info",
                    other, host.name
                );
                return Ok(());
            }
        };

        // Select the correct binary based on the detected architecture
        let binary_path = get_host_info_path_for_arch(remote_arch)
            .with_context(|| "Failed to get host-info binary path")?;

        // Check if the binary exists for this architecture
        if !binary_path.exists() {
            warn!(
                "Host-info binary for {:?} not found at {:?}, skipping host {}",
                remote_arch, binary_path, host.name
            );
            return Ok(());
        }

        // Read the local binary
        let binary_data = std::fs::read(&binary_path)
            .with_context(|| format!("Failed to read host-info binary from {:?}", binary_path))?;

        // Upload the binary
        ssh.scp_upload(&binary_data, Path::new(HOST_INFO_REMOTE_PATH), 0o755)
            .with_context(|| format!("Failed to upload host-info to {}", host.name))?;

        info!("Uploaded host-info to {}", host.name);

        // Execute the binary and capture output
        let (exit_code, output) = ssh
            .execute(HOST_INFO_REMOTE_PATH)
            .await
            .with_context(|| format!("Failed to execute host-info on {}", host.name))?;

        if exit_code != 0 {
            bail!(
                "host-info exited with code {} on {}: {}",
                exit_code,
                host.name,
                output
            );
        }

        // Parse the JSON output
        let host_info: HostInfoOutput = serde_json::from_str(&output)
            .with_context(|| format!("Failed to parse host-info output from {}", host.name))?;

        // Update host with detected features
        let cpu_mfg = match host_info.cpu_mfg.as_str() {
            "intel" => CpuMfg::Intel,
            "amd" => CpuMfg::Amd,
            "apple" => CpuMfg::Apple,
            _ => CpuMfg::Unknown,
        };

        let cpu_arch = match host_info.cpu_arch.as_str() {
            "x86_64" => CpuArch::X86_64,
            "arm64" => CpuArch::ARM64,
            _ => CpuArch::Unknown,
        };

        // Parse CPU features
        let cpu_features: Vec<CpuFeature> = host_info
            .cpu_features
            .iter()
            .filter_map(|f| f.parse().ok())
            .collect();

        let features_changed = host.cpu_mfg != cpu_mfg
            || host.cpu_arch != cpu_arch
            || host.cpu_features.0 != cpu_features;

        if features_changed {
            host.cpu_mfg = cpu_mfg;
            host.cpu_arch = cpu_arch;
            host.cpu_features = cpu_features.into();
            self.db.update_host(host).await?;
            info!(
                "Updated host {} CPU info: mfg={:?}, arch={:?}, features={:?}",
                host.name, host.cpu_mfg, host.cpu_arch, host.cpu_features
            );
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
        let resolver = TokioResolver::builder_tokio()?.build()?;

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
    /// by fetching the activation URL and verifying the response is valid NIP-05 JSON
    /// with an empty `names` map (indicating the hash was recognised by the server).
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

        debug!(
            "Checking path activation for domain {} at {}",
            domain.name, activation_url
        );

        match self.http_client.get(&activation_url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    debug!(
                        "Path activation check failed for domain {} - got status {}",
                        domain.name,
                        response.status()
                    );
                    return Ok(false);
                }
                // Verify the body is valid NIP-05 JSON with an empty `names` map.
                // The lnvps_nostr server returns `{"names":{},"relays":{}}` when
                // the activation hash matches, rather than a real handle lookup.
                match response.json::<serde_json::Value>().await {
                    Ok(body) => {
                        let names_empty = body
                            .get("names")
                            .and_then(|n| n.as_object())
                            .map(|m| m.is_empty())
                            .unwrap_or(false);
                        if names_empty {
                            debug!("Path activation check succeeded for domain {}", domain.name);
                            Ok(true)
                        } else {
                            debug!(
                                "Path activation check failed for domain {} - unexpected body",
                                domain.name
                            );
                            Ok(false)
                        }
                    }
                    Err(e) => {
                        debug!(
                            "Path activation check failed for domain {} - invalid JSON: {}",
                            domain.name, e
                        );
                        Ok(false)
                    }
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
                            format!(
                                "Failed to upgrade domain '{}' (ID: {}) to HTTPS: {}",
                                domain.name, domain.id, e
                            ),
                            Some(format!("Domain HTTPS Upgrade Failed: {}", domain.name)),
                        )
                        .await;
                    }
                }
            }
            // Domain status is correct - no change needed
            else if domain.enabled && (has_dns_record || has_path_activation) {
                debug!(
                    "Domain {} is correctly active (DNS: {}, Path: {}, HTTP-only: {})",
                    domain.name, has_dns_record, has_path_activation, domain.http_only
                );
            } else if !domain.enabled && !has_dns_record && !has_path_activation {
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
            WorkJob::SpawnVm { vm_id } => {
                let vm = self.db.get_vm(*vm_id).await?;
                if vm.mac_address == "ff:ff:ff:ff:ff:ff" {
                    // VM has never been provisioned on the host — spawn it now.
                    self.spawn_vm_internal(&vm).await?;
                } else {
                    // VM already exists (a prior SpawnVm succeeded).
                    // Just sync its state into the cache.
                    self.check_vm(&vm).await?;
                }
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
            WorkJob::CheckSubscriptions => {
                self.check_subscriptions().await?;
            }
            WorkJob::SyncRouterState => {
                self.sync_router_state().await?;
            }
            WorkJob::ToggleBgpSession {
                router_id,
                session_id,
                enabled,
            } => {
                self.toggle_bgp_session(*router_id, session_id, *enabled)
                    .await?;
            }
            WorkJob::SetRouterDefaultRoute {
                router_id,
                next_hop,
            } => {
                self.set_router_default_route(*router_id, next_hop).await?;
            }
            WorkJob::ClearRouterDefaultRoute { router_id } => {
                self.clear_router_default_route(*router_id).await?;
            }
            WorkJob::ToggleTunnel {
                router_id,
                name,
                enabled,
            } => {
                self.toggle_tunnel(*router_id, name, *enabled).await?;
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
                let provisioner = self.subscription_handler.vm_provisioner();
                provisioner.delete_vm(*vm_id).await?;

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

                // Check if VM is expired via subscription
                if self
                    .vm_expires(&vm)
                    .await
                    .map(|e| e < Utc::now())
                    .unwrap_or(false)
                {
                    bail!("Cannot start expired VM {}", vm_id);
                }

                // Start the VM via provisioner
                let provisioner = self.subscription_handler.vm_provisioner();
                provisioner.start_vm(*vm_id).await?;

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
                let provisioner = self.subscription_handler.vm_provisioner();
                provisioner.stop_vm(*vm_id).await?;

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
            WorkJob::ApplyVmFirewall { vm_id } => {
                self.apply_vm_firewall(*vm_id).await?;
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
                let provisioner = self.subscription_handler.vm_provisioner();
                let vm = provisioner
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
            WorkJob::SendEmailVerification {
                user_id,
                verify_url,
            } => {
                if let Err(e) = self.send_email_verification(*user_id, verify_url).await {
                    match e {
                        OpError::Fatal(e) => warn!(
                            "Permanent email error for user {}, skipping: {}",
                            user_id, e
                        ),
                        OpError::Transient(e) => return Err(e),
                    }
                }
            }
            WorkJob::DownloadOsImages { image_id } => {
                self.download_os_images(*image_id).await?;
            }
        }
        Ok(None)
    }

    async fn download_os_images(&self, image_id: Option<u64>) -> Result<()> {
        let images = if let Some(id) = image_id {
            vec![self.db.get_os_image(id).await?]
        } else {
            self.db.list_os_image().await?
        };

        // Resolve and persist sha2/sha2_url for any image that is missing them
        let mut images = images;
        for image in &mut images {
            if image.sha2.is_none() {
                self.resolve_and_persist_sha2(image).await;
            }
        }

        let hosts = self.db.list_hosts().await?;
        for host in &hosts {
            let client = match get_host_client(host, &self.settings.provisioner_config) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to get client for host {}: {}", host.name, e);
                    continue;
                }
            };
            for image in &images {
                info!("Checking image {} on host {}", image.url, host.name);
                if let Err(e) = client.download_os_image(image).await {
                    warn!(
                        "Failed to download image {} on host {}: {}",
                        image.url, host.name, e
                    );
                }
            }
        }
        Ok(())
    }

    /// Resolve sha2/sha2_url for an image that is missing them, then persist
    /// the result to the database so future runs and host downloads can use it.
    async fn resolve_and_persist_sha2(&self, image: &mut VmOsImage) {
        let filename = match image.url_filename() {
            Ok(f) => f,
            Err(e) => {
                warn!("Could not determine filename for {}: {}", image.url, e);
                return;
            }
        };

        let resolved = if let Some(sha2_url) = image.sha2_url.clone() {
            match lnvps_api_common::shasum::fetch_checksum_for_file(&sha2_url, &filename).await {
                Ok(entry) => Some((entry.checksum, sha2_url)),
                Err(e) => {
                    warn!("Failed to fetch sha2 from {}: {}", sha2_url, e);
                    None
                }
            }
        } else {
            match lnvps_api_common::shasum::probe_checksum_from_image_url(&image.url, &filename)
                .await
            {
                Some((entry, sums_url)) => Some((entry.checksum, sums_url)),
                None => {
                    warn!("Could not find a SHASUMS file for {}", image.url);
                    None
                }
            }
        };

        if let Some((checksum, sums_url)) = resolved {
            info!("Resolved sha2 for {}: {}", image.url, checksum);
            image.sha2 = Some(checksum);
            image.sha2_url = Some(sums_url);
            if let Err(e) = self.db.update_os_image(image).await {
                warn!("Failed to persist sha2 for image {}: {}", image.id, e);
            }
        }
    }

    async fn process_vm_upgrade(&self, vm_id: u64, cfg: &UpgradeConfig) -> Result<()> {
        info!("Processing VM {} upgrade with new specs", vm_id);

        // Context struct for the pipeline
        struct UpgradeContext {
            vm_id: u64,
            cfg: UpgradeConfig,
            db: Arc<dyn LNVpsDb>,
            provisioner: VmProvisioner,
            settings: WorkerSettings,
            vm_history_logger: VmHistoryLogger,
        }

        let ctx = UpgradeContext {
            vm_id,
            cfg: cfg.clone(),
            db: self.db.clone(),
            provisioner: self.subscription_handler.vm_provisioner(),
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

                        // Update the subscription line item's renewal amount so that the
                        // displayed subscription cost reflects the upgraded specs.
                        ctx.provisioner
                            .update_line_item_cost_for_custom_vm(ctx.vm_id)
                            .await?;

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

        let upgraded_vm = self.db.get_vm(vm_id).await?;
        let new_resources = FullVmInfo::vm_resources(vm_id, self.db.clone()).await;
        let specs_line = match new_resources {
            Ok(r) => format!(
                "\n\nNew specifications:\nCPU: {} vCPU\nRAM: {} GB\nDisk: {} GB",
                r.cpu,
                r.memory / crate::GB,
                r.disk_size / crate::GB
            ),
            Err(_) => String::new(),
        };
        self.queue_notification(
            upgraded_vm.user_id,
            format!(
                "Your VM #{} has been successfully upgraded. The new specifications are now active.{}",
                vm_id, specs_line
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

    /// Re-apply the firewall ruleset for a VM using current database configuration.
    async fn apply_vm_firewall(&self, vm_id: u64) -> Result<()> {
        info!("Re-applying firewall for VM {}", vm_id);

        let vm = self.db.get_vm(vm_id).await?;
        if vm.deleted {
            bail!("Cannot apply firewall to deleted VM {}", vm_id);
        }

        let full_info = FullVmInfo::load(vm_id, self.db.clone()).await?;
        let host = self.db.get_host(full_info.host.id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        client.patch_firewall(&full_info).await?;

        info!("Successfully re-applied firewall for VM {}", vm_id);
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

        self.subscription_handler
            .vm_provisioner()
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

        self.subscription_handler
            .vm_provisioner()
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

        self.subscription_handler
            .vm_provisioner()
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
                    let msg = e.to_string();
                    if !msg.contains("timed out") {
                        error!("Failed to listen on commander channel: {}", e);
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::MockNode;
    use crate::settings::mock_settings;
    use crate::subscription::SubscriptionHandler;
    use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate};
    use lnvps_db::{
        LNVpsDbBase, Subscription, SubscriptionLineItem, SubscriptionPayment, SubscriptionType,
        UserSshKey, Vm,
    };

    async fn setup_worker(db: Arc<MockDb>) -> Result<Worker> {
        setup_worker_with_delete_after(db, 0).await
    }

    async fn setup_worker_with_delete_after(db: Arc<MockDb>, delete_after: u16) -> Result<Worker> {
        let mut settings = mock_settings();
        settings.delete_after = delete_after;
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::new());
        let work_commander = Arc::new(ChannelWorkCommander::new());
        let cache = VmStateCache::new();
        let sub_handler = SubscriptionHandler::new(
            settings.clone(),
            db.clone(),
            node,
            rates,
            work_commander.clone(),
            cache.clone(),
        )?;
        Worker::new(db, work_commander, sub_handler, &settings, cache, None).await
    }

    /// Create a VM linked to a subscription with the given created timestamp and is_setup state.
    /// Returns (vm_id, subscription_id).
    async fn add_vm_with_subscription(
        db: &Arc<MockDb>,
        sub_created: DateTime<Utc>,
        is_setup: bool,
    ) -> Result<(u64, u64)> {
        let pubkey: [u8; 32] = rand::random();
        let user_id = db.upsert_user(&pubkey).await?;
        let ssh_key_id = db
            .insert_user_ssh_key(&UserSshKey {
                id: 0,
                name: "test".to_string(),
                user_id,
                created: Utc::now(),
                key_data: "ssh-rsa AAA==".into(),
            })
            .await?;

        let (subscription_id, line_item_ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "test sub".to_string(),
                    description: None,
                    created: sub_created,
                    expires: if is_setup {
                        Some(sub_created.add(TimeDelta::days(30)))
                    } else {
                        None
                    },
                    is_active: is_setup,
                    is_setup,
                    currency: "BTC".to_string(),
                    interval_amount: 1,
                    interval_type: lnvps_db::IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::Vps,
                    name: "test item".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        let vm = Vm {
            id: 0,
            host_id: 1,
            user_id,
            image_id: 1,
            template_id: Some(1),
            custom_template_id: None,
            ssh_key_id,
            subscription_line_item_id: line_item_ids[0],
            disk_id: 1,
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            deleted: false,
            ..Default::default()
        };
        let vm_id = db.insert_vm(&vm).await?;
        Ok((vm_id, subscription_id))
    }

    fn make_subscription_payment(
        subscription_id: u64,
        user_id: u64,
        created: DateTime<Utc>,
        expires: DateTime<Utc>,
        id: u8,
    ) -> SubscriptionPayment {
        SubscriptionPayment {
            id: vec![id; 32],
            subscription_id,
            user_id,
            created,
            expires,
            amount: 1000,
            currency: "BTC".to_string(),
            payment_method: lnvps_db::PaymentMethod::Lightning,
            payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
            external_data: lnvps_db::EncryptedString::from("test"),
            external_id: None,
            is_paid: false,
            rate: 1.0,
            time_value: Some(2592000),
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
        }
    }

    /// An unpaid VM (subscription not set up) older than 1 hour must be deleted by check_vms.
    #[tokio::test]
    async fn test_check_vms_deletes_unpaid_vm_after_one_hour() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        let (vm_id, _) = add_vm_with_subscription(&db, old, false).await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        // VM should be soft-deleted
        let vms = db.vms.lock().await;
        let deleted = vms.get(&vm_id).map(|v| v.deleted).unwrap_or(false);
        assert!(deleted, "Unpaid VM older than 1 hour should be deleted");
        Ok(())
    }

    /// Regression: an admin-extended VM whose subscription is older than 1 hour must NOT be
    /// deleted. `admin_extend_vm` marks the subscription `is_setup = true`; the worker's cleanup
    /// keys off `is_setup`, so without that flag the VM would be wrongly deleted as unpaid.
    #[tokio::test]
    async fn test_check_vms_skips_admin_extended_vm() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        // Simulate an admin extension: subscription is old but marked set up/active with a
        // future expiry (what admin_extend_vm now does).
        let (vm_id, subscription_id) = add_vm_with_subscription(&db, old, false).await?;
        {
            let mut subs = db.subscriptions.lock().await;
            let sub = subs.get_mut(&subscription_id).expect("subscription exists");
            sub.is_setup = true;
            sub.is_active = true;
            sub.expires = Some(Utc::now().add(TimeDelta::days(30)));
        }

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        let vms = db.vms.lock().await;
        let deleted = vms.get(&vm_id).map(|v| v.deleted).unwrap_or(true);
        assert!(
            !deleted,
            "Admin-extended (is_setup) VM should not be deleted even when older than 1 hour"
        );
        Ok(())
    }

    /// An unpaid VM whose subscription was created less than 1 hour ago must NOT be deleted.
    #[tokio::test]
    async fn test_check_vms_skips_unpaid_vm_within_one_hour() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let recent = Utc::now().sub(TimeDelta::minutes(30));
        let (vm_id, _) = add_vm_with_subscription(&db, recent, false).await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        // VM should still be present and not deleted
        let vms = db.vms.lock().await;
        let deleted = vms.get(&vm_id).map(|v| v.deleted).unwrap_or(true);
        assert!(
            !deleted,
            "Unpaid VM younger than 1 hour should not be deleted"
        );
        Ok(())
    }

    /// An unpaid VM (older than 1 hour) with a non-expired pending payment must NOT be deleted.
    #[tokio::test]
    async fn test_check_vms_skips_unpaid_vm_with_pending_payment() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        let (vm_id, subscription_id) = add_vm_with_subscription(&db, old, false).await?;
        let user_id = db.get_vm(vm_id).await?.user_id;

        // Add a pending (unpaid, not-yet-expired) payment for this subscription.
        db.insert_subscription_payment(&make_subscription_payment(
            subscription_id,
            user_id,
            Utc::now(),
            Utc::now().add(TimeDelta::minutes(10)),
            1,
        ))
        .await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        // VM must NOT be deleted because there is a pending payment.
        let vms = db.vms.lock().await;
        let deleted = vms.get(&vm_id).map(|v| v.deleted).unwrap_or(true);
        assert!(
            !deleted,
            "Unpaid VM with a non-expired pending payment should not be deleted"
        );
        Ok(())
    }

    /// An unpaid VM (older than 1 hour) whose only payment is already expired must still be deleted.
    #[tokio::test]
    async fn test_check_vms_deletes_unpaid_vm_with_only_expired_payment() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        let (vm_id, subscription_id) = add_vm_with_subscription(&db, old, false).await?;
        let user_id = db.get_vm(vm_id).await?.user_id;

        // Add a payment whose invoice has already expired.
        db.insert_subscription_payment(&make_subscription_payment(
            subscription_id,
            user_id,
            old,
            old.add(TimeDelta::minutes(10)),
            2,
        ))
        .await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        // VM should be soft-deleted because the only payment is expired.
        let vms = db.vms.lock().await;
        let deleted = vms.get(&vm_id).map(|v| v.deleted).unwrap_or(false);
        assert!(
            deleted,
            "Unpaid VM with only an expired payment should still be deleted"
        );
        Ok(())
    }

    /// Drain all currently-queued work jobs without blocking, returning the count of
    /// `SendNotification` jobs whose title contains `needle`.
    async fn count_notifications(worker: &Worker, needle: &str) -> usize {
        let mut count = 0;
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(50),
                worker.work_commander.recv(),
            )
            .await
            {
                Ok(Ok(jobs)) => {
                    for j in jobs {
                        if let WorkJob::SendNotification { title: Some(t), .. } = &j.job {
                            if t.contains(needle) {
                                count += 1;
                            }
                        }
                    }
                }
                _ => break, // timed out (channel drained) or error
            }
        }
        count
    }

    /// Regression: an expired subscription within its grace period must only fire the
    /// "Expired" notification (and `on_expired`) ONCE, on the check where expiry is first
    /// detected — not on every CheckSubscriptions cycle. Previously the expired branch had
    /// no edge-trigger guard and re-ran every ~30s, re-stopping the VM and spamming
    /// notifications in an endless loop.
    #[tokio::test]
    async fn test_expired_subscription_notifies_once_within_grace_period() -> Result<()> {
        let db = Arc::new(MockDb::default());
        // Subscription created 40 days ago, so its 30-day expiry is ~10 days in the past
        // but well within a 30-day grace period.
        let created = Utc::now().sub(TimeDelta::days(40));
        let (_vm_id, subscription_id) = add_vm_with_subscription(&db, created, true).await?;
        let sub = db.get_subscription(subscription_id).await?;
        assert!(sub.expires.unwrap() < Utc::now(), "sub must be expired");

        let worker = setup_worker_with_delete_after(db.clone(), 30).await?;

        // First check: last_check is just before "now", so expiry (10 days ago) is NOT in
        // (last_check, now]. To exercise the first-detection edge we use a last_check from
        // before the expiry, then a later last_check for the subsequent cycle.
        let before_expiry = sub.expires.unwrap().sub(TimeDelta::days(1));
        worker
            .handle_subscription_state(&sub, before_expiry)
            .await?;
        let first = count_notifications(&worker, "Expired").await;
        assert!(
            first >= 1,
            "expired notification must fire when expiry is first detected (got {first})"
        );

        // Second check on a later cycle: last_check is now after the expiry, so the guard
        // (expires >= last_check) must suppress the repeat.
        let after_expiry = sub.expires.unwrap().add(TimeDelta::minutes(1));
        worker.handle_subscription_state(&sub, after_expiry).await?;
        let second = count_notifications(&worker, "Expired").await;
        assert_eq!(
            second, 0,
            "expired notification must NOT repeat on subsequent cycles within grace"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_sync_router_state() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::{
            BgpPeerDirection, BgpSession, GreConfig, Router as _, Tunnel, TunnelConfig,
        };
        use lnvps_db::{Router, RouterKind};

        let db = Arc::new(MockDb::empty());
        {
            let mut routers = db.router.lock().await;
            routers.insert(
                1,
                Router {
                    id: 1,
                    name: "r1".to_string(),
                    enabled: true,
                    kind: RouterKind::MockRouter,
                    url: "mock://".to_string(),
                    token: "".into(),
                },
            );
        }

        // Seed the shared mock-router state with a tunnel and a BGP session
        let mr = MockRouter::new();
        mr.clear().await;
        mr.tunnel()
            .unwrap()
            .add_tunnel(&Tunnel {
                id: None,
                name: "gre1".to_string(),
                local_addr: None,
                remote_addr: None,
                enabled: true,
                config: TunnelConfig::Gre(GreConfig { key: None }),
            })
            .await
            .unwrap();
        mr.add_session(BgpSession {
            id: "s1".to_string(),
            name: "peer1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: Some(5),
            prefixes_sent: Some(1),
            enabled: true,
            direction: BgpPeerDirection::Upstream,
        })
        .await;

        let worker = setup_worker(db.clone()).await?;
        worker.sync_router_state().await?;

        let tunnels = db.list_router_tunnels(1).await?;
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].name, "gre1");

        let traffic = db
            .list_router_tunnel_traffic(
                1,
                "gre1",
                Utc::now() - TimeDelta::hours(1),
                Utc::now() + TimeDelta::hours(1),
            )
            .await?;
        assert_eq!(traffic.len(), 1);

        let sessions = db.list_router_bgp_sessions(1).await?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].peer_asn, Some(64512));

        // Clean up shared state for other tests
        mr.clear().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_toggle_bgp_session() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::{BgpPeerDirection, BgpSession};
        use lnvps_db::{Router, RouterKind};

        let db = Arc::new(MockDb::empty());
        {
            let mut routers = db.router.lock().await;
            routers.insert(
                1,
                Router {
                    id: 1,
                    name: "r1".to_string(),
                    enabled: true,
                    kind: RouterKind::MockRouter,
                    url: "mock://".to_string(),
                    token: "".into(),
                },
            );
        }
        let mr = MockRouter::new();
        mr.clear().await;
        mr.add_session(BgpSession {
            id: "s1".to_string(),
            name: "peer1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: None,
            prefixes_sent: None,
            enabled: true,
            direction: BgpPeerDirection::Upstream,
        })
        .await;

        let worker = setup_worker(db.clone()).await?;
        worker.toggle_bgp_session(1, "s1", false).await?;

        // The cached session should reflect the disabled state after refresh
        let sessions = db.list_router_bgp_sessions(1).await?;
        assert_eq!(sessions.len(), 1);
        assert!(!sessions[0].enabled);

        mr.clear().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_set_and_clear_default_route() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::Router as _;
        use lnvps_db::{Router, RouterKind};

        let db = Arc::new(MockDb::empty());
        {
            let mut routers = db.router.lock().await;
            routers.insert(
                1,
                Router {
                    id: 1,
                    name: "r1".to_string(),
                    enabled: true,
                    kind: RouterKind::MockRouter,
                    url: "mock://".to_string(),
                    token: "".into(),
                },
            );
        }
        let mr = MockRouter::new();
        mr.clear().await;

        let worker = setup_worker(db.clone()).await?;

        // Set a new default route; the backend reflects it and the cache is synced.
        worker.set_router_default_route(1, "198.51.100.1").await?;
        let route = mr.bgp().unwrap().default_routes().await.unwrap();
        assert_eq!(
            route.first().and_then(|r| r.next_hop.as_deref()),
            Some("198.51.100.1")
        );
        let cached = db.list_router_bgp_routes(1).await?;
        assert!(cached.iter().any(|r| r.is_default));

        // Clear the default route; the backend no longer reports one.
        worker.clear_router_default_route(1).await?;
        assert!(mr.bgp().unwrap().default_routes().await.unwrap().is_empty());

        // Restore the mock's shared default route for other tests.
        mr.bgp()
            .unwrap()
            .set_default_route("192.0.2.1")
            .await
            .unwrap();
        mr.clear().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_toggle_tunnel() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::{GreConfig, Router as _, Tunnel, TunnelConfig};
        use lnvps_db::{Router, RouterKind};

        let db = Arc::new(MockDb::empty());
        {
            let mut routers = db.router.lock().await;
            routers.insert(
                1,
                Router {
                    id: 1,
                    name: "r1".to_string(),
                    enabled: true,
                    kind: RouterKind::MockRouter,
                    url: "mock://".to_string(),
                    token: "".into(),
                },
            );
        }
        let mr = MockRouter::new();
        mr.clear().await;
        mr.tunnel()
            .unwrap()
            .add_tunnel(&Tunnel {
                id: None,
                name: "gre1".to_string(),
                local_addr: None,
                remote_addr: None,
                enabled: true,
                config: TunnelConfig::Gre(GreConfig { key: None }),
            })
            .await
            .unwrap();

        let worker = setup_worker(db.clone()).await?;
        worker.toggle_tunnel(1, "gre1", false).await?;

        // The cached tunnel should reflect the disabled state after refresh.
        let tunnels = db.list_router_tunnels(1).await?;
        assert_eq!(tunnels.len(), 1);
        assert!(!tunnels[0].enabled);

        mr.clear().await;
        Ok(())
    }
}
