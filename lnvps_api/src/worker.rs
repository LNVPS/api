use crate::host::{FullVmInfo, VmHostClient, get_host_client};
use crate::notifications::{Notification, NotificationChannel, build_channels, send_email};
use crate::provisioner::{VmLocation, VmProvisioner};
use crate::settings::{ProvisionerConfig, Settings, SmtpConfig, TelegramConfig, WhatsAppConfig};
use crate::ssh_client::SshClient;
use crate::subscription::SubscriptionHandler;
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Days, NaiveDate, TimeDelta, Utc};
use hickory_resolver::TokioResolver;
use lnvps_api_common::{
    BlackholeWorkFeedback, ChannelWorkCommander, InMemoryKeyValueStore, JobFeedback, KeyValueStore,
    NetworkProvisioner, RedisConfig, RedisKeyValueStore, RedisWorkCommander, RedisWorkFeedback,
    SCANNED_KEY_FAMILIES, TrafficRecorder, UpgradeConfig, VmHistoryLogger, VmRunningState,
    VmRunningStates, VmStateCache, WorkCommander, WorkFeedback, WorkJob, WorkJobMessage,
    capture_is_complete, merge_ssh_host_keys, op_fatal, parse_ssh_host_keys, quota_period,
    retry::{OpError, Pipeline, RetryPolicy},
};
use lnvps_db::{
    BulkMessageTarget, CpuArch, CpuFeature, CpuMfg, IntervalType, LNVpsDb, LineItemType,
    PaymentMethod, RouterTunnelTraffic, Subscription, SubscriptionLineItem, SubscriptionPayment,
    Vm, VmHistoryActionType, VmHost, VmHostKind, VmIpAssignment, VmOsImage,
};
use log::{debug, error, info, warn};
use nostr_sdk::Client;
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

/// Whether an unpaid payment should still block deletion of a never-paid VM.
///
/// A payment blocks deletion while its invoice is unexpired, but also — for
/// on-chain payments — once a deposit has been detected in the mempool
/// (`external_id` holds the deposit outpoint `{txid}:{vout}`): confirmation
/// can land well after the 1h quote expiry, and purging the VM in that window
/// would lose the customer's payment (issue #194).
pub(crate) fn payment_blocks_unpaid_vm_deletion(
    p: &SubscriptionPayment,
    now: DateTime<Utc>,
) -> bool {
    !p.is_paid
        && (p.expires > now
            || (p.payment_method == PaymentMethod::OnChain && p.external_id.is_some()))
}

/// How long to wait before scanning a VM's host keys again while the capture is
/// still missing keys.
const HOST_KEY_SCAN_RETRY_SECS: u64 = 3600;

/// Key holding when a VM's host keys were last scanned.
fn host_key_attempt_key(vm_id: u64) -> String {
    format!("worker-host-keys-attempt-{vm_id}")
}

/// One SSH session to a node, shared by every host key scan aimed at it.
///
/// A fleet check walks every VM on a node in turn; connecting per VM would pay
/// a handshake per guest, and a node that is down would be dialled once per VM
/// it carries. A failed connect is remembered so the rest of that node's VMs
/// are skipped rather than retried.
#[derive(Default)]
enum HostSshSession {
    #[default]
    Idle,
    Connected(Box<SshClient>),
    Failed,
}

impl HostSshSession {
    async fn get_or_connect(&mut self, host: &VmHost) -> Option<&mut SshClient> {
        if let Self::Idle = self {
            let ssh_key = host.ssh_key.as_ref()?;
            let ssh_user = host.ssh_user.as_deref().unwrap_or("root");
            let mut ssh = SshClient::new();
            let ssh_host = lnvps_api_common::host::extract_host_from_url(&host.ip);
            if let Err(e) = ssh
                .connect_with_key((ssh_host.as_str(), 22), ssh_user, ssh_key.as_str())
                .await
            {
                warn!("[host-keys] connect to {} failed: {}", host.name, e);
                *self = Self::Failed;
                return None;
            }
            *self = Self::Connected(Box::new(ssh));
        }
        match self {
            Self::Connected(ssh) => Some(ssh),
            _ => None,
        }
    }
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

/// What a tunnel pool's route server disagreed with the database about.
///
/// Kept as three lists rather than a count because they mean different things:
/// a peer that is *missing* was configured and is gone, a *changed* one is
/// carrying the wrong anti-spoof list, and an *unclaimed* one is a key on an
/// LNVPS interface that no allocation accounts for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelPeerDrift {
    /// Allocated peers the route server did not have
    pub missing: Vec<String>,
    /// Peers whose allowed IPs no longer matched their allocation
    pub changed: Vec<String>,
    /// Peers on the interface that no tunnel claims
    pub unclaimed: Vec<String>,
}

impl TunnelPeerDrift {
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.changed.is_empty() && self.unclaimed.is_empty()
    }
}

impl std::fmt::Display for TunnelPeerDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} missing, {} changed, {} unclaimed",
            self.missing.len(),
            self.changed.len(),
            self.unclaimed.len()
        )
    }
}

/// Whether two peers permit the same set of addresses.
///
/// Compared as a set: `wg` reports allowed IPs in its own order, and treating
/// that as a difference would rewrite a working peer's anti-spoof list on every
/// single reconcile.
fn same_allowed_ips(a: &crate::router::WireguardPeer, b: &crate::router::WireguardPeer) -> bool {
    let mut x: Vec<&String> = a.allowed_ips.iter().collect();
    let mut y: Vec<&String> = b.allowed_ips.iter().collect();
    x.sort();
    y.sort();
    x == y
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
    traffic_recorder: TrafficRecorder,
    vm_state_cache: VmStateCache,
    work_commander: Arc<dyn WorkCommander>,
    feedback: Arc<dyn WorkFeedback>,
    kv: Arc<dyn KeyValueStore>,
    http_client: reqwest::Client,
    referral_payouts: crate::referral::ReferralPayoutHandler,
    refunds: crate::refund::VmRefundHandler,
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
    /// Minimum accrued BTC referral commission (satoshis) before an automated
    /// Lightning payout is attempted. `None` disables automated Lightning
    /// referral payouts.
    pub referral_min_payout_sats: Option<u64>,
    /// Minimum accrued BTC referral commission (satoshis) before an automated
    /// on-chain payout is attempted. `None` disables automated on-chain
    /// referral payouts.
    pub referral_min_onchain_payout_sats: Option<u64>,
    /// Maximum next-block fee rate (sat/vByte) tolerated for on-chain referral
    /// payouts; batches are deferred above this.
    pub referral_max_onchain_fee_per_vbyte: u64,
    /// Minimum fiat-settled referral commission (satoshis at the quote) before
    /// an automated converted payout is attempted. `None` disables them.
    pub referral_min_fiat_payout_sats: Option<u64>,
    /// Source of the on-chain fee-rate estimate for the cap above.
    pub referral_fee_estimator: crate::settings::FeeEstimatorConfig,
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
            referral_min_payout_sats: val.referral.as_ref().map(|r| r.min_payout_sats),
            referral_min_onchain_payout_sats: val
                .referral
                .as_ref()
                .and_then(|r| r.min_onchain_payout_sats),
            referral_max_onchain_fee_per_vbyte: val
                .referral
                .as_ref()
                .map(|r| r.max_onchain_fee_per_vbyte)
                .unwrap_or(50),
            referral_min_fiat_payout_sats: val
                .referral
                .as_ref()
                .and_then(|r| r.min_fiat_payout_sats),
            referral_fee_estimator: val
                .referral
                .as_ref()
                .map(|r| r.fee_estimator.clone())
                .unwrap_or_default(),
        }
    }
}

impl Worker {
    const CHECK_VMS_SECONDS: u64 = 30;

    pub async fn new(
        db: Arc<dyn LNVpsDb>,
        work_commander: Arc<dyn WorkCommander>,
        subscription_handler: SubscriptionHandler,
        node: Arc<dyn payments_rs::lightning::LightningNode>,
        onchain: Option<Arc<dyn payments_rs::onchain::OnChainProvider>>,
        settings: impl Into<WorkerSettings>,
        vm_state_cache: VmStateCache,
        nostr: Option<Client>,
    ) -> Result<Self> {
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        let traffic_recorder = TrafficRecorder::new(db.clone());
        let settings = settings.into();
        let fee_estimator =
            crate::fee_estimate::build_fee_estimator(&settings.referral_fee_estimator);
        let kv: Arc<dyn KeyValueStore> = if let Some(c) = &settings.redis {
            Arc::new(RedisKeyValueStore::new(&c.url).await?)
        } else {
            Arc::new(InMemoryKeyValueStore::new())
        };

        let referral_payouts = crate::referral::ReferralPayoutHandler::new(
            db.clone(),
            node.clone(),
            work_commander.clone(),
            settings.referral_min_payout_sats,
            onchain,
            settings.referral_min_onchain_payout_sats,
            settings.referral_max_onchain_fee_per_vbyte,
            fee_estimator,
            subscription_handler.pricing_engine().rates(),
            settings.referral_min_fiat_payout_sats,
            kv.clone(),
        );

        let refunds = crate::refund::VmRefundHandler::new(
            db.clone(),
            node,
            subscription_handler.pricing_engine(),
        );

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
            traffic_recorder,
            settings,
            work_commander,
            http_client,
            referral_payouts,
            refunds,
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
        let Some(expires) = sub.expires else {
            return Ok(());
        };

        // How far ahead of expiry the "expiring soon" auto-renewal / warning
        // window opens. Capped at half the billing interval so a subscription
        // that was just renewed (new expiry = now + interval) is NOT immediately
        // "expiring soon" again. Without the cap, a short interval (e.g. 1-day
        // billing) with a fixed 1-day lead re-enters the window the moment it is
        // paid, and the next worker tick auto-renews it seconds later — a
        // double charge (VM 1828).
        let lead = expiry_lead_window(sub);
        let lead_descr = format_lead_window(lead);

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
        let expiry_window = now.add(lead);
        if expires > now && expires < expiry_window && expires > last_check.add(lead) {
            // Attempt auto-renewal using the user's default saved payment method
            // (NWC Lightning wallet or Revolut card), dispatched by provider.
            let mut auto_renewed = false;

            if sub.auto_renewal_enabled {
                let has_method = self
                    .db
                    .list_user_payment_methods(sub.user_id, None)
                    .await
                    .map(|m| m.iter().any(|pm| pm.enabled))
                    .unwrap_or(false);
                if has_method {
                    info!("Attempting auto-renewal for subscription {}", sub.id);
                    match self.subscription_handler.auto_renew(sub.id).await {
                        Ok(_) => {
                            info!("Successfully auto-renewed subscription {}", sub.id);
                            self.queue_notification(
                                sub.user_id,
                                format!("Your subscription is being automatically renewed using your saved payment method.\n{}", sub_notification_descr),
                                Some(format!("[{}] Auto-Renewed", sub_notification_subject)),
                            ).await;
                            auto_renewed = true;
                        }
                        Err(e) => {
                            warn!("Auto-renewal error for subscription {}: {}", sub.id, e);
                            self.queue_notification(
                                sub.user_id,
                                format!(
                                    "Your subscription will expire soon.\nAutomatic renewal failed: '{}'\nPlease renew manually in the next {}.\n{}",
                                    e, lead_descr, sub_notification_descr
                                ),
                                Some(format!("[{}] Expiring Soon", sub_notification_subject)),
                            )
                            .await;
                            auto_renewed = true;
                        }
                    }
                }
            }

            // Send a plain expiry warning whenever auto-renewal was not attempted
            // (auto_renewal off, or no saved payment method).
            if !auto_renewed {
                self.queue_notification(
                    sub.user_id,
                    format!(
                        "Your subscription will expire soon. Please renew manually in the next {}.\n{}",
                        lead_descr, sub_notification_descr
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
}

/// Grace period (days) for a subscription, tiered by subscription age. Lives in
/// `lnvps_api_common` so the API layer can surface the resulting deletion date;
/// re-exported here for the worker/subscription callers.
pub use lnvps_api_common::grace_period_days_for_sub;

/// Approximate duration of one billing interval for a subscription.
///
/// Calendar months/years are approximated (30/365 days) — this is only used to
/// cap the auto-renewal lead window, where day-level precision is irrelevant.
fn subscription_interval(sub: &Subscription) -> TimeDelta {
    let amount = sub.interval_amount.max(1) as i64;
    match sub.interval_type {
        IntervalType::Day => TimeDelta::days(amount),
        IntervalType::Month => TimeDelta::days(30 * amount),
        IntervalType::Year => TimeDelta::days(365 * amount),
    }
}

/// How far ahead of expiry the "expiring soon" auto-renewal / warning window
/// opens.
///
/// Defaults to one day, but is capped at **half the billing interval** so that
/// a freshly-renewed subscription (new expiry = `now + interval`) does not fall
/// straight back inside the window. Without the cap, any interval ≤ the fixed
/// 1-day lead (e.g. 1-day billing) re-enters the window the instant it is paid,
/// and the next worker tick auto-renews it seconds after purchase — a double
/// charge (VM 1828).
fn expiry_lead_window(sub: &Subscription) -> TimeDelta {
    const MAX_LEAD: TimeDelta = TimeDelta::days(1);
    MAX_LEAD.min(subscription_interval(sub) / 2)
}

/// Human-readable description of a lead window for renewal notifications,
/// e.g. `"1 day"` or `"12 hours"`.
fn format_lead_window(lead: TimeDelta) -> String {
    let hours = lead.num_hours().max(1);
    if hours % 24 == 0 {
        let days = hours / 24;
        format!("{} day{}", days, if days == 1 { "" } else { "s" })
    } else {
        format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
    }
}

impl Worker {
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
            if li.subscription_type != LineItemType::Vps {
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
            .all(|l| l.subscription_type == LineItemType::Vps)
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

    /// Probe one marketplace node that is due one.
    ///
    /// Proving a node can carry a customer means building a customer's VM on it:
    /// everything else LNVPS can see is what the operator's machine chooses to
    /// report. A passing probe is what enables the backing host, which is the
    /// point at which real customers can be placed there.
    ///
    /// One node per run. A probe puts real load on hardware LNVPS does not own,
    /// and a sweep that probed the whole fleet at once would arrive as a
    /// thundering herd on the operators least able to absorb it.
    #[cfg(feature = "linux-ssh")]
    pub async fn probe_marketplace_node(&self) -> Result<()> {
        let due = crate::provisioner::probe_candidates(&self.db, chrono::Utc::now()).await?;
        let Some(node) = due.into_iter().next() else {
            return Ok(());
        };

        // A probe that could not be run at all must not abort the sweep: this
        // runs from `handle_job`, whose error stops the rest of the batch, so
        // one unreachable node would take `CheckVms`, `CheckSubscriptions` and
        // every other queued job down with it. What went wrong is already a
        // health row for whoever looks at the node.
        let result =
            match crate::provisioner::run_probe(&self.db, &self.settings.provisioner_config, &node)
                .await
            {
                Ok(result) => result,
                Err(e) => {
                    warn!("Marketplace node {} could not be probed: {}", node.id, e);
                    return Ok(());
                }
            };
        if !result.passed() {
            // Recorded, not acted on. One bad probe is a bad afternoon — a
            // backup job, a noisy neighbour — and taking a node out of service
            // for it would make the marketplace hostile to the people it needs.
            // Suspension on a trend is increment 12's job.
            warn!(
                "Marketplace node {} failed its probe: {}",
                node.id,
                result.failure.as_deref().unwrap_or("unknown")
            );
            return Ok(());
        }

        // The gate: a host is only enabled once a VM has actually run on it.
        let Some(host) = self.db.get_marketplace_node_host(node.id).await? else {
            return Ok(());
        };
        if !host.enabled {
            info!(
                "Marketplace node {} carried a probe VM in {}ms; enabling host {}",
                node.id,
                result.provision_ms.unwrap_or_default(),
                host.id
            );
            self.db
                .update_host(&VmHost {
                    enabled: true,
                    ..host
                })
                .await?;
        }
        Ok(())
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

            // Reconcile every pool this router terminates. This is where drift
            // is actually caught: a peer wiped by a reboot, a stale key left
            // behind, or a guest address assigned since the last push. Doing it
            // on the existing router poll rather than on every VM change keeps
            // guest addressing correct without wiring a route-server call into
            // the provisioning path.
            match self.db.list_tunnel_pools(None).await {
                Ok(pools) => {
                    for pool in pools
                        .iter()
                        .filter(|p| p.router_id == router_id && p.enabled)
                    {
                        if let Err(e) = self.reconcile_tunnel_peers(pool.id).await {
                            warn!("Failed to reconcile tunnel pool {}: {}", pool.id, e);
                        }
                    }
                }
                Err(e) => warn!("Failed to list tunnel pools for router {router_id}: {e}"),
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

    /// Configure a tunnel pool's WireGuard interface on its route server.
    ///
    /// This is a **push**, not a reconcile: LNVPS generates and holds the
    /// interface's key material, so what the database says is what the
    /// interface should be. Without it a pool could only describe an interface
    /// somebody configured by hand, and bringing up a new route server would be
    /// a manual job with a database row bolted on afterwards.
    pub async fn sync_tunnel_pool(&self, pool_id: u64) -> Result<()> {
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        let router = crate::router::get_router(&self.db, pool.router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", pool.router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;

        let private_key = pool.private_key.as_str().to_string();
        // The stored pair has to agree with itself before it is pushed: a
        // public key that is not this private key's would be handed to every
        // node and none of them could hand shake.
        let derived = lnvps_api_common::wireguard_public_key(&private_key)?;
        if derived != pool.public_key {
            bail!(
                "Tunnel pool {} has a public key that its private key does not produce; \
                 refusing to configure an interface nobody could connect to",
                pool.id
            );
        }

        // Named from the pool's id under a fixed prefix, so a managed
        // interface can never be confused with one the operator of the route
        // server configured themselves.
        let interface = pool.interface();

        let existing = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?
            .into_iter()
            .find(|t| t.name == interface);

        let desired = crate::router::Tunnel {
            id: existing.as_ref().and_then(|t| t.id.clone()),
            name: interface.clone(),
            // The address the data plane listens on. Recorded so the interface
            // and the endpoint peers are told to dial cannot disagree.
            local_addr: Some(pool.listen_addr.clone()),
            remote_addr: None,
            enabled: pool.enabled,
            config: crate::router::TunnelConfig::Wireguard(crate::router::WireguardConfig {
                listen_port: Some(pool.listen_port),
                private_key: Some(private_key),
                public_key: Some(lnvps_api_common::wireguard_key_to_base64(&pool.public_key)),
                // Peers are pushed per allocation, not here. Sending an empty
                // list would be read as "this interface has no peers".
                peers: vec![],
            }),
        };

        match &existing {
            None => {
                info!(
                    "Creating WireGuard interface {} on router {}",
                    interface, pool.router_id
                );
                tr.add_tunnel(&desired)
                    .await
                    .map_err(|e| anyhow!("failed to create tunnel interface: {}", e))?;
            }
            Some(current) => {
                // Re-applying recreates the interface on the Linux backend,
                // which drops every peer with it. So it is only done when the
                // interface is actually wrong — a node whose tunnel is working
                // must not be cut because a pool was renamed.
                let current_key = match &current.config {
                    crate::router::TunnelConfig::Wireguard(c) => c.public_key.clone(),
                    _ => None,
                };
                let current_port = match &current.config {
                    crate::router::TunnelConfig::Wireguard(c) => c.listen_port,
                    _ => None,
                };
                let want_key = lnvps_api_common::wireguard_key_to_base64(&pool.public_key);
                let key_drifted = current_key.as_deref() != Some(want_key.as_str());
                let port_drifted = current_port != Some(pool.listen_port);

                if key_drifted || port_drifted {
                    warn!(
                        "WireGuard interface {} on router {} has drifted (key_changed={}, \
                         port_changed={}); re-applying, which drops its peers until they are \
                         pushed again",
                        interface, pool.router_id, key_drifted, port_drifted
                    );
                    tr.update_tunnel(&desired)
                        .await
                        .map_err(|e| anyhow!("failed to update tunnel interface: {}", e))?;
                } else if current.enabled != pool.enabled {
                    let id = current.id.as_deref().unwrap_or(interface.as_str());
                    tr.set_tunnel_enabled(id, pool.enabled)
                        .await
                        .map_err(|e| anyhow!("failed to toggle tunnel interface: {}", e))?;
                }
            }
        }

        // Refresh the observed-state cache so the admin API stops showing the
        // interface as missing the moment it exists.
        if let Ok(tunnels) = tr.list_tunnels().await {
            for t in &tunnels {
                if let Err(e) = self.db.upsert_router_tunnel(&t.to_db(pool.router_id)).await {
                    warn!("Failed to refresh tunnel cache: {}", e);
                }
            }
        }

        // Whatever happened above, the interface now has to carry the peers
        // that were allocated from this pool. This matters most in the case the
        // push above just created or re-applied it: on Linux that is a fresh
        // interface with no peers at all, and every node on it is cut until
        // they are put back.
        self.reconcile_tunnel_peers(pool.id).await?;
        Ok(())
    }

    /// Reconcile the peers, addresses and routes on a pool's interface against
    /// the tunnels allocated from it.
    ///
    /// The `tunnel` table is the desired state and the router is the observed
    /// one, exactly as with host state. A peer that has vanished from a route
    /// server is drift to put back and report, not an allocation to forget:
    /// forgetting it would hand the node's addresses to somebody else while the
    /// node still believes they are its own.
    ///
    /// Returns what had drifted, so a caller running this on a schedule can say
    /// whether anything was wrong rather than only that it ran.
    pub async fn reconcile_tunnel_peers(&self, pool_id: u64) -> Result<TunnelPeerDrift> {
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        let router = crate::router::get_router(&self.db, pool.router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", pool.router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;
        let interface = pool.interface();

        let observed = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?
            .into_iter()
            .find(|t| t.name == interface);
        // Peers are configured *on* an interface, so there is nothing to
        // reconcile against until it exists. Creating it here would duplicate
        // `sync_tunnel_pool` and hide the fact that it never ran.
        let Some(observed) = observed else {
            bail!(
                "Tunnel pool {pool_id}'s interface {interface} is not configured on router {}; \
                 run SyncTunnelPool first",
                pool.router_id
            );
        };
        let observed_peers = match &observed.config {
            crate::router::TunnelConfig::Wireguard(c) => c.peers.clone(),
            _ => bail!("Tunnel pool {pool_id}'s interface {interface} is not a WireGuard tunnel"),
        };

        // What is behind each node peer is recomputed from the guest
        // assignments before the plan is built, so the planner can read it
        // without knowing that marketplace nodes exist.
        crate::provisioner::refresh_node_routes(&self.db, &pool).await?;
        let plan = crate::provisioner::plan_pool(&self.db, &pool).await?;
        let mut drift = TunnelPeerDrift::default();

        for want in &plan.peers {
            match observed_peers
                .iter()
                .find(|p| p.public_key == want.public_key)
            {
                // Allowed IPs are compared as a set: `wg` reports them in its
                // own order, and re-pushing on every reconcile because of that
                // would rewrite the anti-spoof list of a working peer forever.
                Some(have) if same_allowed_ips(have, want) => continue,
                Some(_) => drift.changed.push(want.public_key.clone()),
                None => drift.missing.push(want.public_key.clone()),
            }
            tr.set_tunnel_peer(&interface, want)
                .await
                .map_err(|e| anyhow!("failed to configure peer on {interface}: {}", e))?;
        }

        for have in &observed_peers {
            if plan.peers.iter().any(|p| p.public_key == have.public_key) {
                continue;
            }
            // LNVPS owns `wgln*` interfaces outright, so a peer no tunnel
            // claims is either a revoked allocation that was never cleaned up
            // or somebody else's key on our route server. Both are removed.
            drift.unclaimed.push(have.public_key.clone());
            tr.remove_tunnel_peer(&interface, &have.public_key)
                .await
                .map_err(|e| anyhow!("failed to remove peer from {interface}: {}", e))?;
        }

        tr.sync_tunnel_addresses(&interface, &plan.addresses)
            .await
            .map_err(|e| anyhow!("failed to configure addresses on {interface}: {}", e))?;
        tr.sync_tunnel_routes(&interface, &plan.routes)
            .await
            .map_err(|e| anyhow!("failed to configure routes on {interface}: {}", e))?;

        if !drift.is_empty() {
            warn!(
                "Tunnel pool {pool_id} on router {} had drifted: {drift}",
                pool.router_id
            );
        }
        Ok(drift)
    }

    /// Push one node's peer onto its route server.
    ///
    /// Used when a single allocation changes — a node asking for its tunnel, a
    /// guest getting an address — so it does not wait behind a reconcile of
    /// every other node on the same route server.
    pub async fn sync_node_tunnel(&self, tunnel_id: u64) -> Result<()> {
        let tunnel = self.db.get_tunnel(tunnel_id).await?;
        let pool_id = tunnel.pool_id.ok_or_else(|| {
            anyhow!("Tunnel {tunnel_id} was not allocated from a pool, so there is no interface")
        })?;
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        let router = crate::router::get_router(&self.db, pool.router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", pool.router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;
        let interface = pool.interface();

        // The peer's own share of the pool plan, rather than a second
        // calculation of what one tunnel needs: the addresses and routes are
        // per-interface, so one node's change is applied by re-stating the
        // whole interface's addressing, and only its own peer is pushed.
        crate::provisioner::refresh_node_routes(&self.db, &pool).await?;
        let plan = crate::provisioner::plan_pool(&self.db, &pool).await?;
        let key = tunnel
            .peer_pubkey
            .as_deref()
            .map(lnvps_api_common::wireguard_key_to_base64);

        match key
            .as_ref()
            .and_then(|k| plan.peers.iter().find(|p| &p.public_key == k))
        {
            Some(peer) => tr
                .set_tunnel_peer(&interface, peer)
                .await
                .map_err(|e| anyhow!("failed to configure peer on {interface}: {}", e))?,
            // A tunnel that is disabled or has never presented a key has no
            // peer to push. Removing whatever is there under its key is the
            // same statement in the other direction.
            None => {
                if let Some(key) = &key {
                    tr.remove_tunnel_peer(&interface, key)
                        .await
                        .map_err(|e| anyhow!("failed to remove peer from {interface}: {}", e))?;
                }
            }
        }

        tr.sync_tunnel_addresses(&interface, &plan.addresses)
            .await
            .map_err(|e| anyhow!("failed to configure addresses on {interface}: {}", e))?;
        tr.sync_tunnel_routes(&interface, &plan.routes)
            .await
            .map_err(|e| anyhow!("failed to configure routes on {interface}: {}", e))?;
        Ok(())
    }

    /// Remove a tunnel interface from a router, after its pool is deleted.
    ///
    /// Idempotent: an interface that is already gone is the desired state, not
    /// a failure to retry forever.
    pub async fn remove_tunnel_interface(&self, router_id: u64, interface: &str) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;

        let existing = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?
            .into_iter()
            .find(|t| t.name == interface);
        let Some(existing) = existing else {
            info!("Tunnel interface {interface} is already gone from router {router_id}");
            return Ok(());
        };

        let id = existing.id.as_deref().unwrap_or(interface);
        tr.remove_tunnel(id)
            .await
            .map_err(|e| anyhow!("failed to remove tunnel interface: {}", e))?;
        // Drop the observed-state row too, or the admin API keeps reporting an
        // interface that is gone.
        match self.db.list_router_tunnels(router_id).await {
            Ok(cached) => {
                for t in cached.iter().filter(|t| t.name == interface) {
                    if let Err(e) = self.db.delete_router_tunnel(t.id).await {
                        warn!("Failed to drop tunnel from cache: {}", e);
                    }
                }
            }
            Err(e) => warn!("Failed to read tunnel cache: {}", e),
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

    /// Run the line item on-payment handling for a payment another process
    /// already marked paid.
    ///
    /// Re-marking it paid here would extend the subscription a second time, so
    /// an unpaid payment is a routing bug and is refused rather than completed.
    pub async fn apply_subscription_payment(&self, payment_id: &str) -> Result<()> {
        let id = hex::decode(payment_id)?;
        let payment = self.db.get_subscription_payment(&id).await?;
        if !payment.is_paid {
            bail!("Subscription payment {} is not paid", payment_id);
        }
        let result = self.subscription_handler.apply_payment(&payment).await?;
        // No Lightning node here to cancel the invoices with; they are already
        // expired in the database, so they can no longer settle.
        info!(
            "Expired {} competing upgrade payments",
            result.expired_competing_upgrades.len()
        );
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
                // Every path that reads a VM's state funnels through here, so
                // this is the one place traffic has to be sampled from. It runs
                // before the cache write only because the cache takes ownership
                // of the state.
                self.traffic_recorder.record_best_effort(vm.id, &s).await;
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
                    self.recover_missing_vm(vm).await?;
                }
            }
        }
        Ok(())
    }

    /// A VM was not where the database said it would be: find it, or rebuild it.
    ///
    /// Which host a VM sits on is not something a check should depend on. A VM
    /// absent from its recorded host is much more often one whose placement
    /// drifted (a hand-run migration, a failed one that landed anyway) than one
    /// that was destroyed, so the check re-points the database at the host that
    /// actually has it and reads the state from there, in the same pass.
    ///
    /// Rebuilding is reserved for the case where every enabled host answered
    /// and none of them has this VM. Spawning on weaker evidence tried to build
    /// a second copy of a live customer VM; it only failed because Proxmox ids
    /// are cluster-wide, and the failed spawn's rollback then wiped the live
    /// VM's MAC address.
    async fn recover_missing_vm(&self, vm: &Vm) -> Result<()> {
        let provisioner = self.subscription_handler.vm_provisioner();
        match provisioner.locate_vm(vm).await {
            // `locate_vm` has already corrected the placement; read the state
            // from where the VM really is so this pass is not wasted.
            Ok(VmLocation::Host(host_id)) => {
                if host_id == vm.host_id {
                    warn!(
                        "VM {} is on host {} after all; treating the failed state read as transient",
                        vm.id, host_id
                    );
                    return Ok(());
                }
                info!(
                    "VM {} was recorded on host {} but runs on host {}; placement corrected",
                    vm.id, vm.host_id, host_id
                );
                let moved = self.db.get_vm(vm.id).await?;
                let host = self.db.get_host(moved.host_id).await?;
                let client = get_host_client(&host, &self.settings.provisioner_config)?;
                match client.get_vm_state(&moved).await {
                    Ok(s) => self.vm_state_cache.set_state(moved.id, s).await?,
                    Err(e) => warn!(
                        "VM {} still unreadable on host {} after reconciling placement: {}",
                        moved.id, host.id, e
                    ),
                }
                Ok(())
            }
            Ok(VmLocation::Nowhere) => self.spawn_vm_internal(vm).await,
            Ok(VmLocation::Ambiguous(hosts)) => {
                warn!(
                    "VM {} exists on more than one host ({:?}); not rebuilding it",
                    vm.id, hosts
                );
                Ok(())
            }
            Ok(VmLocation::Unknown) => {
                warn!(
                    "VM {} not found, but some hosts could not be polled; not rebuilding it",
                    vm.id
                );
                Ok(())
            }
            Err(e) => {
                // Never fall through to a spawn here: not knowing where a VM is
                // is the one state in which building another one is worst.
                warn!(
                    "Could not establish where VM {} lives ({}); not rebuilding it",
                    vm.id, e
                );
                Ok(())
            }
        }
    }

    /// Resolve the authoritative expiry for a VM from its subscription.
    async fn vm_expires(&self, vm: &Vm) -> Option<DateTime<Utc>> {
        self.db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await
            .ok()?
            .expires
    }

    /// Discover VMs present on a host that aren't tracked in the database.
    ///
    /// A host VM is "unmanaged" when it maps to a database id (i.e. is within
    /// the managed id range) that has no live (non-deleted) VM record. Host VMs
    /// outside the managed range (e.g. Proxmox vmid < 100) can't be imported and
    /// are omitted.
    async fn list_unmanaged_vms(&self, host_id: u64) -> Result<Vec<lnvps_api_common::HostVmSpec>> {
        let host = self.db.get_host(host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;
        let all = client.list_host_vms().await?;

        let mut unmanaged = Vec::new();
        for spec in all {
            let Some(mapped) = spec.mapped_vm_id else {
                // Outside the managed id range, not importable
                continue;
            };
            match self.db.get_vm(mapped).await {
                Ok(vm) if !vm.deleted => continue, // already tracked
                _ => unmanaged.push(spec),
            }
        }
        Ok(unmanaged)
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
            vm,
        )
        .await?;

        // Placement may have just been corrected, and the remaining steps talk
        // to the host: scanning SSH host keys from the node the VM left reads
        // the wrong machine, or nothing at all.
        let vm = self.db.get_vm(vm.id).await.unwrap_or_else(|_| vm.clone());
        let host = match self.db.get_host(vm.host_id).await {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to load host {} for VM {}: {}", vm.host_id, vm.id, e);
                return Ok(());
            }
        };
        self.reconcile_vm_dns(&vm).await;
        self.capture_vm_ssh_host_keys(&vm, &host, &mut HostSshSession::default())
            .await;
        Ok(())
    }

    /// Best-effort capture of a VM's SSH host keys, so a customer can verify
    /// the host on first connect instead of trusting whatever key answers.
    ///
    /// Scanned from the Proxmox node rather than from here: the VM's address is
    /// often not routable from the API, and the node is already trusted with
    /// the VM. Only public keys are read — nothing runs inside the guest.
    ///
    /// Runs on the periodic VM check rather than at spawn: the keys do not
    /// exist until cloud-init has generated them and sshd is up, and a VM whose
    /// keys were never captured (or were cleared by a reinstall) self-heals on
    /// the next pass. A VM whose capture already covers every algorithm is
    /// skipped, so this costs nothing for a healthy VM.
    async fn capture_vm_ssh_host_keys(&self, vm: &Vm, host: &VmHost, ssh: &mut HostSshSession) {
        if vm.deleted || host.ssh_key.is_none() {
            return;
        }
        let captured = vm
            .ssh_host_keys
            .as_deref()
            .map(parse_ssh_host_keys)
            .unwrap_or_default();
        if capture_is_complete(&captured) {
            return;
        }
        if !matches!(
            self.vm_state_cache.get_state(vm.id).await.map(|s| s.state),
            Some(VmRunningStates::Running)
        ) {
            return;
        }
        let Some(ip) = self.vm_scan_address(vm).await else {
            return;
        };
        // A guest that blocks port 22, never runs sshd, or offers fewer
        // algorithms than a scan asks for would otherwise be scanned on every
        // check for the life of the VM. One attempt per hour still captures
        // the keys within an hour of the guest becoming reachable.
        let attempt_key = host_key_attempt_key(vm.id);
        if let Ok(Some(v)) = self.kv.get(&attempt_key).await
            && v.len() == 8
        {
            let last = u64::from_le_bytes(v.as_slice().try_into().unwrap_or_default());
            // A clock stepped backwards leaves a stamp in the future; wait it
            // out rather than panic.
            let waited = (Utc::now().timestamp() as u64).saturating_sub(last);
            if waited < HOST_KEY_SCAN_RETRY_SECS {
                return;
            }
        }
        let now = Utc::now().timestamp() as u64;
        if let Err(e) = self.kv.store(&attempt_key, &now.to_le_bytes()).await {
            warn!("[host-keys] vm {}: failed to record attempt: {}", vm.id, e);
        }
        let Some(ssh) = ssh.get_or_connect(host).await else {
            return;
        };
        // Bounded so an unreachable or half-open guest cannot hold the check.
        let scan = match ssh
            .execute(&format!(
                "ssh-keyscan -T 5 -t {} {ip}",
                SCANNED_KEY_FAMILIES.join(",")
            ))
            .await
        {
            Ok((_, out)) => out,
            Err(e) => {
                warn!("[host-keys] vm {}: keyscan failed: {}", vm.id, e);
                return;
            }
        };
        // A non-zero exit still prints the keys it did get, so the output is
        // what decides. A scan opens one connection per algorithm and can time
        // out on some of them, so what came back is merged into what is stored
        // rather than replacing it, and a short capture is scanned again later.
        if parse_ssh_host_keys(&scan).is_empty() {
            debug!("[host-keys] vm {}: no keys in scan of {}", vm.id, ip);
            return;
        }
        let merged = merge_ssh_host_keys(&ip, vm.ssh_host_keys.as_deref(), &scan);
        if Some(merged.as_str()) == vm.ssh_host_keys.as_deref() {
            return;
        }
        if let Err(e) = self.db.set_vm_ssh_host_keys(vm.id, Some(&merged)).await {
            warn!("[host-keys] vm {}: failed to store keys: {}", vm.id, e);
        }
    }

    /// The address to scan a VM's host keys on: its first assigned IP, v4
    /// preferred because a node without IPv6 egress cannot reach the other.
    async fn vm_scan_address(&self, vm: &Vm) -> Option<String> {
        // Assignments are stored as CIDR; ssh-keyscan wants the bare address.
        // Parsed rather than trimmed: the result is interpolated into a command
        // on the host, so only something that is definitely an address goes in.
        let addrs: Vec<std::net::IpAddr> = self
            .db
            .list_vm_ip_assignments(vm.id)
            .await
            .ok()?
            .into_iter()
            .filter(|i| !i.deleted)
            .filter_map(|i| i.ip.split('/').next()?.parse().ok())
            .collect();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .map(|a| a.to_string())
    }

    /// Best-effort reconciliation of missing DNS records for a VM's IPs.
    ///
    /// DNS is best-effort during spawn (a failed forward/reverse record must not
    /// block or tear down a deploy — notably OVH rejects a PTR until the forward
    /// name resolves). VMs whose records failed to create then self-heal here on
    /// the periodic VM check. For healthy VMs (all refs present) this is a cheap
    /// no-op that makes no provider API calls.
    async fn reconcile_vm_dns(&self, vm: &Vm) {
        let provisioner = self.subscription_handler.vm_provisioner();
        let network = &provisioner.network;

        let mut ips = match self.db.list_vm_ip_assignments(vm.id).await {
            Ok(i) => i,
            Err(e) => {
                warn!("[dns-reconcile] failed to list ips for vm {}: {}", vm.id, e);
                return;
            }
        };
        for a in &mut ips {
            let range = match self.db.get_ip_range(a.ip_range_id).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let want_fwd = range.forward_dns_server_id.is_some() && a.dns_forward_ref.is_none();
            let want_rev = range.reverse_dns_server_id.is_some() && a.dns_reverse_ref.is_none();
            if !want_fwd && !want_rev {
                continue;
            }

            let mut changed = false;
            if want_fwd {
                match network.update_forward_ip_dns(a).await {
                    Ok(_) => changed = true,
                    Err(e) => warn!("[dns-reconcile] forward failed for {}: {}", a.ip, e),
                }
            }
            if want_rev {
                match network.update_reverse_ip_dns(a).await {
                    Ok(_) => changed = true,
                    Err(e) => warn!("[dns-reconcile] reverse failed for {}: {}", a.ip, e),
                }
            }
            if changed && let Err(e) = self.db.update_vm_ip_assignment(a).await {
                warn!(
                    "[dns-reconcile] failed to persist dns refs for {}: {}",
                    a.ip, e
                );
            }
        }
    }

    /// Check multiple VMs on a single host using bulk API
    async fn check_vms_on_host(&self, host_id: u64, vms: &[&Vm]) -> Result<()> {
        debug!("Checking {} VMs on host {}", vms.len(), host_id);
        let host = self.db.get_host(host_id).await?;
        let client = get_host_client(&host, &self.settings.provisioner_config)?;

        let states = client.get_all_vm_states().await?;
        let state_map: HashMap<u64, VmRunningState> = states.into_iter().collect();

        // Every VM here lives on the same node, so the host key scans share one
        // session instead of paying a handshake per guest.
        let mut host_ssh = HostSshSession::default();

        for vm in vms {
            self.handle_vm_state(
                state_map
                    .get(&vm.id)
                    .map(|s| s.clone())
                    .context("VM not found in bulk response"),
                &vm,
            )
            .await?;
            // Self-heal any DNS records that failed to create during spawn.
            self.reconcile_vm_dns(vm).await;
            // This sweep is the only pass that visits every VM, so capture has
            // to hang off it; the single-VM check only runs on customer action.
            self.capture_vm_ssh_host_keys(vm, &host, &mut host_ssh)
                .await;
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
            "Your VM #{} has been created!\n\nOS: {}\nCPU: {} vCPU\nRAM: {} GB\nDisk: {} GB\n{}",
            vm.id,
            image,
            resources.cpu,
            resources.memory / crate::GB,
            resources.disk_size / crate::GB,
            ip_lines,
        );
        let admin_msg = format!(
            "VM #{} has been created.\n\nOS: {}\nCPU: {} vCPU\nRAM: {} GB\nDisk: {} GB\n{}",
            vm.id,
            image,
            resources.cpu,
            resources.memory / crate::GB,
            resources.disk_size / crate::GB,
            ip_lines,
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
            // Skip deletion if there are still pending (unexpired) payments
            // outstanding, or an on-chain deposit was detected in the mempool
            // but has not confirmed yet (issue #194).
            let now = Utc::now();
            if self
                .db
                .list_vm_subscription_payments(vm.id)
                .await
                .map(|ps| ps.iter().any(|p| payment_blocks_unpaid_vm_deletion(p, now)))
                .unwrap_or(false)
            {
                info!(
                    "VM {} has pending or detected unpaid payments, skipping deletion",
                    vm.id
                );
                continue;
            }
            info!("Deleting unpaid VM {}", vm.id);
            // Never-paid (new) VMs carry no customer data, so purge them entirely
            // rather than leaving a soft-deleted row and orphaned subscription.
            if let Err(e) = provisioner.delete_vm(vm.id, true).await {
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

        // Runs after the sweep that produced the numbers, and gates itself to
        // an hourly cadence internally.
        if let Err(e) = self.check_transfer_quotas().await {
            error!("Failed to check transfer quotas: {}", e);
        }

        self.set_last_check_vms(Utc::now()).await?;
        Ok(())
    }

    /// Percentages of a VM's monthly transfer allowance that trigger a warning.
    ///
    /// 80 is early enough to act on with most of the month's usage still ahead;
    /// 100 is the one that matters. Descending so the highest crossed threshold
    /// is the one reported — a VM that jumps from 50% to 105% between passes
    /// should be told it is over, not that it is at 80%.
    const TRANSFER_WARN_THRESHOLDS: [u8; 2] = [100, 80];

    /// How often the allowance check runs.
    ///
    /// Not every VM sweep: the sweep is every 30 seconds, the figures move
    /// slowly, and the check costs an aggregate query per metered VM.
    const CHECK_TRANSFER_SECONDS: i64 = 3600;

    /// Key marking a warning as already sent, scoped to the VM, the quota month
    /// and the threshold.
    ///
    /// Month-scoped so a new month starts clean without anything having to
    /// expire or be swept, and threshold-scoped so crossing 80% does not
    /// suppress the later 100% warning.
    fn transfer_warned_key(vm_id: u64, period_start: NaiveDate, threshold: u8) -> String {
        format!("vm-transfer-warned:{vm_id}:{period_start}:{threshold}")
    }

    /// Warn customers whose VMs are at or past their monthly transfer
    /// allowance.
    ///
    /// Warning only — nothing here throttles, suspends or bills. The figures
    /// come from hypervisor interface counters and include traffic that is not
    /// billable internet egress, so they are not yet a basis for enforcement.
    async fn check_transfer_quotas(&self) -> Result<()> {
        let last_check = self.get_last_check_transfer().await?;
        if Utc::now().signed_duration_since(last_check).num_seconds() < Self::CHECK_TRANSFER_SECONDS
        {
            return Ok(());
        }

        let (period_start, period_end) = quota_period(Utc::now().date_naive());

        // Allowances live on templates, and there are far fewer templates than
        // VMs, so they are resolved once here rather than per VM.
        let mut standard_quota: HashMap<u64, Option<u32>> = HashMap::new();
        for t in self.db.list_vm_templates().await? {
            standard_quota.insert(t.id, t.transfer_gb);
        }

        for vm in self.db.list_vms().await? {
            if vm.deleted {
                continue;
            }
            // A custom template is 1:1 with its VM, so unlike the standard ones
            // it cannot be pre-loaded and is fetched only for VMs that have one.
            let quota_gb = match (vm.template_id, vm.custom_template_id) {
                (Some(t), _) => standard_quota.get(&t).copied().flatten(),
                (_, Some(t)) => match self.db.get_custom_vm_template(t).await {
                    Ok(t) => t.transfer_gb,
                    Err(e) => {
                        warn!("Failed to load custom template for VM {}: {}", vm.id, e);
                        continue;
                    }
                },
                _ => None,
            };
            // Unmetered: there is no allowance to be near.
            let Some(quota_gb) = quota_gb.filter(|g| *g > 0) else {
                continue;
            };

            if let Err(e) = self
                .check_vm_transfer_quota(&vm, quota_gb, period_start, period_end)
                .await
            {
                warn!("Failed to check transfer quota for VM {}: {}", vm.id, e);
            }
        }

        self.set_last_check_transfer(Utc::now()).await?;
        Ok(())
    }

    /// Warn about one VM if it has crossed a threshold it has not been warned
    /// about this month.
    async fn check_vm_transfer_quota(
        &self,
        vm: &Vm,
        quota_gb: u32,
        period_start: NaiveDate,
        period_end: NaiveDate,
    ) -> Result<()> {
        let (_, bytes_out) = self
            .db
            .get_vm_traffic_total(vm.id, period_start, period_end)
            .await?;

        let quota_bytes = quota_gb as u64 * 1_000_000_000;
        let used_pct = (bytes_out as f64 / quota_bytes as f64 * 100.0) as u64;

        let Some(threshold) = Self::TRANSFER_WARN_THRESHOLDS
            .into_iter()
            .find(|t| used_pct >= *t as u64)
        else {
            return Ok(());
        };

        let key = Self::transfer_warned_key(vm.id, period_start, threshold);
        if self.kv.get(&key).await?.is_some() {
            return Ok(());
        }

        let used_gb = bytes_out as f64 / 1_000_000_000.0;
        let message = if threshold >= 100 {
            format!(
                "VM {} has used {:.1} GB of its {} GB monthly outbound transfer allowance ({}%).\n\n\
                 Your VM has not been throttled, suspended or charged for the excess — this is a \
                 notification only. The allowance resets on {}.",
                vm.id,
                used_gb,
                quota_gb,
                used_pct,
                period_end.succ_opt().unwrap_or(period_end)
            )
        } else {
            format!(
                "VM {} has used {:.1} GB of its {} GB monthly outbound transfer allowance ({}%).\n\n\
                 The allowance resets on {}. Nothing changes if you exceed it — this is an early \
                 notice, not a warning of any action.",
                vm.id,
                used_gb,
                quota_gb,
                used_pct,
                period_end.succ_opt().unwrap_or(period_end)
            )
        };

        self.queue_notification(
            vm.user_id,
            message,
            Some(format!(
                "VM {} transfer allowance {}% used",
                vm.id, used_pct
            )),
        )
        .await;

        // Marked only after the notification is queued, so a failure to queue
        // is retried on the next pass rather than silently suppressed.
        self.kv.store(&key, &[1u8]).await?;
        Ok(())
    }

    pub async fn get_last_check_transfer(&self) -> Result<DateTime<Utc>> {
        let Some(v) = self.kv.get("worker-last-check-transfer").await? else {
            return Ok(DateTime::UNIX_EPOCH);
        };
        let timestamp = if v.len() == 8 {
            u64::from_le_bytes(v.as_slice().try_into()?)
        } else {
            0
        };
        Ok(DateTime::from_timestamp(timestamp as _, 0).unwrap_or(DateTime::UNIX_EPOCH))
    }

    pub async fn set_last_check_transfer(&self, ts: DateTime<Utc>) -> Result<()> {
        let t = ts.timestamp() as u64;
        self.kv
            .store("worker-last-check-transfer", &t.to_le_bytes())
            .await?;
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

    /// Send a bulk message to the customers selected by `target`.
    ///
    /// Returns a one-line summary used as the job result (visible on the
    /// `/jobs/feedback` stream).
    async fn process_bulk_message(
        &self,
        subject: String,
        message: String,
        admin_user_id: u64,
        target: Option<BulkMessageTarget>,
    ) -> Result<String> {
        let target = target.unwrap_or_default();
        info!("Processing bulk message: '{}' target={:?}", subject, target);

        let recipients = self.db.get_bulk_message_recipients(&target).await?;
        let total_recipients = recipients.len();

        if total_recipients == 0 {
            info!("No recipients matched for bulk message '{}'", subject);
            let summary = format!("Bulk message '{}' matched no recipients", subject.trim());
            self.queue_notification(
                admin_user_id,
                summary.clone(),
                Some("Bulk Message Complete".to_string()),
            )
            .await;
            return Ok(summary);
        }

        // Users with no usable contact method are reported rather than
        // silently skipped: they are exactly the people a maintenance notice
        // fails to reach, and the admin needs to know who they are.
        let (reachable, unreachable): (Vec<_>, Vec<_>) = recipients
            .into_iter()
            .partition(|u| !u.contact_methods().is_empty());
        let skipped_count = unreachable.len();

        info!(
            "Sending bulk message to {} of {} matched recipients ({} unreachable)",
            reachable.len(),
            total_recipients,
            skipped_count
        );

        let mut sent_count = 0;
        let mut failed_count = 0;

        for customer in reachable {
            // Personalize the message with customer name if available
            let personalized_message = if let Some(ref name) = customer.billing_name {
                format!("Dear {},\n\n{}", name, message)
            } else {
                format!("Dear Customer,\n\n{}", message)
            };

            // send_notification fans out over every channel the user wants
            // (email, NIP-17, Telegram, WhatsApp)
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

        let summary = format!(
            "Bulk message '{}' completed. Sent: {}, Failed: {}, Unreachable: {}, Matched: {}",
            subject.trim(),
            sent_count,
            failed_count,
            skipped_count,
            total_recipients
        );
        info!("{}", summary);

        let mut admin_report = format!(
            "Bulk message '{}' completed.\nSent: {}\nFailed: {}\nUnreachable (no contact method): {}\nMatched recipients: {}",
            subject, sent_count, failed_count, skipped_count, total_recipients
        );
        if !unreachable.is_empty() {
            admin_report.push_str("\n\nUsers with no contact method (not messaged):\n");
            for user in &unreachable {
                admin_report.push_str(&format!("- user #{}\n", user.id));
            }
        }

        self.queue_notification(
            admin_user_id,
            admin_report,
            Some("Bulk Message Complete".to_string()),
        )
        .await;

        Ok(summary)
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

        // Patch config + firewall configuration for all VMs on this host
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
                info!("Patching VM {} on host {}", vm.id, host.name);
                match FullVmInfo::load(vm.id, self.db.clone()).await {
                    Ok(vm_config) => {
                        // Re-apply the VM config when what's on the host no
                        // longer matches the database (e.g. template upgrades
                        // or manual edits on the hypervisor).
                        match client.patch_config(&vm_config).await {
                            Ok(drift) if !drift.is_empty() => {
                                info!(
                                    "Re-configured VM {} on host {} (drift: {})",
                                    vm.id,
                                    host.name,
                                    drift.join(", ")
                                );
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("Failed to patch config for VM {}: {}", vm.id, e);
                            }
                        }
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
        let ssh_host = lnvps_api_common::host::extract_host_from_url(&host.ip);

        // Connect to host via SSH
        let mut ssh = SshClient::new();
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
            .await
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
            WorkJob::PatchHost { host_id } => {
                let mut host = self.db.get_host(*host_id).await?;
                info!("Patching host {}", host.name);
                self.patch_host(&mut host).await?;
            }
            WorkJob::PatchHosts => {
                let mut hosts = self.reconcile_hosts().await?;
                let total = hosts.len();
                let mut failed = 0usize;
                for host in &mut hosts {
                    info!("Patching host {}", host.name);
                    // Each host is an independent hypervisor, so one that is
                    // unreachable or misconfigured must not stop the sweep
                    // before the hosts after it in the list — which it did,
                    // silently, for as long as that host stayed broken. The
                    // per-host `PatchHost { host_id }` still reports its
                    // failure: that one is tied to a waiting admin request.
                    if let Err(e) = self.patch_host(host).await {
                        failed += 1;
                        warn!("Failed to patch host {}: {}", host.name, e);
                    }
                }
                if failed > 0 {
                    warn!("Patched hosts with {}/{} failures", failed, total);
                }
            }
            WorkJob::CheckVm { vm_id } => {
                let vm = self.db.get_vm(*vm_id).await?;
                self.check_vm(&vm).await?;
            }
            // Addressed to an operator, not to this worker: it is published to
            // a per-cluster stream (#254) and only reaches here if someone
            // sends it to the general queue by mistake. Nothing to do — the
            // operator's own poll is the backstop either way.
            WorkJob::ReconcileAppDeployment { deployment_id } => {
                warn!(
                    "Ignoring ReconcileAppDeployment({deployment_id}) on the worker queue: it \
                     belongs on the deployment's app-cluster stream"
                );
            }
            WorkJob::ApplySubscriptionPayment { payment_id } => {
                self.apply_subscription_payment(payment_id).await?;
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
                target,
            } => {
                let summary = self
                    .process_bulk_message(
                        subject.clone(),
                        message.clone(),
                        *admin_user_id,
                        target.clone(),
                    )
                    .await?;

                return Ok(Some(summary));
            }
            WorkJob::CheckVms => {
                self.check_vms().await?;
            }
            WorkJob::CheckSubscriptions => {
                self.check_subscriptions().await?;
            }
            WorkJob::ProcessReferralPayouts => {
                self.referral_payouts.process_payouts().await?;
            }
            WorkJob::SyncRouterState => {
                self.sync_router_state().await?;
            }
            #[cfg(feature = "linux-ssh")]
            WorkJob::ProbeMarketplaceNode => {
                self.probe_marketplace_node().await?;
            }
            #[cfg(not(feature = "linux-ssh"))]
            WorkJob::ProbeMarketplaceNode => {
                // A build without SSH cannot log into a probe VM, and a probe
                // that only created and destroyed one would report a node
                // healthy on the strength of nothing.
                warn!("Marketplace probes need the linux-ssh feature; skipping");
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
            WorkJob::SyncTunnelPool { pool_id } => {
                self.sync_tunnel_pool(*pool_id).await?;
            }
            WorkJob::RemoveTunnelInterface {
                router_id,
                interface,
            } => {
                self.remove_tunnel_interface(*router_id, interface).await?;
            }
            WorkJob::ReconcileTunnelPeers { pool_id } => {
                self.reconcile_tunnel_peers(*pool_id).await?;
            }
            WorkJob::SyncNodeTunnel { tunnel_id } => {
                self.sync_node_tunnel(*tunnel_id).await?;
            }
            WorkJob::DeleteVm {
                vm_id,
                reason,
                admin_user_id,
                purge,
            } => {
                let vm = self.db.get_vm(*vm_id).await?;
                if vm.deleted {
                    return Ok(None);
                }

                // A VM that has never had its first (purchase) payment confirmed
                // carries no customer data, so purge it entirely. Super-admins
                // can also force a purge of any VM (including paid ones) via the
                // `purge` flag.
                let ever_paid = self
                    .db
                    .get_subscription_by_line_item_id(vm.subscription_line_item_id)
                    .await
                    .map(|s| s.is_setup)
                    .unwrap_or(false);
                let hard_delete = *purge || !ever_paid;

                // Delete the VM via provisioner
                let provisioner = self.subscription_handler.vm_provisioner();
                provisioner.delete_vm(*vm_id, hard_delete).await?;

                // A hard delete removes the VM row (and its history), so logging
                // a vm_history entry afterwards would fail the foreign key.
                // Only record deletion history for soft-deleted VMs.
                if !hard_delete {
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
                }

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
            WorkJob::ReinstallVm {
                vm_id,
                user_id,
                old_image_id,
                new_image_id,
                reply_channel,
            } => {
                // Run the reinstall pipeline (stop → wipe → import → start) on the
                // provisioner and report the outcome on the reply channel so the
                // waiting API request can respond to the user. Running here (rather
                // than inline in the web request) serialises reinstall with spawn
                // and other host operations, preventing the reinstall-vs-spawn race.
                let result = self
                    .subscription_handler
                    .vm_provisioner()
                    .reinstall_vm(*vm_id)
                    .await;

                let feedback = match &result {
                    Ok(()) => {
                        // The guest generates fresh host keys on reinstall, so
                        // the stored ones now belong to an image that is gone;
                        // clearing them makes the next check re-capture. The
                        // scan-attempt stamp goes with them, or the customer
                        // would be shown no keys until the retry window passed
                        // — exactly when they are looking for the fingerprint.
                        if let Err(e) = self.db.set_vm_ssh_host_keys(*vm_id, None).await {
                            warn!(
                                "Failed to clear ssh host keys after reinstall of VM {}: {}",
                                vm_id, e
                            );
                        }
                        if let Err(e) = self
                            .kv
                            .store(&host_key_attempt_key(*vm_id), &0u64.to_le_bytes())
                            .await
                        {
                            warn!(
                                "Failed to reset ssh host key scan stamp for VM {}: {}",
                                vm_id, e
                            );
                        }
                        // Record history + refresh cached state only on success.
                        self.vm_history_logger
                            .log_vm_reinstalled(
                                *vm_id,
                                *user_id,
                                *old_image_id,
                                *new_image_id,
                                None,
                            )
                            .await
                            .ok();
                        if let Err(e) = self
                            .work_commander
                            .send(WorkJob::CheckVm { vm_id: *vm_id })
                            .await
                        {
                            warn!(
                                "Failed to queue CheckVm after reinstall of VM {}: {}",
                                vm_id, e
                            );
                        }
                        JobFeedback::create_job_completed_feedback(
                            reply_channel.clone(),
                            "ReinstallVm".to_string(),
                            None,
                        )
                    }
                    Err(e) => JobFeedback::create_job_failed_feedback(
                        reply_channel.clone(),
                        "ReinstallVm".to_string(),
                        e.to_string(),
                    ),
                };
                if let Err(e) = self.feedback.publish(feedback).await {
                    warn!(
                        "Failed to publish ReinstallVm reply for VM {}: {}",
                        vm_id, e
                    );
                }
                return Ok(Some(match &result {
                    Ok(()) => format!("VM {} reinstalled successfully", vm_id),
                    Err(e) => format!("VM {} reinstall failed: {}", vm_id, e),
                }));
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
                vm_id,
                admin_user_id,
                refund_from_date,
                reason,
                payment_method,
                lightning_invoice,
            } => {
                let vm = self.db.get_vm(*vm_id).await?;
                let outcome = self
                    .refunds
                    .process(
                        *vm_id,
                        *admin_user_id,
                        *refund_from_date,
                        reason.as_deref(),
                        payment_method,
                        lightning_invoice.as_deref(),
                    )
                    .await?;

                // A refunded VM is deleted — the customer has been paid for the
                // time it would have run. Queued rather than done here so the
                // one deletion path (provisioner, history, notifications) stays
                // the only one; the refund itself is already committed, so a
                // deletion that fails is a VM to clean up, not money to chase.
                if let Err(e) = self
                    .work_commander
                    .send(WorkJob::DeleteVm {
                        vm_id: *vm_id,
                        reason: Some(format!(
                            "Refunded {} {}",
                            outcome.booked_amount, outcome.currency
                        )),
                        admin_user_id: Some(*admin_user_id),
                        purge: false,
                    })
                    .await
                {
                    error!(
                        "VM {} was refunded but the deletion job could not be queued: {}",
                        vm_id, e
                    );
                }

                self.queue_notification(
                    vm.user_id,
                    format!(
                        "Your VM #{} has been refunded {} sats and will be deleted.",
                        vm_id,
                        outcome.amount_msat / 1000
                    ),
                    Some(format!("[VM{}] Refunded", vm_id)),
                )
                .await;

                return Ok(Some(format!(
                    "VM {} refunded {} msat (fee {} msat, preimage {}), booked {} {} across {} \
                     payment(s)",
                    vm_id,
                    outcome.amount_msat,
                    outcome.fee_msat,
                    outcome.preimage.as_deref().unwrap_or("none"),
                    outcome.booked_amount,
                    outcome.currency,
                    outcome.refund_rows
                )));
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
            WorkJob::CreateCustomVm {
                user_id,
                spec,
                image_id,
                ssh_key_id,
                ref_code,
                admin_user_id,
                reason,
            } => {
                info!(
                    "Admin {} creating custom VM for user {}",
                    admin_user_id, user_id
                );
                let template = spec.to_template()?;

                let provisioner = self.subscription_handler.vm_provisioner();
                let vm = provisioner
                    .provision_custom(*user_id, template, *image_id, *ssh_key_id, ref_code.clone())
                    .await?;

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
                    "Admin {} successfully created custom VM {} for user {}",
                    admin_user_id, vm.id, user_id
                );

                return Ok(Some(format!(
                    "Custom VM {} created successfully for user {}",
                    vm.id, user_id
                )));
            }
            WorkJob::ListUnmanagedVms {
                host_id,
                reply_channel,
            } => {
                // Discover VMs on the host that aren't tracked in the database
                // and reply with the JSON list on the requested temp channel.
                let result = self.list_unmanaged_vms(*host_id).await;
                let feedback = match &result {
                    Ok(list) => match serde_json::to_string(list) {
                        Ok(json) => JobFeedback::create_job_completed_feedback(
                            reply_channel.clone(),
                            "ListUnmanagedVms".to_string(),
                            Some(json),
                        ),
                        Err(e) => JobFeedback::create_job_failed_feedback(
                            reply_channel.clone(),
                            "ListUnmanagedVms".to_string(),
                            e.to_string(),
                        ),
                    },
                    Err(e) => JobFeedback::create_job_failed_feedback(
                        reply_channel.clone(),
                        "ListUnmanagedVms".to_string(),
                        e.to_string(),
                    ),
                };
                if let Err(e) = self.feedback.publish(feedback).await {
                    warn!("Failed to publish ListUnmanagedVms reply: {}", e);
                }
                return Ok(Some(match &result {
                    Ok(list) => format!("Found {} unmanaged VM(s) on host {}", list.len(), host_id),
                    Err(e) => format!("Discovery failed for host {}: {}", host_id, e),
                }));
            }
            WorkJob::ImportVm {
                host_id,
                host_vm_id,
                user_id,
                admin_user_id,
                reason,
            } => {
                info!(
                    "Admin {} importing host VM {} on host {} for user {}",
                    admin_user_id, host_vm_id, host_id, user_id
                );
                let provisioner = self.subscription_handler.vm_provisioner();
                let vm = provisioner
                    .import_vm(*host_id, *host_vm_id, *user_id)
                    .await?;

                let metadata = Some(serde_json::json!({
                    "admin_user_id": admin_user_id,
                    "admin_action": true,
                    "imported": true,
                    "host_vm_id": host_vm_id,
                    "reason": reason
                }));
                if let Err(e) = self
                    .vm_history_logger
                    .log_vm_created(&vm, Some(*user_id), metadata)
                    .await
                {
                    error!("Failed to log VM {} import: {}", vm.id, e);
                }

                return Ok(Some(format!(
                    "VM {} imported successfully for user {}",
                    vm.id, user_id
                )));
            }
            WorkJob::MigrateVm {
                vm_id,
                target_host_id,
                live,
                admin_user_id,
                reason,
            } => {
                info!(
                    "Migrating VM {} to host {} ({})",
                    vm_id,
                    target_host_id,
                    if *live { "online" } else { "offline" }
                );
                let provisioner = self.subscription_handler.vm_provisioner();
                match provisioner
                    .migrate_vm(*vm_id, *target_host_id, *live, *admin_user_id)
                    .await
                {
                    Ok(vm) => {
                        // The destination enforces its own firewall/ipset state,
                        // so re-apply the ruleset rather than assuming it came
                        // across with the VM.
                        if let Err(e) = self
                            .work_commander
                            .send(WorkJob::ApplyVmFirewall { vm_id: vm.id })
                            .await
                        {
                            warn!("Failed to queue firewall re-apply for VM {}: {}", vm.id, e);
                        }
                        return Ok(Some(format!(
                            "VM {} migrated to host {}{}",
                            vm.id,
                            target_host_id,
                            reason
                                .as_ref()
                                .map(|r| format!(" ({})", r))
                                .unwrap_or_default()
                        )));
                    }
                    Err(e) => {
                        error!("Failed to migrate VM {}: {}", vm_id, e);
                        self.queue_admin_notification(
                            format!(
                                "Failed to migrate VM {} to host {}:\n{}",
                                vm_id, target_host_id, e
                            ),
                            Some(format!("VM {} Migration Failed", vm_id)),
                        )
                        .await;
                        return Err(e);
                    }
                }
            }
            WorkJob::ReconcileVmHosts => {
                let provisioner = self.subscription_handler.vm_provisioner();
                let drifts = provisioner.reconcile_vm_hosts().await?;
                for drift in &drifts {
                    // Nobody asked this API for the move, so surface it: either
                    // an operator migrated by hand, or a VM moved on its own
                    // (HA fail-over) and capacity planning needs to know.
                    let (subject, body) = if drift.is_host_move() {
                        (
                            format!("VM {} Moved Host", drift.vm_id),
                            format!(
                                "VM {} was found on host {} but was recorded on host {}. \
                                 The database has been updated to match the host.",
                                drift.vm_id, drift.to_host_id, drift.from_host_id
                            ),
                        )
                    } else {
                        (
                            format!("VM {} Disk Moved", drift.vm_id),
                            format!(
                                "VM {} is still on host {}, but its disk was found on storage {}. \
                                 The database has been updated to match the host.",
                                drift.vm_id,
                                drift.to_host_id,
                                drift.storage.as_deref().unwrap_or("(unknown)")
                            ),
                        )
                    };
                    self.queue_admin_notification(body, Some(subject)).await;
                }
                if !drifts.is_empty() {
                    return Ok(Some(format!(
                        "Reconciled placement of {} VM(s)",
                        drifts.len()
                    )));
                }
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
            WorkJob::PatchIpRangeDns {
                ip_range_id,
                admin_user_id: _,
            } => {
                let n = self.patch_ip_range_dns(*ip_range_id).await?;
                return Ok(Some(format!(
                    "Patched DNS for {} IP assignment(s) in range {}",
                    n, ip_range_id
                )));
            }
        }
        Ok(None)
    }

    /// Re-apply forward + reverse DNS records for every (non-deleted) IP assignment
    /// in a range, reconciling them to the range's current DNS server configuration.
    /// Per-assignment DNS failures are logged and skipped so one bad record can't
    /// abort the whole batch; only the DB save is treated as fatal.
    async fn patch_ip_range_dns(&self, ip_range_id: u64) -> Result<usize> {
        // Validate the range exists
        let _range = self.db.get_ip_range(ip_range_id).await?;
        let provisioner = self.subscription_handler.vm_provisioner();
        let network = &provisioner.network;

        let mut assignments = self.db.list_vm_ip_assignments_in_range(ip_range_id).await?;
        info!(
            "Patching DNS for {} IP assignment(s) in range {}",
            assignments.len(),
            ip_range_id
        );
        let mut count = 0usize;
        for a in &mut assignments {
            if let Err(e) = network.update_forward_ip_dns(a).await {
                warn!("[patch-dns] forward failed for {}: {}", a.ip, e);
            }
            if let Err(e) = network.update_reverse_ip_dns(a).await {
                warn!("[patch-dns] reverse failed for {}: {}", a.ip, e);
            }
            self.db.update_vm_ip_assignment(a).await?;
            count += 1;
        }
        Ok(count)
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

        let hosts = self.reconcile_hosts().await?;
        let clients: Vec<(String, Arc<dyn VmHostClient>)> = hosts
            .iter()
            .filter_map(
                |host| match get_host_client(host, &self.settings.provisioner_config) {
                    Ok(c) => Some((host.name.clone(), c)),
                    Err(e) => {
                        warn!("Failed to get client for host {}: {}", host.name, e);
                        None
                    }
                },
            )
            .collect();

        download_images_on_hosts(clients, &images).await;
        Ok(())
    }

    /// Hosts that reconciliation sweeps must visit.
    ///
    /// Every host, including disabled ones and hosts in disabled regions:
    /// `enabled` means "place no new VMs here", not "this host is gone". A
    /// disabled host still runs the VMs it already has, so it still needs OS
    /// images (a reinstall or rebuild imports one from local storage) and still
    /// needs its cpu/memory/disk sizes re-read, or its capacity is frozen at
    /// whatever it was when someone disabled it. `PatchHost { host_id }` — what
    /// the admin force-sync calls — patches a disabled host quite happily, so
    /// skipping it in the sweep only made the two disagree.
    ///
    /// Placement and pricing use the filtered [`LNVpsDbBase::list_hosts`]
    /// instead; those must not offer a disabled host.
    async fn reconcile_hosts(&self) -> Result<Vec<VmHost>> {
        Ok(self.db.list_hosts_all().await?)
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

        // Send ConfigureVm job to update VM network configuration.
        // Deleted VMs no longer exist on the host, so there is nothing to configure.
        if vm.deleted {
            info!(
                "Skipping ConfigureVm for deleted VM {} after unassigning IP {}",
                vm.id, assignment.ip
            );
        } else {
            self.work_commander
                .send(WorkJob::ConfigureVm {
                    vm_id: vm.id,
                    admin_user_id,
                })
                .await?;
        }

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
                if msg.job.can_skip() {
                    if let Err(e) = self.work_commander.ack(&msg.id).await {
                        error!("Failed to acknowledge job {}: {}", stream_id, e);
                    }
                } else {
                    // Left unacked so it is retried with backoff; stash why, so
                    // that if it burns through its attempts the dead-lettered
                    // entry says what kept failing instead of just naming the
                    // job.
                    let reason = e.to_string();
                    if let Err(rec_err) = self.work_commander.record_failure(&msg.id, &reason).await
                    {
                        warn!(
                            "Failed to record failure reason for job {}: {}",
                            stream_id, rec_err
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Download `images` on every host concurrently.
///
/// Hosts run in parallel (each host is an independent hypervisor with its own
/// network/storage), while images on a single host are downloaded sequentially
/// to avoid saturating that host's storage backend.  Failures are logged and
/// do not abort other hosts or images.
pub(crate) async fn download_images_on_hosts(
    clients: Vec<(String, Arc<dyn VmHostClient>)>,
    images: &[VmOsImage],
) {
    // One task per host rather than one shared `join_all` future, so a single
    // host's long download (wget/decompress/checksum over SSH) cannot delay the
    // others. Images on a single host are still processed sequentially to avoid
    // saturating that host's storage.
    let tasks: Vec<_> = clients
        .into_iter()
        .map(|(host_name, client)| {
            let images = images.to_vec();
            tokio::spawn(async move {
                for image in &images {
                    info!("Checking image {} on host {}", image.url, host_name);
                    if let Err(e) = client.download_os_image(image).await {
                        warn!(
                            "Failed to download image {} on host {}: {}",
                            image.url, host_name, e
                        );
                    }
                }
            })
        })
        .collect();
    for t in tasks {
        if let Err(e) = t.await {
            warn!("Image download task panicked: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::{MockNode, MockOnChainProvider};
    use crate::settings::mock_settings;
    use crate::subscription::SubscriptionHandler;
    use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate};
    use lnvps_db::{
        LNVpsDbBase, LineItemType, Subscription, SubscriptionLineItem, SubscriptionPayment,
        UserSshKey, Vm,
    };

    mod download_parallel {
        use super::*;
        use crate::host::dummy_host::DummyVmHost;
        use async_trait::async_trait;
        use lnvps_api_common::retry::OpResult;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        /// Wraps DummyVmHost, tracking concurrency of download_os_image calls.
        struct ConcurrencyTrackingHost {
            inner: DummyVmHost,
            active: Arc<AtomicUsize>,
            max_active: Arc<AtomicUsize>,
            downloads: Arc<AtomicUsize>,
        }

        impl ConcurrencyTrackingHost {
            fn new(
                active: Arc<AtomicUsize>,
                max_active: Arc<AtomicUsize>,
                downloads: Arc<AtomicUsize>,
            ) -> Self {
                Self {
                    inner: DummyVmHost::new(),
                    active,
                    max_active,
                    downloads,
                }
            }
        }

        #[async_trait]
        impl VmHostClient for ConcurrencyTrackingHost {
            async fn get_info(&self) -> OpResult<crate::host::VmHostInfo> {
                self.inner.get_info().await
            }

            async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
                let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.downloads.fetch_add(1, Ordering::SeqCst);
                self.inner.download_os_image(image).await
            }

            async fn generate_mac(&self, vm: &Vm) -> OpResult<String> {
                self.inner.generate_mac(vm).await
            }

            async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
                self.inner.start_vm(vm).await
            }

            async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
                self.inner.stop_vm(vm).await
            }

            async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
                self.inner.reset_vm(vm).await
            }

            async fn create_vm(&self, req: &crate::host::FullVmInfo) -> OpResult<()> {
                self.inner.create_vm(req).await
            }

            async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
                self.inner.delete_vm(vm).await
            }

            async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()> {
                self.inner.unlink_primary_disk(vm).await
            }

            async fn import_template_disk(&self, cfg: &crate::host::FullVmInfo) -> OpResult<()> {
                self.inner.import_template_disk(cfg).await
            }

            async fn resize_disk(&self, cfg: &crate::host::FullVmInfo) -> OpResult<()> {
                self.inner.resize_disk(cfg).await
            }

            async fn get_vm_state(&self, vm: &Vm) -> OpResult<lnvps_api_common::VmRunningState> {
                self.inner.get_vm_state(vm).await
            }

            async fn get_all_vm_states(
                &self,
            ) -> OpResult<Vec<(u64, lnvps_api_common::VmRunningState)>> {
                self.inner.get_all_vm_states().await
            }

            async fn configure_vm(&self, cfg: &crate::host::FullVmInfo) -> OpResult<()> {
                self.inner.configure_vm(cfg).await
            }

            async fn patch_firewall(&self, cfg: &crate::host::FullVmInfo) -> OpResult<()> {
                self.inner.patch_firewall(cfg).await
            }

            async fn get_time_series_data(
                &self,
                vm: &Vm,
                series: crate::host::TimeSeries,
            ) -> OpResult<Vec<crate::host::TimeSeriesData>> {
                self.inner.get_time_series_data(vm, series).await
            }

            async fn connect_terminal(&self, vm: &Vm) -> OpResult<crate::host::TerminalStream> {
                self.inner.connect_terminal(vm).await
            }
        }

        /// Regression: image downloads must run in parallel across hosts
        /// (previously hosts were processed strictly sequentially).
        #[tokio::test]
        async fn test_download_images_parallel_across_hosts() {
            let active = Arc::new(AtomicUsize::new(0));
            let max_active = Arc::new(AtomicUsize::new(0));
            let downloads = Arc::new(AtomicUsize::new(0));

            let clients: Vec<(String, Arc<dyn VmHostClient>)> = (0..3)
                .map(|i| {
                    (
                        format!("host-{i}"),
                        Arc::new(ConcurrencyTrackingHost::new(
                            active.clone(),
                            max_active.clone(),
                            downloads.clone(),
                        )) as Arc<dyn VmHostClient>,
                    )
                })
                .collect();

            let img = |id: u64, url: &str| VmOsImage {
                id,
                distribution: lnvps_db::OsDistribution::Debian,
                flavour: "server".to_string(),
                version: "12".to_string(),
                enabled: true,
                release_date: Utc::now(),
                url: url.to_string(),
                cpu_arch: CpuArch::X86_64,
                default_username: None,
                sha2: None,
                sha2_url: None,
            };
            let images = vec![
                img(1, "https://example.com/a.qcow2"),
                img(2, "https://example.com/b.qcow2"),
            ];

            download_images_on_hosts(clients, &images).await;

            // 3 hosts x 2 images
            assert_eq!(downloads.load(Ordering::SeqCst), 6);
            // Hosts overlap: at some point more than one download was active
            assert!(
                max_active.load(Ordering::SeqCst) >= 2,
                "downloads did not overlap across hosts (max_active = {})",
                max_active.load(Ordering::SeqCst)
            );
            // Images per host are sequential: never more than one per host,
            // so the max possible is the number of hosts
            assert!(max_active.load(Ordering::SeqCst) <= 3);
        }
    }

    async fn setup_worker(db: Arc<MockDb>) -> Result<Worker> {
        setup_worker_with_delete_after(db, 0).await
    }

    /// Regression test: one broken host must not abort the `PatchHosts` sweep.
    ///
    /// The loop used `?`, so the first host whose client could not be built (a
    /// bad address, a hypervisor that is down) ended the job and every host
    /// after it in the list went unpatched — for as long as that host stayed
    /// broken, which is indefinitely.
    #[tokio::test]
    async fn test_patch_hosts_continues_past_a_failing_host() -> Result<()> {
        let db = Arc::new(MockDb::default());
        // A Proxmox host whose address cannot be parsed: `get_host_client`
        // fails, which is what used to abort the sweep.
        db.create_host(&VmHost {
            kind: VmHostKind::Proxmox,
            region_id: 1,
            name: "broken-host".to_string(),
            ip: "not a url".to_string(),
            enabled: true,
            ..Default::default()
        })
        .await?;
        db.create_host(&VmHost {
            kind: VmHostKind::Dummy,
            region_id: 1,
            name: "dummy-host".to_string(),
            enabled: true,
            ..Default::default()
        })
        .await?;

        let worker = setup_worker(db.clone()).await?;
        worker
            .try_job(&WorkJob::PatchHosts)
            .await
            .expect("a single unpatchable host must not fail the whole sweep");
        Ok(())
    }

    /// Regression test: reconciliation sweeps must visit disabled hosts too.
    ///
    /// Both the OS image download and `PatchHosts` listed hosts with
    /// `list_hosts()`, which hides disabled hosts and hosts in disabled regions.
    /// A disabled host therefore never received new images (a reinstall of a VM
    /// still living there then failed on a missing local image) and never had
    /// its cpu/memory/disk sizes re-read. `enabled` gates placement, not
    /// existence.
    #[tokio::test]
    async fn test_reconcile_hosts_include_disabled_hosts() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let enabled_id = db
            .create_host(&VmHost {
                kind: VmHostKind::Proxmox,
                region_id: 1,
                name: "enabled-host".to_string(),
                enabled: true,
                ..Default::default()
            })
            .await?;
        let disabled_id = db
            .create_host(&VmHost {
                kind: VmHostKind::Proxmox,
                region_id: 1,
                name: "disabled-host".to_string(),
                enabled: false,
                ..Default::default()
            })
            .await?;

        // Precondition: the placement listing is what used to be used here.
        assert!(
            db.list_hosts().await?.iter().all(|h| h.id != disabled_id),
            "precondition: list_hosts() hides disabled hosts"
        );

        let worker = setup_worker(db.clone()).await?;
        let targets = worker.reconcile_hosts().await?;

        assert!(
            targets.iter().any(|h| h.id == disabled_id),
            "a disabled host must still be reconciled"
        );
        assert!(
            targets.iter().any(|h| h.id == enabled_id),
            "an enabled host must still be reconciled"
        );
        Ok(())
    }

    /// A node whose probe cannot even be attempted must not have its host
    /// enabled.
    ///
    /// This is the gate the whole marketplace rests on: an enabled host is one
    /// LNVPS will place paying customers on, and the only thing that should
    /// open it is a VM having actually run there. A gate that opened on a
    /// failure — or on nothing at all — would put customers on hardware nobody
    /// has tested.
    #[cfg(feature = "linux-ssh")]
    #[tokio::test]
    async fn a_host_is_not_enabled_without_a_passing_probe() -> Result<()> {
        let mock = Arc::new(MockDb::empty());
        let db: Arc<dyn LNVpsDb> = mock.clone();
        let user_id = db.upsert_user(&[4u8; 32]).await?;
        let operator_id = db
            .insert_marketplace_operator(&lnvps_db::MarketplaceOperator {
                user_id,
                enabled: true,
                ..Default::default()
            })
            .await?;
        let node_id = db
            .insert_marketplace_node(&lnvps_db::MarketplaceNode {
                operator_id,
                name: "unproven".to_string(),
                status: lnvps_db::MarketplaceNodeStatus::Approved,
                ..Default::default()
            })
            .await?;
        let host_id = db
            .create_host(&VmHost {
                kind: lnvps_db::VmHostKind::MarketplaceNode,
                region_id: 1,
                name: "unproven".to_string(),
                enabled: false,
                marketplace_node_id: Some(node_id),
                ..Default::default()
            })
            .await?;

        let worker = setup_worker(mock.clone()).await?;
        // No tunnel, so the probe cannot even be specified. The sweep records
        // the failure and carries on rather than returning an error: this runs
        // from `handle_job`, and an error there stops every other job in the
        // batch.
        worker.probe_marketplace_node().await?;

        assert!(
            !db.get_host(host_id).await?.enabled,
            "a host was opened to customers without a VM ever running on it"
        );

        // Written down, so the node has a cooldown and an admin can see why it
        // never came into service.
        let (health, _) = db.list_marketplace_node_health(node_id, 10, 0).await?;
        assert_eq!(health.len(), 1, "an unprobeable node recorded nothing");
        assert!(!health[0].passed);
        assert!(
            health[0]
                .failure
                .as_deref()
                .unwrap_or_default()
                .contains("could not be specified"),
            "{:?}",
            health[0].failure
        );
        Ok(())
    }

    /// A node that cannot be probed must not monopolise every sweep.
    ///
    /// One node is probed per run, never-probed first. A node whose probe
    /// failed before it could be specified used to record nothing, so it stayed
    /// "never probed" forever: it was selected again five minutes later, and
    /// again, and no other node in the fleet was ever reached. A broken node
    /// silently disabled the health gate for every other operator's hardware.
    #[cfg(feature = "linux-ssh")]
    #[tokio::test]
    async fn an_unprobeable_node_does_not_starve_the_fleet() -> Result<()> {
        let mock = Arc::new(MockDb::empty());
        let db: Arc<dyn LNVpsDb> = mock.clone();
        let user_id = db.upsert_user(&[5u8; 32]).await?;
        let operator_id = db
            .insert_marketplace_operator(&lnvps_db::MarketplaceOperator {
                user_id,
                enabled: true,
                ..Default::default()
            })
            .await?;

        // Two nodes, neither probeable (no tunnel), so selection is decided
        // purely by what the previous sweep recorded.
        let mut node_ids = Vec::new();
        for name in ["first", "second"] {
            let node_id = db
                .insert_marketplace_node(&lnvps_db::MarketplaceNode {
                    operator_id,
                    name: name.to_string(),
                    status: lnvps_db::MarketplaceNodeStatus::Approved,
                    ..Default::default()
                })
                .await?;
            db.create_host(&VmHost {
                kind: lnvps_db::VmHostKind::MarketplaceNode,
                region_id: 1,
                name: name.to_string(),
                enabled: false,
                marketplace_node_id: Some(node_id),
                ..Default::default()
            })
            .await?;
            node_ids.push(node_id);
        }

        let worker = setup_worker(mock.clone()).await?;
        worker.probe_marketplace_node().await?;
        worker.probe_marketplace_node().await?;

        // The second sweep moved on: the first node is now inside its cooldown.
        for node_id in node_ids {
            let (health, _) = db.list_marketplace_node_health(node_id, 10, 0).await?;
            assert_eq!(
                health.len(),
                1,
                "node {node_id} was probed the wrong number of times"
            );
        }
        Ok(())
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
            node.clone(),
            Arc::new(MockOnChainProvider::default()),
            None,
            rates,
            lnvps_api_common::VatClient::new(),
            work_commander.clone(),
            cache.clone(),
        )?;
        Worker::new(
            db,
            work_commander,
            sub_handler,
            node,
            None,
            &settings,
            cache,
            None,
        )
        .await
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
                    subscription_type: LineItemType::Vps,
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
            ssh_key_id: Some(ssh_key_id),
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
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        }
    }

    /// Set the monthly transfer allowance on the mock's standard template.
    async fn set_template_transfer_gb(db: &Arc<MockDb>, gb: Option<u32>) {
        db.templates
            .lock()
            .await
            .get_mut(&1)
            .expect("mock template")
            .transfer_gb = gb;
    }

    /// Book outbound traffic for a VM in the current quota period.
    async fn book_traffic(db: &Arc<MockDb>, vm_id: u64, bytes_out: u64) {
        db.add_vm_traffic(vm_id, Utc::now().date_naive(), 0, bytes_out)
            .await
            .expect("book traffic");
    }

    fn warned_key(vm_id: u64, threshold: u8) -> String {
        let (period_start, _) = quota_period(Utc::now().date_naive());
        Worker::transfer_warned_key(vm_id, period_start, threshold)
    }

    /// A VM comfortably inside its allowance must not be told anything.
    #[tokio::test]
    async fn test_transfer_quota_below_threshold_is_silent() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        set_template_transfer_gb(&db, Some(100)).await;
        // 50 GB of a 100 GB allowance.
        book_traffic(&db, vm_id, 50_000_000_000).await;

        let worker = setup_worker(db.clone()).await?;
        worker.check_transfer_quotas().await?;

        assert!(worker.kv.get(&warned_key(vm_id, 80)).await?.is_none());
        assert!(worker.kv.get(&warned_key(vm_id, 100)).await?.is_none());
        Ok(())
    }

    /// Crossing 80% warns once, and only once for that month — the check runs
    /// repeatedly and must not mail the customer on every pass.
    #[tokio::test]
    async fn test_transfer_quota_warns_once_per_threshold() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        set_template_transfer_gb(&db, Some(100)).await;
        book_traffic(&db, vm_id, 85_000_000_000).await;

        let worker = setup_worker(db.clone()).await?;
        worker.check_transfer_quotas().await?;
        assert!(
            worker.kv.get(&warned_key(vm_id, 80)).await?.is_some(),
            "crossing 80% must warn"
        );

        // A second pass has nothing new to say. The hourly gate is cleared so
        // this exercises the per-threshold suppression, not the cadence.
        worker.set_last_check_transfer(DateTime::UNIX_EPOCH).await?;
        worker.check_transfer_quotas().await?;
        assert!(
            worker.kv.get(&warned_key(vm_id, 100)).await?.is_none(),
            "still under 100%, so the 100% warning must not fire"
        );
        Ok(())
    }

    /// A VM that jumps straight past its allowance must be told it is over, not
    /// that it is at 80%.
    #[tokio::test]
    async fn test_transfer_quota_reports_highest_threshold_crossed() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        set_template_transfer_gb(&db, Some(100)).await;
        book_traffic(&db, vm_id, 150_000_000_000).await;

        let worker = setup_worker(db.clone()).await?;
        worker.check_transfer_quotas().await?;

        assert!(
            worker.kv.get(&warned_key(vm_id, 100)).await?.is_some(),
            "over the allowance must report the 100% threshold"
        );
        assert!(
            worker.kv.get(&warned_key(vm_id, 80)).await?.is_none(),
            "the lower threshold must not also fire"
        );
        Ok(())
    }

    /// An unmetered plan has no allowance to be near, however much it sends.
    #[tokio::test]
    async fn test_transfer_quota_ignores_unmetered_plans() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        set_template_transfer_gb(&db, None).await;
        book_traffic(&db, vm_id, 900_000_000_000).await;

        let worker = setup_worker(db.clone()).await?;
        worker.check_transfer_quotas().await?;

        assert!(worker.kv.get(&warned_key(vm_id, 100)).await?.is_none());
        assert!(worker.kv.get(&warned_key(vm_id, 80)).await?.is_none());
        Ok(())
    }

    /// The check is hourly, not once per 30-second VM sweep: the figures move
    /// slowly and it costs a query per metered VM.
    #[tokio::test]
    async fn test_transfer_quota_check_is_rate_limited() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        set_template_transfer_gb(&db, Some(100)).await;

        let worker = setup_worker(db.clone()).await?;
        // First pass has nothing to report but stamps the check time.
        worker.check_transfer_quotas().await?;

        book_traffic(&db, vm_id, 150_000_000_000).await;
        worker.check_transfer_quotas().await?;
        assert!(
            worker.kv.get(&warned_key(vm_id, 100)).await?.is_none(),
            "a second pass within the hour must be skipped entirely"
        );

        worker.set_last_check_transfer(DateTime::UNIX_EPOCH).await?;
        worker.check_transfer_quotas().await?;
        assert!(
            worker.kv.get(&warned_key(vm_id, 100)).await?.is_some(),
            "once the cadence allows it, the warning fires"
        );
        Ok(())
    }

    /// Every state read funnels through `handle_vm_state`, so that is where
    /// traffic accounting has to happen — otherwise the periodic sweep, which
    /// is the only pass that visits every VM, would record nothing.
    ///
    /// The first read can only establish a baseline; the second is the one that
    /// has a difference to attribute.
    #[tokio::test]
    async fn test_handle_vm_state_records_traffic() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        let worker = setup_worker(db.clone()).await?;
        let vm = db.get_vm(vm_id).await?;

        let reading = |net_in: u64, net_out: u64| VmRunningState {
            state: VmRunningStates::Running,
            net_in,
            net_out,
            ..Default::default()
        };

        worker
            .handle_vm_state(Ok(reading(1_000, 4_000)), &vm)
            .await?;
        let today = Utc::now().date_naive();
        assert_eq!(
            db.get_vm_traffic_total(vm_id, today, today).await?,
            (0, 0),
            "a single reading has no difference to attribute"
        );

        worker
            .handle_vm_state(Ok(reading(1_250, 9_000)), &vm)
            .await?;
        assert_eq!(
            db.get_vm_traffic_total(vm_id, today, today).await?,
            (250, 5_000),
            "the sweep must fold the counter difference into today's row"
        );
        Ok(())
    }

    /// The periodic fleet sweep — not just the per-VM check dispatched on
    /// customer action — has to attempt host key capture, otherwise a VM nobody
    /// touches never gets any keys.
    #[tokio::test]
    async fn test_check_vms_on_host_attempts_host_key_capture() -> Result<()> {
        let db = Arc::new(MockDb::default());
        // A host with no SSH key is skipped outright, so the scan path needs one.
        db.hosts
            .lock()
            .await
            .get_mut(&1)
            .expect("mock host")
            .ssh_key = Some(lnvps_db::EncryptedString::from("not-a-usable-key"));
        let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
        db.insert_vm_ip_assignment(&VmIpAssignment {
            vm_id,
            ip_range_id: 1,
            ip: "10.0.0.5".to_string(),
            ..Default::default()
        })
        .await?;

        let worker = setup_worker(db.clone()).await?;
        // Capture only runs for a VM the cache believes is up.
        worker
            .vm_state_cache
            .set_state(
                vm_id,
                VmRunningState {
                    state: VmRunningStates::Running,
                    ..Default::default()
                },
            )
            .await?;

        let vm = db.get_vm(vm_id).await?;
        worker.check_vms_on_host(vm.host_id, &[&vm]).await?;

        // The scan itself needs a real SSH session to the host; the recorded
        // attempt is what proves the sweep reached capture.
        assert!(
            worker.kv.get(&host_key_attempt_key(vm_id)).await?.is_some(),
            "periodic sweep did not attempt host key capture"
        );
        Ok(())
    }

    /// Regression: unassigning an IP from a deleted VM must not queue a `ConfigureVm` job.
    ///
    /// A deleted VM no longer exists on the host, so reconfiguring it always
    /// fails; the job just churns in the queue.
    #[tokio::test]
    async fn test_unassign_vm_ip_skips_configure_for_deleted_vm() -> Result<()> {
        for deleted in [true, false] {
            let db = Arc::new(MockDb::default());
            let (vm_id, _) = add_vm_with_subscription(&db, Utc::now(), true).await?;
            if deleted {
                db.delete_vm(vm_id).await?;
            }
            let assignment_id = db
                .insert_vm_ip_assignment(&VmIpAssignment {
                    vm_id,
                    ip_range_id: 1,
                    ip: "10.0.0.5".to_string(),
                    ..Default::default()
                })
                .await?;

            let worker = setup_worker(db.clone()).await?;
            worker.unassign_vm_ip(assignment_id, None).await?;

            let queued =
                tokio::time::timeout(Duration::from_millis(100), worker.work_commander.recv())
                    .await;
            if deleted {
                assert!(
                    queued.is_err(),
                    "deleted VM must not get a ConfigureVm job after unassigning its IP"
                );
            } else {
                let jobs = queued.expect("live VM should get a job")?;
                assert!(
                    jobs.iter()
                        .any(|j| matches!(j.job, WorkJob::ConfigureVm { .. })),
                    "live VM should get a ConfigureVm job"
                );
            }
        }
        Ok(())
    }

    /// An unpaid VM (subscription not set up) older than 1 hour must be deleted by check_vms.
    #[tokio::test]
    async fn test_check_vms_deletes_unpaid_vm_after_one_hour() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        let (vm_id, _) = add_vm_with_subscription(&db, old, false).await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        // Never-paid VMs are purged entirely, not just soft-deleted.
        let vms = db.vms.lock().await;
        assert!(
            !vms.contains_key(&vm_id),
            "Unpaid VM older than 1 hour should be purged"
        );
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

        // VM should be purged because the only payment is expired.
        let vms = db.vms.lock().await;
        assert!(
            !vms.contains_key(&vm_id),
            "Unpaid VM with only an expired payment should still be purged"
        );
        Ok(())
    }

    /// Regression (#194): an unpaid VM (older than 1 hour) whose on-chain payment quote has
    /// expired must NOT be purged when a deposit was already detected in the mempool
    /// (`external_id` holds the deposit outpoint) — confirmation may simply be slow.
    #[tokio::test]
    async fn test_check_vms_skips_unpaid_vm_with_detected_onchain_deposit() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        let (vm_id, subscription_id) = add_vm_with_subscription(&db, old, false).await?;
        let user_id = db.get_vm(vm_id).await?.user_id;

        // Expired on-chain payment whose deposit was seen in the mempool (external_id set).
        let mut payment = make_subscription_payment(
            subscription_id,
            user_id,
            old,
            old.add(TimeDelta::hours(1)),
            3,
        );
        payment.payment_method = lnvps_db::PaymentMethod::OnChain;
        payment.external_id = Some("aabbccdd:0".to_string());
        db.insert_subscription_payment(&payment).await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        let vms = db.vms.lock().await;
        let deleted = vms.get(&vm_id).map(|v| v.deleted).unwrap_or(true);
        assert!(
            !deleted,
            "Unpaid VM with a detected (unconfirmed) on-chain deposit must not be purged"
        );
        Ok(())
    }

    /// An unpaid VM (older than 1 hour) with an expired on-chain payment and NO detected
    /// deposit must still be purged — the #194 guard only holds VMs with a mempool sighting.
    #[tokio::test]
    async fn test_check_vms_deletes_unpaid_vm_with_expired_undetected_onchain_payment() -> Result<()>
    {
        let db = Arc::new(MockDb::default());
        let old = Utc::now().sub(TimeDelta::hours(2));
        let (vm_id, subscription_id) = add_vm_with_subscription(&db, old, false).await?;
        let user_id = db.get_vm(vm_id).await?.user_id;

        let mut payment = make_subscription_payment(
            subscription_id,
            user_id,
            old,
            old.add(TimeDelta::hours(1)),
            4,
        );
        payment.payment_method = lnvps_db::PaymentMethod::OnChain;
        db.insert_subscription_payment(&payment).await?;

        let worker = setup_worker(db.clone()).await?;
        worker.check_vms().await?;

        let vms = db.vms.lock().await;
        assert!(
            !vms.contains_key(&vm_id),
            "Unpaid VM with an expired on-chain payment and no detected deposit should be purged"
        );
        Ok(())
    }

    #[test]
    fn test_payment_blocks_unpaid_vm_deletion() {
        let now = Utc::now();
        let base = make_subscription_payment(
            1,
            1,
            now.sub(TimeDelta::hours(2)),
            now.sub(TimeDelta::hours(1)),
            5,
        );

        // Expired lightning payment: does not block.
        assert!(!payment_blocks_unpaid_vm_deletion(&base, now));

        // Unexpired payment: blocks.
        let mut p = base.clone();
        p.expires = now.add(TimeDelta::minutes(10));
        assert!(payment_blocks_unpaid_vm_deletion(&p, now));

        // Expired on-chain with detected deposit: blocks (#194).
        let mut p = base.clone();
        p.payment_method = lnvps_db::PaymentMethod::OnChain;
        p.external_id = Some("txid:0".to_string());
        assert!(payment_blocks_unpaid_vm_deletion(&p, now));

        // Expired on-chain without detected deposit: does not block.
        let mut p = base.clone();
        p.payment_method = lnvps_db::PaymentMethod::OnChain;
        assert!(!payment_blocks_unpaid_vm_deletion(&p, now));

        // Expired lightning with external_id (not on-chain): does not block.
        let mut p = base.clone();
        p.external_id = Some("abc".to_string());
        assert!(!payment_blocks_unpaid_vm_deletion(&p, now));

        // Paid payment never blocks, even with detected deposit.
        let mut p = base.clone();
        p.payment_method = lnvps_db::PaymentMethod::OnChain;
        p.external_id = Some("txid:0".to_string());
        p.is_paid = true;
        assert!(!payment_blocks_unpaid_vm_deletion(&p, now));
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

    #[test]
    fn test_expiry_lead_window_capped_by_interval() {
        let mut sub = Subscription {
            id: 0,
            user_id: 0,
            company_id: 1,
            name: "s".to_string(),
            description: None,
            created: Utc::now(),
            expires: None,
            is_active: true,
            is_setup: true,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: true,
            external_id: None,
        };

        // Monthly billing: the fixed 1-day lead is well under half a month, so
        // the window is unchanged at 1 day.
        assert_eq!(expiry_lead_window(&sub), TimeDelta::days(1));
        assert_eq!(subscription_interval(&sub), TimeDelta::days(30));

        // Daily billing: the lead is capped at half the interval (12h), so a
        // freshly-renewed VM (expiry = now + 1 day) is not immediately "expiring
        // soon" again — the double-charge bug (VM 1828).
        sub.interval_type = IntervalType::Day;
        assert_eq!(subscription_interval(&sub), TimeDelta::days(1));
        assert_eq!(expiry_lead_window(&sub), TimeDelta::hours(12));

        // A 2-day interval caps at 1 day (== the max), not more.
        sub.interval_amount = 2;
        assert_eq!(expiry_lead_window(&sub), TimeDelta::days(1));

        // Yearly billing stays at the 1-day max.
        sub.interval_amount = 1;
        sub.interval_type = IntervalType::Year;
        assert_eq!(expiry_lead_window(&sub), TimeDelta::days(1));
    }

    #[test]
    fn test_format_lead_window() {
        assert_eq!(format_lead_window(TimeDelta::days(1)), "1 day");
        assert_eq!(format_lead_window(TimeDelta::days(2)), "2 days");
        assert_eq!(format_lead_window(TimeDelta::hours(12)), "12 hours");
        assert_eq!(format_lead_window(TimeDelta::hours(1)), "1 hour");
        // Sub-hour windows clamp to a minimum of one hour.
        assert_eq!(format_lead_window(TimeDelta::minutes(30)), "1 hour");
    }

    /// Regression for the VM 1828 double charge: a subscription billed on a
    /// 1-day interval that was just renewed (expiry = now + 1 day) must NOT be
    /// treated as "expiring soon", so auto-renewal does not fire seconds after
    /// the customer paid.
    #[tokio::test]
    async fn test_freshly_renewed_daily_sub_not_expiring_soon() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let created = Utc::now();
        let (_vm_id, subscription_id) = add_vm_with_subscription(&db, created, true).await?;
        {
            let mut subs = db.subscriptions.lock().await;
            let s = subs.get_mut(&subscription_id).unwrap();
            s.interval_type = IntervalType::Day;
            s.interval_amount = 1;
            s.auto_renewal_enabled = true;
            // Just renewed: new expiry is one full interval out.
            s.expires = Some(Utc::now().add(TimeDelta::days(1)));
        }
        let sub = db.get_subscription(subscription_id).await?;

        let worker = setup_worker(db.clone()).await?;
        // last_check just before now (a normal worker cadence).
        worker
            .handle_subscription_state(&sub, Utc::now().sub(TimeDelta::minutes(1)))
            .await?;

        let notes = count_notifications(&worker, "Expiring Soon").await
            + count_notifications(&worker, "Auto-Renewed").await;
        assert_eq!(
            notes, 0,
            "a freshly-renewed 1-day sub must not be 'expiring soon' (double-charge bug)"
        );
        Ok(())
    }

    /// A 1-day-interval subscription genuinely near expiry (within the capped
    /// 12h lead window) still fires the expiring-soon handling.
    #[tokio::test]
    async fn test_daily_sub_within_lead_window_is_expiring_soon() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let created = Utc::now().sub(TimeDelta::days(1));
        let (_vm_id, subscription_id) = add_vm_with_subscription(&db, created, true).await?;
        {
            let mut subs = db.subscriptions.lock().await;
            let s = subs.get_mut(&subscription_id).unwrap();
            s.interval_type = IntervalType::Day;
            s.interval_amount = 1;
            s.auto_renewal_enabled = false; // exercise the plain warning path
            // 6h from expiry: inside the 12h capped lead window.
            s.expires = Some(Utc::now().add(TimeDelta::hours(6)));
        }
        let sub = db.get_subscription(subscription_id).await?;

        let worker = setup_worker(db.clone()).await?;
        worker
            .handle_subscription_state(&sub, Utc::now().sub(TimeDelta::days(1)))
            .await?;

        let notes = count_notifications(&worker, "Expiring Soon").await;
        assert!(
            notes >= 1,
            "a daily sub within the 12h lead window must warn/auto-renew (got {notes})"
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

    /// A route server with a mock router and one pool on it.
    async fn setup_pool(db: &Arc<MockDb>, port: u16) -> Result<u64> {
        use lnvps_api_common::generate_wireguard_keypair;
        use lnvps_db::{Router, RouterKind, TunnelPool};

        {
            let mut routers = db.router.lock().await;
            routers.entry(1).or_insert(Router {
                id: 1,
                name: "rs1".to_string(),
                enabled: true,
                kind: RouterKind::MockRouter,
                url: "mock://".to_string(),
                token: "".into(),
            });
        }
        {
            let mut regions = db.regions.lock().await;
            regions.entry(1).or_insert(lnvps_db::Region {
                id: 1,
                name: "Mock".to_string(),
                enabled: true,
                company_id: 1,
                country_code: Some("IE".to_string()),
            });
        }
        let keys = generate_wireguard_keypair()?;
        Ok(db
            .insert_tunnel_pool(&TunnelPool {
                router_id: 1,
                region_id: 1,
                name: "pool".to_string(),
                listen_addr: "192.0.2.1".to_string(),
                listen_port: port,
                private_key: keys.private_key.into(),
                public_key: keys.public_key,
                cidr4: Some("10.66.0.0/24".to_string()),
                mtu: 1420,
                enabled: true,
                ..Default::default()
            })
            .await?)
    }

    /// An approved node with a backing host, holding a tunnel from `pool_id`
    /// and one guest address.
    async fn setup_node_tunnel(db: &Arc<MockDb>, pool_id: u64) -> Result<lnvps_db::Tunnel> {
        use lnvps_db::{
            MarketplaceNode, MarketplaceNodeStatus, MarketplaceOperator, VmHost, VmHostKind,
        };

        let dbt: Arc<dyn LNVpsDb> = db.clone();
        let user_id = dbt.upsert_user(&[7u8; 32]).await?;
        let operator_id = dbt
            .insert_marketplace_operator(&MarketplaceOperator {
                user_id,
                enabled: true,
                ..Default::default()
            })
            .await?;
        let node_id = dbt
            .insert_marketplace_node(&MarketplaceNode {
                operator_id,
                name: "rack 1".to_string(),
                status: MarketplaceNodeStatus::Approved,
                ..Default::default()
            })
            .await?;
        let host_id = dbt
            .create_host(&VmHost {
                kind: VmHostKind::MarketplaceNode,
                region_id: 1,
                name: "node-host".to_string(),
                ip: String::new(),
                enabled: false,
                marketplace_node_id: Some(node_id),
                ..Default::default()
            })
            .await?;

        let vm_id = {
            let mut vms = db.vms.lock().await;
            let id = vms.keys().max().copied().unwrap_or(0) + 1;
            vms.insert(
                id,
                lnvps_db::Vm {
                    id,
                    host_id,
                    ..Default::default()
                },
            );
            id
        };
        dbt.insert_vm_ip_assignment(&lnvps_db::VmIpAssignment {
            vm_id,
            ip: "203.0.113.5".to_string(),
            ..Default::default()
        })
        .await?;

        let node = dbt.get_marketplace_node(node_id).await?;
        let allocation =
            crate::provisioner::allocate_node_tunnel(&dbt, &node, &[0x11u8; 32]).await?;
        assert_eq!(allocation.tunnel.pool_id, Some(pool_id));
        Ok(allocation.tunnel)
    }

    /// Configuring the interface is only half the job: the peers allocated from
    /// the pool have to be on it, with an address on each link and a route for
    /// each guest, or the node has a tunnel that carries nothing.
    #[tokio::test]
    async fn test_sync_tunnel_pool_realises_its_peers() -> Result<()> {
        use crate::mocks::MockRouter;

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        let tunnel = setup_node_tunnel(&db, pool_id).await?;
        let mr = MockRouter::new();
        mr.clear().await;

        let worker = setup_worker(db.clone()).await?;
        worker.sync_tunnel_pool(pool_id).await?;

        let interface = format!("wgln{pool_id}");
        let peers = mr.peers(&interface).await;
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].public_key,
            lnvps_api_common::wireguard_key_to_base64(&[0x11u8; 32])
        );
        // The node's own address plus exactly the guest address assigned to it:
        // this list is the anti-spoof boundary, not just a routing hint.
        assert_eq!(
            peers[0].allowed_ips,
            vec!["10.66.0.2/32".to_string(), "203.0.113.5/32".to_string()]
        );
        // One address for the pool, carrying the block's prefix: every node in
        // it is on-link, so the route server does not carry an address per
        // node on a single interface.
        assert_eq!(
            mr.interface_addresses(&interface).await,
            vec!["10.66.0.1/24".to_string()]
        );
        // AllowedIPs picks which peer a packet belongs to; it does not put the
        // packet on the tunnel. Without these routes the guest's return traffic
        // is dropped as unroutable — and without the pool's own block, so is
        // everything addressed to the nodes themselves, because an address on a
        // point-to-point interface does not route the rest of its prefix.
        assert_eq!(
            mr.interface_routes(&interface).await,
            vec!["10.66.0.0/24".to_string(), "203.0.113.5/32".to_string()]
        );
        assert_eq!(tunnel.pool_id, Some(pool_id));

        mr.clear().await;
        Ok(())
    }

    /// A peer that has vanished from a route server is drift to put back and
    /// report, not an allocation to forget: forgetting it would hand the node's
    /// addresses to somebody else while the node still uses them.
    #[tokio::test]
    async fn test_reconcile_tunnel_peers_repairs_and_reports_drift() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::{Router as _, WireguardPeer};

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        setup_node_tunnel(&db, pool_id).await?;
        let mr = MockRouter::new();
        mr.clear().await;
        let worker = setup_worker(db.clone()).await?;
        worker.sync_tunnel_pool(pool_id).await?;
        let interface = format!("wgln{pool_id}");

        // Nothing changed: a working peer must not be rewritten on every poll,
        // and `wg` reports allowed IPs in its own order.
        let drift = worker.reconcile_tunnel_peers(pool_id).await?;
        assert!(drift.is_empty(), "{drift}");

        // The route server lost the peer (a reboot without persistence).
        let tr = mr.tunnel().unwrap();
        let key = lnvps_api_common::wireguard_key_to_base64(&[0x11u8; 32]);
        tr.remove_tunnel_peer(&interface, &key).await.unwrap();
        let drift = worker.reconcile_tunnel_peers(pool_id).await?;
        assert_eq!(drift.missing, vec![key.clone()]);
        assert_eq!(mr.peers(&interface).await.len(), 1, "not put back");

        // A peer whose allowed IPs no longer match its allocation is carrying
        // the wrong anti-spoof list, which is a security boundary, not cosmetic.
        tr.set_tunnel_peer(
            &interface,
            &WireguardPeer {
                public_key: key.clone(),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let drift = worker.reconcile_tunnel_peers(pool_id).await?;
        assert_eq!(drift.changed, vec![key.clone()]);
        assert_eq!(
            mr.peers(&interface).await[0].allowed_ips,
            vec!["10.66.0.2/32".to_string(), "203.0.113.5/32".to_string()]
        );

        // LNVPS owns `wgln*` outright, so a key no allocation accounts for is
        // either a revoked node or somebody else's. Both are removed.
        tr.set_tunnel_peer(
            &interface,
            &WireguardPeer {
                public_key: "c3RyYXk=".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let drift = worker.reconcile_tunnel_peers(pool_id).await?;
        assert_eq!(drift.unclaimed, vec!["c3RyYXk=".to_string()]);
        assert_eq!(mr.peers(&interface).await.len(), 1);

        mr.clear().await;
        Ok(())
    }

    /// Peers are configured *on* an interface. Creating it here would duplicate
    /// the pool sync and hide the fact that it never ran.
    #[tokio::test]
    async fn test_reconcile_tunnel_peers_needs_the_interface() -> Result<()> {
        use crate::mocks::MockRouter;

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        let mr = MockRouter::new();
        mr.clear().await;
        let worker = setup_worker(db.clone()).await?;

        let err = worker
            .reconcile_tunnel_peers(pool_id)
            .await
            .expect_err("peers were reconciled onto an interface that is not there");
        assert!(format!("{err}").contains("SyncTunnelPool"), "{err}");

        mr.clear().await;
        Ok(())
    }

    /// One node getting an address must not wait behind a reconcile of every
    /// other node on the same route server — and a tunnel that stops being
    /// realisable takes its peer off the interface.
    #[tokio::test]
    async fn test_sync_node_tunnel_pushes_and_withdraws_one_peer() -> Result<()> {
        use crate::mocks::MockRouter;

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        let tunnel = setup_node_tunnel(&db, pool_id).await?;
        let mr = MockRouter::new();
        mr.clear().await;
        use crate::router::Router as _;
        let worker = setup_worker(db.clone()).await?;
        // The interface exists but has no peers, which is exactly the state
        // right after a node asks for its tunnel.
        worker.sync_tunnel_pool(pool_id).await?;
        let interface = format!("wgln{pool_id}");
        let tr = mr.tunnel().unwrap();
        let key = lnvps_api_common::wireguard_key_to_base64(&[0x11u8; 32]);
        tr.remove_tunnel_peer(&interface, &key).await.unwrap();

        worker.sync_node_tunnel(tunnel.id).await?;
        assert_eq!(mr.peers(&interface).await.len(), 1);

        // Disabling the allocation is a statement in the other direction: the
        // peer comes off rather than being left behind carrying traffic.
        let dbt: Arc<dyn LNVpsDb> = db.clone();
        dbt.update_tunnel(&lnvps_db::Tunnel {
            enabled: false,
            ..tunnel.clone()
        })
        .await?;
        worker.sync_node_tunnel(tunnel.id).await?;
        assert!(mr.peers(&interface).await.is_empty());

        mr.clear().await;
        Ok(())
    }

    /// A tunnel allocated outside a pool has no interface to be configured on,
    /// and inventing one would write a peer onto somebody else's tunnel.
    #[tokio::test]
    async fn test_sync_node_tunnel_without_a_pool_is_refused() -> Result<()> {
        let db = Arc::new(MockDb::empty());
        let dbt: Arc<dyn LNVpsDb> = db.clone();
        let user_id = dbt.upsert_user(&[3u8; 32]).await?;
        let tunnel_id = dbt
            .insert_tunnel(&lnvps_db::Tunnel {
                user_id,
                name: "hand-made".to_string(),
                enabled: true,
                ..Default::default()
            })
            .await?;

        let worker = setup_worker(db.clone()).await?;
        let err = worker
            .sync_node_tunnel(tunnel_id)
            .await
            .expect_err("a pool-less tunnel was pushed to an interface");
        assert!(
            format!("{err}").contains("not allocated from a pool"),
            "{err}"
        );
        Ok(())
    }

    /// A pool is not a description of an interface somebody configured by hand:
    /// syncing it creates the interface, with LNVPS's own key and port.
    #[tokio::test]
    async fn test_sync_tunnel_pool_creates_the_interface() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::{Router as _, TunnelConfig};

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        let mr = MockRouter::new();
        mr.clear().await;

        let worker = setup_worker(db.clone()).await?;
        worker.sync_tunnel_pool(pool_id).await?;

        let tunnels = mr.tunnel().unwrap().list_tunnels().await.unwrap();
        assert_eq!(tunnels.len(), 1);
        // Named from the pool id under a fixed prefix, so a managed interface
        // cannot collide with one the route server already carries.
        assert_eq!(tunnels[0].name, format!("wgln{pool_id}"));
        assert_eq!(tunnels[0].local_addr.as_deref(), Some("192.0.2.1"));
        let pool = db.get_tunnel_pool(pool_id).await?;
        match &tunnels[0].config {
            TunnelConfig::Wireguard(c) => {
                assert_eq!(c.listen_port, Some(51820));
                assert_eq!(
                    c.public_key.as_deref(),
                    Some(lnvps_api_common::wireguard_key_to_base64(&pool.public_key).as_str()),
                    "the interface came up with a key nodes were not given"
                );
            }
            other => panic!("expected a WireGuard interface, got {other:?}"),
        }

        // The observed-state cache knows about it, so the admin API stops
        // reporting the interface as missing.
        assert_eq!(db.list_router_tunnels(1).await?.len(), 1);

        // Syncing again is a no-op rather than a recreate: re-applying drops
        // every peer with the interface, so a working node must not be cut by
        // a routine sync.
        worker.sync_tunnel_pool(pool_id).await?;
        let after = mr.tunnel().unwrap().list_tunnels().await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, tunnels[0].id);

        mr.clear().await;
        Ok(())
    }

    /// A stored pair that disagrees with itself would be pushed to the router
    /// and handed to every node, and none of them could hand shake. Better to
    /// refuse than to configure an interface nobody can reach.
    #[tokio::test]
    async fn test_sync_tunnel_pool_refuses_a_mismatched_keypair() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::Router as _;

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        let mut pool = db.get_tunnel_pool(pool_id).await?;
        pool.public_key = vec![0xaa; 32];
        db.update_tunnel_pool(&pool).await?;

        let mr = MockRouter::new();
        mr.clear().await;
        let worker = setup_worker(db.clone()).await?;

        assert!(worker.sync_tunnel_pool(pool_id).await.is_err());
        assert!(
            mr.tunnel()
                .unwrap()
                .list_tunnels()
                .await
                .unwrap()
                .is_empty(),
            "an interface was configured from a keypair that does not match"
        );

        mr.clear().await;
        Ok(())
    }

    /// Deleting a pool has to take the interface with it, or a route server is
    /// left carrying a configured tunnel that no record mentions.
    #[tokio::test]
    async fn test_remove_tunnel_interface() -> Result<()> {
        use crate::mocks::MockRouter;
        use crate::router::Router as _;

        let db = Arc::new(MockDb::empty());
        let pool_id = setup_pool(&db, 51820).await?;
        let mr = MockRouter::new();
        mr.clear().await;

        let worker = setup_worker(db.clone()).await?;
        worker.sync_tunnel_pool(pool_id).await?;
        assert_eq!(mr.tunnel().unwrap().list_tunnels().await.unwrap().len(), 1);

        let interface = db.get_tunnel_pool(pool_id).await?.interface();
        worker.remove_tunnel_interface(1, &interface).await?;
        assert!(
            mr.tunnel()
                .unwrap()
                .list_tunnels()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_router_tunnels(1).await?.is_empty(),
            "the cache still reports an interface that is gone"
        );

        // Removing it again is the desired state, not a failure to retry
        // forever — the job runs after the row is already deleted.
        worker.remove_tunnel_interface(1, &interface).await?;

        mr.clear().await;
        Ok(())
    }

    /// Bulk messaging must obey the target and must *report* the owners it
    /// could not reach — the failure mode of the manual workaround this
    /// replaced (issue #387) was that Nostr-only owners were silently missed.
    #[tokio::test]
    async fn test_bulk_message_targets_host_and_reports_unreachable() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let reachable = db.upsert_user(&[1u8; 32]).await?;
        let unreachable = db.upsert_user(&[2u8; 32]).await?;
        let other_host_owner = db.upsert_user(&[3u8; 32]).await?;
        {
            let mut users = db.users.lock().await;
            let u = users.get_mut(&reachable).unwrap();
            u.contact_nip17 = true;
            u.billing_name = Some("Nostr Owner".to_string());
            users.get_mut(&other_host_owner).unwrap().contact_nip17 = true;
        }
        {
            let mut hosts = db.hosts.lock().await;
            let mut second = hosts.get(&1).unwrap().clone();
            second.id = 2;
            second.name = "mock-host-2".to_string();
            hosts.insert(2, second);
        }
        {
            let mut vms = db.vms.lock().await;
            for (id, host_id, user_id) in [
                (1u64, 1u64, reachable),
                (2, 1, unreachable),
                (3, 2, other_host_owner),
            ] {
                vms.insert(
                    id,
                    Vm {
                        id,
                        host_id,
                        user_id,
                        ..Default::default()
                    },
                );
            }
        }

        let worker = setup_worker(db.clone()).await?;
        let summary = worker
            .process_bulk_message(
                "Storage maintenance".to_string(),
                "Your VM will reboot".to_string(),
                reachable,
                Some(BulkMessageTarget {
                    host_ids: Some(vec![1]),
                    ..Default::default()
                }),
            )
            .await?;

        // Only host 1's two owners are matched; one of them is unreachable.
        assert!(
            summary.contains("Sent: 1")
                && summary.contains("Unreachable: 1")
                && summary.contains("Matched: 2"),
            "unexpected summary: {summary}"
        );
        assert!(
            !summary.contains("Failed: 1"),
            "unexpected summary: {summary}"
        );
        Ok(())
    }

    /// A target that matches nobody completes with a summary rather than
    /// failing the job.
    #[tokio::test]
    async fn test_bulk_message_with_no_recipients() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let admin = db.upsert_user(&[9u8; 32]).await?;
        let worker = setup_worker(db.clone()).await?;

        let summary = worker
            .process_bulk_message("Nobody home".to_string(), "text".to_string(), admin, None)
            .await?;
        assert!(summary.contains("matched no recipients"), "{summary}");
        Ok(())
    }
}
