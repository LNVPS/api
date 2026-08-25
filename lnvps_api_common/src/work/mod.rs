use crate::model::{CustomVmSpec, UpgradeConfig};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

mod feedback;
mod sender;

pub use feedback::*;
pub use sender::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkJobMessage {
    pub id: String,
    pub job: WorkJob,
    pub is_pending: bool,
}

/// Generic work commander for sending work jobs
#[async_trait]
pub trait WorkCommander: Send + Sync {
    async fn send(&self, job: WorkJob) -> Result<String>;
    /// Send to a named stream instead of the default one.
    ///
    /// Defaults to [`WorkCommander::send`], which is right for the in-process
    /// implementations (one queue, one consumer) and is overridden by the Redis
    /// one, where the stream name is what routes a job to the right consumer.
    async fn send_to_stream(&self, _stream: &str, job: WorkJob) -> Result<String> {
        self.send(job).await
    }
    async fn recv(&self) -> Result<Vec<WorkJobMessage>>;
    async fn ack(&self, id: &str) -> Result<()>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WorkJob {
    /// Sync resources from hosts to database
    PatchHosts,
    /// Sync resources (cpu/memory/disks) from a single host to the database
    PatchHost { host_id: u64 },
    /// Check all running VMS
    CheckVms,
    /// Check the VM status matches database state
    ///
    /// This job starts a vm if stopped and also creates the vm if it doesn't exist yet
    CheckVm { vm_id: u64 },
    /// Unconditionally provision and spawn a VM onto the host.
    ///
    /// Used after a first (Purchase) payment is confirmed so the VM is created
    /// immediately without relying on `get_vm_state` to detect its absence.
    SpawnVm { vm_id: u64 },
    /// Send a notification to the users chosen contact preferences
    SendNotification {
        user_id: u64,
        message: String,
        title: Option<String>,
    },
    /// Send a notification to all admin users
    /// This job looks up all admin users in the database and creates individual SendNotification jobs for each
    SendAdminNotification {
        message: String,
        title: Option<String>,
    },
    /// Send bulk message to customers based on their contact preferences
    BulkMessage {
        subject: String,
        message: String,
        admin_user_id: u64,
        /// Recipient selection. Absent (or empty) means every active customer.
        #[serde(default)]
        target: Option<lnvps_db::BulkMessageTarget>,
    },
    /// Delete a VM at admin request
    DeleteVm {
        vm_id: u64,
        reason: Option<String>,
        admin_user_id: Option<u64>,
        /// Permanently purge the VM and all related records (history,
        /// payments, subscription) from the database instead of soft-deleting.
        /// Reserved for super-admin forced deletions; never-paid VMs are always
        /// purged regardless of this flag.
        #[serde(default)]
        purge: bool,
    },
    /// Start a VM
    StartVm {
        vm_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Stop a VM
    StopVm {
        vm_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Check all nostr domains DNS records - enable disabled domains with DNS records, disable active domains without DNS records
    CheckNostrDomains,
    /// Process VM upgrade after payment confirmation
    ProcessVmUpgrade { vm_id: u64, config: UpgradeConfig },
    /// Re-configure a VM using current database configuration
    ConfigureVm {
        vm_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Re-apply the firewall ruleset for a VM (after firewall rule changes)
    ApplyVmFirewall { vm_id: u64 },
    /// Assign an IP to a VM using the provisioner (handles all additional steps)
    AssignVmIp {
        vm_id: u64,
        ip_range_id: u64,
        ip: Option<String>, // If None, auto-assign from range
        admin_user_id: Option<u64>,
    },
    /// Delete/unassign an IP from a VM using the provisioner (handles all cleanup)
    UnassignVmIp {
        assignment_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Update an assignment
    UpdateVmIp {
        assignment_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Process a refund for a VM automatically
    ProcessVmRefund {
        vm_id: u64,
        admin_user_id: u64,
        refund_from_date: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<String>,
        payment_method: String,            // "lightning", "revolut", "paypal"
        lightning_invoice: Option<String>, // Required when payment_method is "lightning"
    },
    /// Discover VMs present on a host that are not tracked in the database and
    /// publish the resulting list (JSON `Vec<HostVmSpec>`) to a temporary Redis
    /// pub/sub channel so the admin API can read it synchronously.
    ListUnmanagedVms {
        host_id: u64,
        /// Temporary channel id the worker replies on (via job feedback).
        reply_channel: String,
    },
    /// Import a VM that exists on a host but isn't tracked in the database,
    /// assigning it to a user and billing it via the region's custom pricing.
    ImportVm {
        host_id: u64,
        /// Raw host VM id (e.g. Proxmox vmid)
        host_vm_id: i64,
        user_id: u64,
        admin_user_id: u64,
        reason: Option<String>,
    },
    /// Migrate a VM to another host (issue #66). Runs on the worker so it is
    /// serialised with the other lifecycle operations for that VM.
    MigrateVm {
        vm_id: u64,
        target_host_id: u64,
        /// Attempt an online migration; otherwise the VM is stopped, moved and
        /// started again on the destination.
        live: bool,
        admin_user_id: Option<u64>,
        reason: Option<String>,
    },
    /// Poll every host for the VMs it is running and re-point `vm.host_id` at
    /// whichever host actually has each VM, so a migration performed outside
    /// this API (e.g. by hand in the Proxmox UI) does not leave the database
    /// aiming every lifecycle operation at the wrong host.
    ReconcileVmHosts,
    /// Re-install a VM: stop it, wipe & re-import the primary disk from its
    /// current image template, then start it again. Runs on the worker so it is
    /// serialised with spawn (avoiding a reinstall racing an in-flight spawn).
    /// The worker publishes the outcome on `reply_channel` so the API can wait
    /// for the result before responding to the user.
    ReinstallVm {
        vm_id: u64,
        /// The user who triggered the reinstall (for history logging).
        user_id: Option<u64>,
        /// Image id already in effect on the VM (recorded in history).
        old_image_id: u64,
        /// Image the VM was reinstalled with (recorded in history).
        new_image_id: u64,
        /// Temporary channel id the worker replies on (via job feedback).
        reply_channel: String,
    },
    /// Create a VM for a specific user (admin action)
    CreateVm {
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
        ref_code: Option<String>,
        admin_user_id: u64,
        reason: Option<String>,
    },
    /// Create a VM from a custom spec for a specific user (admin action).
    CreateCustomVm {
        user_id: u64,
        spec: CustomVmSpec,
        image_id: u64,
        ssh_key_id: u64,
        ref_code: Option<String>,
        admin_user_id: u64,
        reason: Option<String>,
    },
    /// Send an email verification link to the user
    SendEmailVerification { user_id: u64, verify_url: String },
    /// Download OS images to all hosts, verifying checksums and re-downloading if stale.
    /// If `image_id` is Some, only that image is processed; otherwise all images are checked.
    DownloadOsImages { image_id: Option<u64> },
    /// Check all active subscriptions for expiry, auto-renewal, and deactivation.
    CheckSubscriptions,
    /// Process automated referral commission payouts (BTC, over Lightning).
    ProcessReferralPayouts,
    /// Poll routers to refresh cached tunnel/BGP session/route state and record
    /// per-tunnel traffic samples.
    SyncRouterState,
    /// Build a short-lived VM on one marketplace node that is due a probe,
    /// measure what a customer would get, and destroy it.
    ///
    /// One node per run rather than the whole fleet: a probe puts real load on
    /// somebody else's hardware, and a sweep that probed every node at once
    /// would arrive as a thundering herd on the operators least able to absorb
    /// it.
    ProbeMarketplaceNode,
    /// Enable or disable a BGP session on a router (admin action).
    ToggleBgpSession {
        router_id: u64,
        /// Backend session id (protocol name on BIRD, `.id` on Mikrotik)
        session_id: String,
        enabled: bool,
    },
    /// Install or replace the static default route on a router (admin action).
    /// The address family is inferred from `next_hop`.
    SetRouterDefaultRoute { router_id: u64, next_hop: String },
    /// Remove the static default route(s) from a router (admin action).
    ClearRouterDefaultRoute { router_id: u64 },
    /// Enable or disable a tunnel on a router (admin action).
    ToggleTunnel {
        router_id: u64,
        /// Tunnel interface name (the cache key)
        name: String,
        enabled: bool,
    },
    /// Configure a tunnel pool's WireGuard interface on its route server:
    /// create it if it is missing, re-apply it if what the router reports has
    /// drifted from what LNVPS holds, and bring it up or down to match the
    /// pool's `enabled` flag.
    ///
    /// LNVPS owns the interface's key material, so this is a push, not a
    /// reconcile against whatever happens to be configured.
    SyncTunnelPool { pool_id: u64 },
    /// Remove a tunnel interface from a router.
    ///
    /// Carries the router and interface rather than a pool id because it runs
    /// *after* the pool row is gone — the alternative is deleting the row and
    /// leaving a configured interface behind with no record that it exists.
    RemoveTunnelInterface { router_id: u64, interface: String },
    /// Reconcile the peers, addresses and routes on a tunnel pool's interface
    /// against the tunnels allocated from it.
    ///
    /// Separate from [`SyncTunnelPool`](Self::SyncTunnelPool) because that
    /// re-applies the interface itself, which on Linux means recreating it and
    /// dropping every peer. This one touches only what has actually drifted,
    /// which is what makes it safe to run on a schedule.
    ReconcileTunnelPeers { pool_id: u64 },
    /// Push one node's peer onto its route server.
    ///
    /// The fast path for "this node just got an address": a full reconcile of
    /// the pool would work, but a node waiting on its first guest should not
    /// wait for every other node on the route server to be checked first.
    SyncNodeTunnel { tunnel_id: u64 },
    /// Re-apply forward + reverse DNS records for every IP assignment in a range.
    ///
    /// Used after changing a range's DNS server configuration (e.g. switching
    /// reverse DNS to OVH) to reconcile existing assignments to the current config.
    PatchIpRangeDns {
        ip_range_id: u64,
        admin_user_id: Option<u64>,
    },
    /// Reconcile one managed-app deployment now, rather than at the operator's
    /// next poll (issue #254).
    ///
    /// Published to the deployment's cluster stream ([`app_cluster_stream`]) by
    /// the payment path, and consumed by the operator serving that cluster. The
    /// periodic reconcile stays as the backstop: a dropped trigger must be a
    /// delay, not a deployment that never happens.
    ReconcileAppDeployment { deployment_id: u64 },
    /// Run the on-payment handling for a subscription payment that has already
    /// been marked paid.
    ///
    /// The admin override endpoint marks a payment paid itself but lives in a
    /// crate without the provisioner stack, so the line-item handlers (instant
    /// app reconcile, VM/app upgrade application) run here on the worker
    /// instead. The Lightning settlement path calls the same handling inline.
    ApplySubscriptionPayment {
        /// Hex-encoded `subscription_payment.id`.
        payment_id: String,
    },
}

/// Redis stream carrying reconcile triggers for one app cluster (issue #254).
///
/// Per cluster, not global: an operator serves exactly one cluster
/// (`Settings::app_cluster_id`), so keying the stream by cluster is what routes
/// a trigger to the operator that can act on it — without the API needing to
/// discover N operators.
pub fn app_cluster_stream(cluster_id: u64) -> String {
    format!("app-cluster-{cluster_id}")
}

impl WorkJob {
    /// If this job can be skipped on failure
    pub fn can_skip(&self) -> bool {
        match self {
            Self::CheckNostrDomains { .. } => true,
            Self::StopVm { .. } => true,
            Self::StartVm { .. } => true,
            Self::CheckVm { .. } => true,
            Self::CheckVms => true,
            Self::CheckSubscriptions => true,
            // A discovery request is a one-shot read tied to a waiting admin
            // request; never retry it if it fails.
            Self::ListUnmanagedVms { .. } => true,
            // A reinstall is a one-shot action tied to a waiting user request;
            // don't let the worker silently retry it later.
            Self::ReinstallVm { .. } => true,
            // The periodic reconcile is the backstop, so a failed trigger costs
            // at most one interval — not worth retrying and blocking the stream.
            Self::ReconcileAppDeployment { .. } => true,
            // Placement drift is re-detected on the next pass, so a failed run
            // (usually an unreachable host) costs one interval, not a fix.
            Self::ReconcileVmHosts => true,
            // A spawn that keeps failing must not be redelivered forever. An
            // unacked job is reclaimed on every poll, so a permanently failing
            // spawn (a misconfigured host, a missing image) re-ran the pipeline
            // every few seconds, and each attempt built and abandoned state on
            // the host. `CheckVms` re-drives a VM that is missing from its host
            // every 30s anyway (see `recover_missing_vm`), so nothing is lost by
            // letting the queued copy go.
            Self::SpawnVm { .. } => true,
            _ => false,
        }
    }
}

impl fmt::Display for WorkJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkJob::ReconcileAppDeployment { .. } => write!(f, "ReconcileAppDeployment"),
            WorkJob::ApplySubscriptionPayment { .. } => write!(f, "ApplySubscriptionPayment"),
            WorkJob::PatchHosts => write!(f, "PatchHosts"),
            WorkJob::PatchHost { .. } => write!(f, "PatchHost"),
            WorkJob::CheckVms => write!(f, "CheckVms"),
            WorkJob::CheckVm { .. } => write!(f, "CheckVm"),
            WorkJob::SendNotification { .. } => write!(f, "SendNotification"),
            WorkJob::SendAdminNotification { .. } => write!(f, "SendAdminNotification"),
            WorkJob::BulkMessage { .. } => write!(f, "BulkMessage"),
            WorkJob::DeleteVm { .. } => write!(f, "DeleteVm"),
            WorkJob::StartVm { .. } => write!(f, "StartVm"),
            WorkJob::StopVm { .. } => write!(f, "StopVm"),
            WorkJob::CheckNostrDomains => write!(f, "CheckNostrDomains"),
            WorkJob::ProcessVmUpgrade { .. } => write!(f, "ProcessVmUpgrade"),
            WorkJob::ConfigureVm { .. } => write!(f, "ConfigureVm"),
            WorkJob::ApplyVmFirewall { .. } => write!(f, "ApplyVmFirewall"),
            WorkJob::AssignVmIp { .. } => write!(f, "AssignVmIp"),
            WorkJob::UnassignVmIp { .. } => write!(f, "UnassignVmIp"),
            WorkJob::UpdateVmIp { .. } => write!(f, "UpdateVmIp"),
            WorkJob::ProcessVmRefund { .. } => write!(f, "ProcessVmRefund"),
            WorkJob::ListUnmanagedVms { .. } => write!(f, "ListUnmanagedVms"),
            WorkJob::ReinstallVm { .. } => write!(f, "ReinstallVm"),
            WorkJob::ImportVm { .. } => write!(f, "ImportVm"),
            WorkJob::MigrateVm { .. } => write!(f, "MigrateVm"),
            WorkJob::ReconcileVmHosts => write!(f, "ReconcileVmHosts"),
            WorkJob::CreateVm { .. } => write!(f, "CreateVm"),
            WorkJob::CreateCustomVm { .. } => write!(f, "CreateCustomVm"),
            WorkJob::SendEmailVerification { .. } => write!(f, "SendEmailVerification"),
            WorkJob::DownloadOsImages { .. } => write!(f, "DownloadOsImages"),
            WorkJob::CheckSubscriptions => write!(f, "CheckSubscriptions"),
            WorkJob::ProcessReferralPayouts => write!(f, "ProcessReferralPayouts"),
            WorkJob::SpawnVm { .. } => write!(f, "SpawnVm"),
            WorkJob::SyncRouterState => write!(f, "SyncRouterState"),
            WorkJob::ProbeMarketplaceNode => write!(f, "ProbeMarketplaceNode"),
            WorkJob::ToggleBgpSession { .. } => write!(f, "ToggleBgpSession"),
            WorkJob::SetRouterDefaultRoute { .. } => write!(f, "SetRouterDefaultRoute"),
            WorkJob::ClearRouterDefaultRoute { .. } => write!(f, "ClearRouterDefaultRoute"),
            WorkJob::ToggleTunnel { .. } => write!(f, "ToggleTunnel"),
            WorkJob::SyncTunnelPool { .. } => write!(f, "SyncTunnelPool"),
            WorkJob::RemoveTunnelInterface { .. } => write!(f, "RemoveTunnelInterface"),
            WorkJob::ReconcileTunnelPeers { .. } => write!(f, "ReconcileTunnelPeers"),
            WorkJob::SyncNodeTunnel { .. } => write!(f, "SyncNodeTunnel"),
            WorkJob::PatchIpRangeDns { .. } => write!(f, "PatchIpRangeDns"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_host_job_display_and_roundtrip() {
        let job = WorkJob::PatchHost { host_id: 7 };
        assert_eq!(job.to_string(), "PatchHost");
        let json = serde_json::to_string(&job).unwrap();
        match serde_json::from_str::<WorkJob>(&json).unwrap() {
            WorkJob::PatchHost { host_id } => assert_eq!(host_id, 7),
            other => panic!("unexpected job: {other}"),
        }
    }

    #[test]
    fn test_router_default_route_job_display() {
        assert_eq!(
            WorkJob::SetRouterDefaultRoute {
                router_id: 1,
                next_hop: "192.0.2.1".to_string(),
            }
            .to_string(),
            "SetRouterDefaultRoute"
        );
        assert_eq!(
            WorkJob::ClearRouterDefaultRoute { router_id: 1 }.to_string(),
            "ClearRouterDefaultRoute"
        );
        assert_eq!(
            WorkJob::ToggleTunnel {
                router_id: 1,
                name: "gre1".to_string(),
                enabled: false,
            }
            .to_string(),
            "ToggleTunnel"
        );
        assert_eq!(
            WorkJob::PatchIpRangeDns {
                ip_range_id: 3,
                admin_user_id: Some(1),
            }
            .to_string(),
            "PatchIpRangeDns"
        );
        assert_eq!(
            WorkJob::SyncTunnelPool { pool_id: 2 }.to_string(),
            "SyncTunnelPool"
        );
        assert_eq!(
            WorkJob::RemoveTunnelInterface {
                router_id: 1,
                interface: "wg-mkt0".to_string(),
            }
            .to_string(),
            "RemoveTunnelInterface"
        );
        assert_eq!(
            WorkJob::ReconcileTunnelPeers { pool_id: 2 }.to_string(),
            "ReconcileTunnelPeers"
        );
        assert_eq!(
            WorkJob::SyncNodeTunnel { tunnel_id: 5 }.to_string(),
            "SyncNodeTunnel"
        );
    }
}
