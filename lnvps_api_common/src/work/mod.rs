use crate::model::UpgradeConfig;
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
    async fn recv(&self) -> Result<Vec<WorkJobMessage>>;
    async fn ack(&self, id: &str) -> Result<()>;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum WorkJob {
    /// Sync resources from hosts to database
    PatchHosts,
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
    /// Send bulk message to all active customers based on their contact preferences
    BulkMessage {
        subject: String,
        message: String,
        admin_user_id: u64,
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
    /// Re-apply forward + reverse DNS records for every IP assignment in a range.
    ///
    /// Used after changing a range's DNS server configuration (e.g. switching
    /// reverse DNS to OVH) to reconcile existing assignments to the current config.
    PatchIpRangeDns {
        ip_range_id: u64,
        admin_user_id: Option<u64>,
    },
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
            _ => false,
        }
    }
}

impl fmt::Display for WorkJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkJob::PatchHosts => write!(f, "PatchHosts"),
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
            WorkJob::ImportVm { .. } => write!(f, "ImportVm"),
            WorkJob::CreateVm { .. } => write!(f, "CreateVm"),
            WorkJob::SendEmailVerification { .. } => write!(f, "SendEmailVerification"),
            WorkJob::DownloadOsImages { .. } => write!(f, "DownloadOsImages"),
            WorkJob::CheckSubscriptions => write!(f, "CheckSubscriptions"),
            WorkJob::ProcessReferralPayouts => write!(f, "ProcessReferralPayouts"),
            WorkJob::SpawnVm { .. } => write!(f, "SpawnVm"),
            WorkJob::SyncRouterState => write!(f, "SyncRouterState"),
            WorkJob::ToggleBgpSession { .. } => write!(f, "ToggleBgpSession"),
            WorkJob::SetRouterDefaultRoute { .. } => write!(f, "SetRouterDefaultRoute"),
            WorkJob::ClearRouterDefaultRoute { .. } => write!(f, "ClearRouterDefaultRoute"),
            WorkJob::ToggleTunnel { .. } => write!(f, "ToggleTunnel"),
            WorkJob::PatchIpRangeDns { .. } => write!(f, "PatchIpRangeDns"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
