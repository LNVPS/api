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
            WorkJob::AssignVmIp { .. } => write!(f, "AssignVmIp"),
            WorkJob::UnassignVmIp { .. } => write!(f, "UnassignVmIp"),
            WorkJob::UpdateVmIp { .. } => write!(f, "UpdateVmIp"),
            WorkJob::ProcessVmRefund { .. } => write!(f, "ProcessVmRefund"),
            WorkJob::CreateVm { .. } => write!(f, "CreateVm"),
        }
    }
}
