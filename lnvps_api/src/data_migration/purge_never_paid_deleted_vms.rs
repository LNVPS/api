use crate::data_migration::DataMigration;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::warn;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Hard-deletes historical soft-deleted VMs whose subscription was never paid.
///
/// Never-paid VMs are now purged entirely by the worker's unpaid-VM cleanup, but
/// VMs that were soft-deleted (`deleted = 1`) before that behaviour existed still
/// linger in the database along with their orphaned subscription. The worker's
/// `check_vms` loop skips soft-deleted rows, so it never revisits them.
///
/// This one-shot, idempotent cleanup finds those never-paid soft-deleted VMs and
/// removes them (plus `vm_history`, `vm_firewall_rule`, `vm_ip_assignment`, and
/// their subscription) via [`LNVpsDb::hard_delete_vm`]. VMs that were ever paid
/// are left untouched so their payment history is preserved. Once none remain it
/// is a no-op, so it is safe to run on every boot.
pub struct PurgeNeverPaidDeletedVmsMigration {
    db: Arc<dyn LNVpsDb>,
}

impl PurgeNeverPaidDeletedVmsMigration {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }
}

impl DataMigration for PurgeNeverPaidDeletedVmsMigration {
    fn name(&self) -> &'static str {
        "purge never-paid soft-deleted VMs"
    }

    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> {
        let db = self.db.clone();
        Box::pin(async move {
            let ids = db.list_deleted_never_paid_vm_ids().await?;
            let candidates = ids.len();
            let mut purged = 0u64;
            for vm_id in ids {
                match db.hard_delete_vm(vm_id).await {
                    Ok(()) => purged += 1,
                    Err(e) => warn!("Failed to purge never-paid soft-deleted VM {vm_id}: {e}"),
                }
            }
            Ok(format!(
                "purged {purged} of {candidates} never-paid soft-deleted VM(s)"
            ))
        })
    }
}
