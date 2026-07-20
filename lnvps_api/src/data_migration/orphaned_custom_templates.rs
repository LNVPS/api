use crate::data_migration::DataMigration;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::info;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Removes `vm_custom_template` rows that are not referenced by any VM.
///
/// A custom template exists 1:1 with the VM that owns it. Historically some rows
/// were left behind without a referencing VM (e.g. hard-deleted VMs); this
/// one-shot, idempotent cleanup deletes those orphans. Once no orphans remain it
/// is a no-op, so it is safe to run on every boot.
pub struct OrphanedCustomTemplatesMigration {
    db: Arc<dyn LNVpsDb>,
}

impl OrphanedCustomTemplatesMigration {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }
}

impl DataMigration for OrphanedCustomTemplatesMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let db = self.db.clone();
        Box::pin(async move {
            let deleted = db.delete_orphaned_custom_vm_templates().await?;
            if deleted > 0 {
                info!("Deleted {deleted} orphaned vm_custom_template row(s)");
            }
            Ok(())
        })
    }
}
