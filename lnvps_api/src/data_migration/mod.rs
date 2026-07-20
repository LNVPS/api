use crate::data_migration::arp_ref_fixer::ArpRefFixerDataMigration;
use crate::data_migration::dns::DnsDataMigration;
use crate::data_migration::email_hash_backfill::EmailHashBackfillMigration;
use crate::data_migration::encryption_migration::EncryptionDataMigration;
use crate::data_migration::ip6_init::Ip6InitDataMigration;
use crate::data_migration::orphaned_custom_templates::OrphanedCustomTemplatesMigration;
use crate::data_migration::payment_method_config::PaymentMethodConfigMigration;
use crate::data_migration::purge_never_paid_deleted_vms::PurgeNeverPaidDeletedVmsMigration;
use crate::data_migration::ssh_key_migration::SshKeyMigration;
use crate::provisioner::VmProvisioner;
use crate::settings::Settings;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::{error, info};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

mod arp_ref_fixer;
mod dns;
mod email_hash_backfill;
mod encryption_migration;
mod ip6_init;
mod orphaned_custom_templates;
mod payment_method_config;
mod purge_never_paid_deleted_vms;
mod ssh_key_migration;

/// Basic data migration to run at startup
pub trait DataMigration: Send + Sync {
    /// Human-readable name, logged when the migration runs.
    fn name(&self) -> &'static str;

    /// Run the migration, returning a human-readable summary of what it did
    /// (e.g. "purged 3 VM(s)" or "no changes").
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<String>> + Send>>;
}

pub async fn run_data_migrations(
    db: Arc<dyn LNVpsDb>,
    lnvps: VmProvisioner,
    settings: &Settings,
) -> Result<()> {
    let mut migrations: Vec<Box<dyn DataMigration>> = vec![];

    // Add encryption migration first (should run before other migrations)
    migrations.push(Box::new(EncryptionDataMigration::new(db.clone())));

    migrations.push(Box::new(Ip6InitDataMigration::new(
        db.clone(),
        lnvps.clone(),
    )));

    if let Some(d) = DnsDataMigration::new(db.clone(), settings) {
        migrations.push(Box::new(d));
    }

    migrations.push(Box::new(ArpRefFixerDataMigration::new(db.clone())));

    // Migrate payment method config from YAML to database
    migrations.push(Box::new(PaymentMethodConfigMigration::new(
        db.clone(),
        settings.clone(),
    )));

    // Migrate SSH key from proxmox config to database
    migrations.push(Box::new(SshKeyMigration::new(db.clone(), settings.clone())));

    // Backfill email_hash for users missing it (must run after encryption migration)
    migrations.push(Box::new(EmailHashBackfillMigration::new(db.clone())));

    // Clean up orphaned per-VM custom templates (1:1 with their VM)
    migrations.push(Box::new(OrphanedCustomTemplatesMigration::new(db.clone())));

    // Purge historical never-paid soft-deleted VMs (back-fills the never-paid
    // hard-delete for VMs soft-deleted before that behaviour existed)
    migrations.push(Box::new(PurgeNeverPaidDeletedVmsMigration::new(db.clone())));

    info!("Running {} data migrations", migrations.len());
    for migration in migrations {
        info!("Running data migration: {}", migration.name());
        match migration.migrate().await {
            Ok(summary) => info!("Data migration '{}': {}", migration.name(), summary),
            Err(e) => error!("Error running data migration '{}': {}", migration.name(), e),
        }
    }

    Ok(())
}
