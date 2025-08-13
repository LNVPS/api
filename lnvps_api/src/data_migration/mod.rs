use crate::data_migration::arp_ref_fixer::ArpRefFixerDataMigration;
use crate::data_migration::dns::DnsDataMigration;
use crate::data_migration::encryption_migration::EncryptionDataMigration;
use crate::data_migration::ip6_init::Ip6InitDataMigration;
use crate::provisioner::LNVpsProvisioner;
use crate::settings::Settings;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::{error, info};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

mod arp_ref_fixer;
mod dns;
mod encryption_migration;
mod ip6_init;

/// Basic data migration to run at startup
pub trait DataMigration: Send + Sync {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}

pub async fn run_data_migrations(
    db: Arc<dyn LNVpsDb>,
    lnvps: Arc<LNVpsProvisioner>,
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

    migrations.push(Box::new(ArpRefFixerDataMigration::new(
        db.clone(),
        lnvps.clone(),
    )));

    info!("Running {} data migrations", migrations.len());
    for migration in migrations {
        if let Err(e) = migration.migrate().await {
            error!("Error running data migration: {}", e);
        }
    }

    Ok(())
}
