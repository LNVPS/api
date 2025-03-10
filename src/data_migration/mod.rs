use crate::data_migration::dns::DnsDataMigration;
use crate::settings::Settings;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::{error, info};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

mod dns;

/// Basic data migration to run at startup
pub trait DataMigration: Send + Sync {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}

pub async fn run_data_migrations(db: Arc<dyn LNVpsDb>, settings: &Settings) -> Result<()> {
    let mut migrations: Vec<Arc<dyn DataMigration>> = vec![];
    if let Some(d) = DnsDataMigration::new(db.clone(), settings) {
        migrations.push(Arc::new(d));
    }

    info!("Running {} data migrations", migrations.len());
    for migration in migrations {
        if let Err(e) = migration.migrate().await {
            error!("Error running data migration: {}", e);
        }
    }

    Ok(())
}
