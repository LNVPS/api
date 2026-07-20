use crate::data_migration::DataMigration;
use crate::settings::Settings;
use anyhow::{Context, Result};
use lnvps_db::LNVpsDb;
use log::info;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Migrates SSH key from proxmox config file to the database
pub struct SshKeyMigration {
    db: Arc<dyn LNVpsDb>,
    settings: Settings,
}

impl SshKeyMigration {
    pub fn new(db: Arc<dyn LNVpsDb>, settings: Settings) -> Self {
        Self { db, settings }
    }
}

impl DataMigration for SshKeyMigration {
    fn name(&self) -> &'static str {
        "SSH key migration"
    }

    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> {
        let db = self.db.clone();
        let settings = self.settings.clone();
        Box::pin(async move {
            // Get SSH config from proxmox settings
            let ssh_config = match &settings.provisioner.proxmox {
                Some(proxmox) => match &proxmox.ssh {
                    Some(ssh) => ssh.clone(),
                    None => {
                        return Ok("no SSH config in proxmox settings, skipped".to_string());
                    }
                },
                None => {
                    return Ok("no proxmox config found, skipped".to_string());
                }
            };

            // Read the SSH key file
            let key_content = std::fs::read_to_string(&ssh_config.key)
                .with_context(|| format!("Failed to read SSH key file: {:?}", ssh_config.key))?;

            info!(
                "Starting SSH key migration from config file: {:?}",
                ssh_config.key
            );

            // Get all hosts
            let hosts = db.list_hosts().await?;
            let mut migrated_count = 0;

            for mut host in hosts {
                // Skip hosts that already have SSH key configured
                if host.ssh_key.is_some() {
                    continue;
                }

                // Update host with SSH credentials
                host.ssh_user = Some(ssh_config.user.clone());
                host.ssh_key = Some(key_content.clone().into());
                db.update_host(&host).await?;

                info!("Migrated SSH key to host '{}' (id={})", host.name, host.id);
                migrated_count += 1;
            }

            Ok(format!("migrated SSH key to {migrated_count} host(s)"))
        })
    }
}
