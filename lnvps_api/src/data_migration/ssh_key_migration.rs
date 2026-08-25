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

            // Every host, not just the placement targets: a host disabled when
            // this ran would keep an empty `ssh_key`, and every node-local
            // command (`qm`, image downloads) hard-fails without one — so
            // re-enabling it later would need the row filled in by hand.
            let hosts = db.list_hosts_all().await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::mock_settings;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDbBase;

    /// Regression: the migration must reach disabled hosts.
    ///
    /// It listed hosts with `list_hosts()`, which hides disabled hosts, so a
    /// host that happened to be disabled when this ran kept an empty `ssh_key` —
    /// and every node-local command (`qm`, image downloads) hard-fails without
    /// one, so re-enabling that host later needed the row filled in by hand.
    #[tokio::test]
    async fn test_ssh_key_migration_covers_disabled_hosts() -> Result<()> {
        let key_path = std::env::temp_dir().join("lnvps_ssh_key_migration_test.key");
        std::fs::write(&key_path, "PRIVATE KEY")?;

        let mut settings = mock_settings();
        settings.provisioner.proxmox.as_mut().unwrap().ssh =
            Some(lnvps_api_common::host::config::SshConfig {
                key: key_path.clone(),
                user: "root".to_string(),
            });

        let db = MockDb::default();
        let mut host = db.get_host(1).await?;
        host.enabled = false;
        host.ssh_key = None;
        host.ssh_user = None;
        db.update_host(&host).await?;

        let db: Arc<dyn LNVpsDb> = Arc::new(db);
        assert!(
            db.list_hosts().await?.iter().all(|h| h.id != 1),
            "precondition: list_hosts() hides disabled hosts"
        );

        SshKeyMigration::new(db.clone(), settings).migrate().await?;

        let host = db.get_host(1).await?;
        assert!(
            host.ssh_key.is_some(),
            "a disabled host must still receive the SSH key"
        );
        assert_eq!(host.ssh_user.as_deref(), Some("root"));

        std::fs::remove_file(&key_path)?;
        Ok(())
    }
}
