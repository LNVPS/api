use crate::data_migration::DataMigration;
use anyhow::Result;
use lnvps_db::{EncryptionContext, LNVpsDb};
use log::info;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct EncryptionDataMigration {
    db: Arc<dyn LNVpsDb>,
}

impl EncryptionDataMigration {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// Check if encryption is initialized and available
    fn is_encryption_available() -> bool {
        EncryptionContext::get().is_ok()
    }
}

impl DataMigration for EncryptionDataMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let db = self.db.clone();
        Box::pin(async move {
            // Only run migration if encryption is configured
            if !Self::is_encryption_available() {
                info!("Encryption not configured, skipping encryption migration");
                return Ok(());
            }

            info!("Starting encryption data migration");

            let encryption_context = EncryptionContext::get()?;
            let mut total_encrypted = 0;

            // Migrate user email addresses using raw SQL to avoid EncryptedString decode issues
            let email_rows = db.fetch_raw_strings("SELECT id, email FROM users WHERE email IS NOT NULL AND email != ''").await?;
            for (user_id, email) in email_rows {
                if !EncryptionContext::is_encrypted(&email) {
                    info!("Encrypting email for user {}", user_id);
                    let encrypted_email = encryption_context.encrypt(&email)?;
                    db.execute_query_with_string_params(
                        "UPDATE users SET email = ? WHERE id = ?",
                        vec![encrypted_email, user_id.to_string()]
                    ).await?;
                    total_encrypted += 1;
                }
            }

            // Migrate VM host API tokens using raw SQL
            let token_rows = db.fetch_raw_strings("SELECT id, api_token FROM vm_host WHERE api_token != ''").await?;
            for (host_id, token) in token_rows {
                if !EncryptionContext::is_encrypted(&token) {
                    info!("Encrypting API token for host {}", host_id);
                    let encrypted_token = encryption_context.encrypt(&token)?;
                    db.execute_query_with_string_params(
                        "UPDATE vm_host SET api_token = ? WHERE id = ?",
                        vec![encrypted_token, host_id.to_string()]
                    ).await?;
                    total_encrypted += 1;
                }
            }

            // Migrate user SSH keys using raw SQL
            let ssh_key_rows = db.fetch_raw_strings("SELECT id, key_data FROM user_ssh_key WHERE key_data != ''").await?;
            let mut ssh_keys_encrypted = 0;
            for (ssh_key_id, key_data) in ssh_key_rows {
                if !EncryptionContext::is_encrypted(&key_data) {
                    info!("Encrypting SSH key {}", ssh_key_id);
                    let encrypted_key_data = encryption_context.encrypt(&key_data)?;
                    db.execute_query_with_string_params(
                        "UPDATE user_ssh_key SET key_data = ? WHERE id = ?",
                        vec![encrypted_key_data, ssh_key_id.to_string()]
                    ).await?;
                    ssh_keys_encrypted += 1;
                }
            }

            // Migrate router tokens using raw SQL
            let router_rows = db.fetch_raw_strings("SELECT id, token FROM router WHERE token != ''").await?;
            let mut routers_encrypted = 0;
            for (router_id, token) in router_rows {
                if !EncryptionContext::is_encrypted(&token) {
                    info!("Encrypting token for router {}", router_id);
                    let encrypted_token = encryption_context.encrypt(&token)?;
                    db.execute_query_with_string_params(
                        "UPDATE router SET token = ? WHERE id = ?",
                        vec![encrypted_token, router_id.to_string()]
                    ).await?;
                    routers_encrypted += 1;
                }
            }

            info!(
                "Encryption migration completed: {} users/hosts, {} SSH keys, {} routers",
                total_encrypted, ssh_keys_encrypted, routers_encrypted
            );

            Ok(())
        })
    }
}