use crate::data_migration::DataMigration;
use anyhow::Result;
use lnvps_db::{EncryptionContext, LNVpsDb};
use log::info;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct EmailHashBackfillMigration {
    db: Arc<dyn LNVpsDb>,
}

impl EmailHashBackfillMigration {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }
}

impl DataMigration for EmailHashBackfillMigration {
    fn name(&self) -> &'static str {
        "email hash backfill"
    }

    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> {
        let db = self.db.clone();
        Box::pin(async move {
            // Find all users with an email but no email_hash yet
            let rows = db
                .fetch_raw_strings(
                    "SELECT id, email FROM users WHERE email IS NOT NULL AND email != '' AND email_hash IS NULL",
                )
                .await?;

            if rows.is_empty() {
                return Ok("no users need email_hash backfill".to_string());
            }

            info!("Backfilling email_hash for {} users", rows.len());

            let encryption_context = EncryptionContext::get()?;
            let mut updated = 0u64;
            let mut skipped = 0u64;

            for (user_id, email_encrypted) in &rows {
                // Decrypt the email
                let email_plaintext = if EncryptionContext::is_encrypted(email_encrypted) {
                    match encryption_context.decrypt(email_encrypted) {
                        Ok(plain) => plain,
                        Err(e) => {
                            info!("Failed to decrypt email for user {}: {}", user_id, e);
                            skipped += 1;
                            continue;
                        }
                    }
                } else {
                    email_encrypted.clone()
                };

                let hash = lnvps_db::email_hash(&email_plaintext);
                let hash_hex = hex::encode(hash);

                db.execute_query_with_string_params(
                    "UPDATE users SET email_hash = UNHEX(?) WHERE id = ?",
                    vec![hash_hex, user_id.to_string()],
                )
                .await?;

                updated += 1;
                if updated % 100 == 0 {
                    info!(
                        "Email hash backfill progress: {} updated, {} skipped",
                        updated, skipped
                    );
                }
            }

            Ok(format!(
                "email_hash backfill: {updated} updated, {skipped} skipped"
            ))
        })
    }
}
