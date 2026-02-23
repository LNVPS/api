use crate::data_migration::DataMigration;
use crate::settings::{LightningConfig, Settings};
use anyhow::Result;
use lnvps_db::{
    BitvoraConfig, LNVpsDb, LndConfig, PaymentMethod, PaymentMethodConfig, ProviderConfig,
    RevolutProviderConfig,
};
use log::info;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

pub struct PaymentMethodConfigMigration {
    db: Arc<dyn LNVpsDb>,
    settings: Settings,
}

impl PaymentMethodConfigMigration {
    pub fn new(db: Arc<dyn LNVpsDb>, settings: Settings) -> Self {
        Self { db, settings }
    }
}

impl DataMigration for PaymentMethodConfigMigration {
    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let db = self.db.clone();
        let settings = self.settings.clone();
        Box::pin(async move {
            info!("Starting payment method config migration from YAML settings");

            // Check if any payment method configs already exist
            let existing_configs = db.list_payment_method_configs().await?;
            if !existing_configs.is_empty() {
                info!(
                    "Payment method configs already exist ({} found), skipping migration",
                    existing_configs.len()
                );
                return Ok(());
            }

            // Get the first company to assign configs to
            let companies = db.list_companies().await?;
            let company = companies.first().ok_or_else(|| {
                anyhow::anyhow!(
                    "No companies found in database, cannot migrate payment method configs"
                )
            })?;
            let company_id = company.id;
            info!(
                "Using company '{}' (id={}) for payment method config migration",
                company.name, company_id
            );

            let mut migrated_count = 0;

            // Migrate Lightning config
            match &settings.lightning {
                LightningConfig::LND {
                    url,
                    cert,
                    macaroon,
                } => {
                    let provider_config = ProviderConfig::Lnd(LndConfig {
                        url: url.clone(),
                        cert_path: PathBuf::from(cert),
                        macaroon_path: PathBuf::from(macaroon),
                    });

                    let payment_config = PaymentMethodConfig::new_with_config(
                        company_id,
                        PaymentMethod::Lightning,
                        "LND Node".to_string(),
                        true,
                        provider_config,
                    );

                    db.insert_payment_method_config(&payment_config).await?;
                    info!("Migrated LND Lightning config for company {}", company_id);
                    migrated_count += 1;
                }
                LightningConfig::Bitvora {
                    token,
                    webhook_secret,
                } => {
                    let provider_config = ProviderConfig::Bitvora(BitvoraConfig {
                        token: token.clone(),
                        webhook_secret: webhook_secret.clone(),
                    });

                    let payment_config = PaymentMethodConfig::new_with_config(
                        company_id,
                        PaymentMethod::Lightning,
                        "Bitvora".to_string(),
                        true,
                        provider_config,
                    );

                    db.insert_payment_method_config(&payment_config).await?;
                    info!(
                        "Migrated Bitvora Lightning config for company {}",
                        company_id
                    );
                    migrated_count += 1;
                }
            }

            // Migrate Revolut config if present
            if let Some(ref revolut) = settings.revolut {
                let provider_config = ProviderConfig::Revolut(RevolutProviderConfig {
                    url: revolut
                        .url
                        .clone()
                        .unwrap_or_else(|| "https://api.revolut.com".to_string()),
                    token: revolut.token.clone(),
                    api_version: revolut.api_version.clone(),
                    public_key: revolut.public_key.clone(),
                    webhook_secret: None, // Will be populated when webhook is registered
                });

                let payment_config = PaymentMethodConfig::new_with_config(
                    company_id,
                    PaymentMethod::Revolut,
                    "Revolut".to_string(),
                    true,
                    provider_config,
                );

                db.insert_payment_method_config(&payment_config).await?;
                info!("Migrated Revolut config for company {}", company_id);
                migrated_count += 1;
            }

            info!(
                "Payment method config migration completed: {} configs migrated for company {}",
                migrated_count, company_id
            );

            Ok(())
        })
    }
}
