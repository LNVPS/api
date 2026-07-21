use crate::data_migration::DataMigration;
use crate::settings::{LightningConfig, Settings};
use anyhow::Result;
use lnvps_db::{
    BitvoraConfig, LNVpsDb, LndConfig, OnChainAddressType, OnChainProviderConfig, PaymentMethod,
    PaymentMethodConfig, ProviderConfig, RevolutProviderConfig,
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
    fn name(&self) -> &'static str {
        "payment method config migration"
    }

    fn migrate(&self) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> {
        let db = self.db.clone();
        let settings = self.settings.clone();
        Box::pin(async move {
            info!("Starting payment method config migration from YAML settings");

            // Skip per payment *method*, not globally: earlier versions of
            // this migration only imported the Lightning config, so a global
            // "any config exists" check would prevent newly added methods
            // (e.g. on-chain) from ever being imported on existing deployments.
            let existing_configs = db.list_payment_method_configs().await?;
            let has_method =
                |m: PaymentMethod| existing_configs.iter().any(|c| c.payment_method == m);

            let need_lightning = !has_method(PaymentMethod::Lightning);
            // On-chain is only seeded from an LND wallet
            let need_onchain = matches!(settings.lightning, LightningConfig::LND { .. })
                && !has_method(PaymentMethod::OnChain);
            let need_revolut = settings.revolut.is_some() && !has_method(PaymentMethod::Revolut);

            if !need_lightning && !need_onchain && !need_revolut {
                return Ok(format!(
                    "configs already exist ({} found), skipped",
                    existing_configs.len()
                ));
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
                    if need_lightning {
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

                    if need_onchain {
                        // On-chain payments reuse the same LND wallet; seed a
                        // config with defaults so it is manageable in the admin UI
                        let onchain_config = ProviderConfig::OnChain(OnChainProviderConfig {
                            url: url.clone(),
                            cert_path: PathBuf::from(cert),
                            macaroon_path: PathBuf::from(macaroon),
                            address_type: OnChainAddressType::default(),
                            account: None,
                            min_confirmations: 1,
                        });
                        let payment_config = PaymentMethodConfig::new_with_config(
                            company_id,
                            PaymentMethod::OnChain,
                            "LND On-chain".to_string(),
                            true,
                            onchain_config,
                        );
                        db.insert_payment_method_config(&payment_config).await?;
                        info!("Migrated LND on-chain config for company {}", company_id);
                        migrated_count += 1;
                    }
                }
                LightningConfig::Bitvora {
                    token,
                    webhook_secret,
                } => {
                    if need_lightning {
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
            }

            // Migrate Revolut config if present
            if need_revolut && let Some(ref revolut) = settings.revolut {
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

            Ok(format!(
                "migrated {migrated_count} payment method config(s) for company {company_id}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::mock_settings;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDbBase;

    fn lightning_only_config(company_id: u64) -> PaymentMethodConfig {
        PaymentMethodConfig::new_with_config(
            company_id,
            PaymentMethod::Lightning,
            "LND Node".to_string(),
            true,
            ProviderConfig::Lnd(LndConfig {
                url: "https://127.0.0.1:10009".to_string(),
                cert_path: PathBuf::from("tls.cert"),
                macaroon_path: PathBuf::from("admin.macaroon"),
            }),
        )
    }

    #[tokio::test]
    async fn test_fresh_db_imports_lightning_and_onchain() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let migration = PaymentMethodConfigMigration::new(db.clone(), mock_settings());

        migration.migrate().await?;

        let configs = db.list_payment_method_configs().await?;
        assert!(
            configs
                .iter()
                .any(|c| c.payment_method == PaymentMethod::Lightning)
        );
        assert!(
            configs
                .iter()
                .any(|c| c.payment_method == PaymentMethod::OnChain)
        );
        Ok(())
    }

    /// Regression: a previously imported Lightning config must not prevent
    /// the newer on-chain config from being imported.
    #[tokio::test]
    async fn test_existing_lightning_does_not_block_onchain_import() -> Result<()> {
        let db = Arc::new(MockDb::default());
        db.insert_payment_method_config(&lightning_only_config(1))
            .await?;

        let migration = PaymentMethodConfigMigration::new(db.clone(), mock_settings());
        let result = migration.migrate().await?;
        assert!(result.contains("migrated 1"), "unexpected result: {result}");

        let configs = db.list_payment_method_configs().await?;
        let lightning_count = configs
            .iter()
            .filter(|c| c.payment_method == PaymentMethod::Lightning)
            .count();
        let onchain_count = configs
            .iter()
            .filter(|c| c.payment_method == PaymentMethod::OnChain)
            .count();
        assert_eq!(lightning_count, 1, "must not duplicate lightning config");
        assert_eq!(onchain_count, 1, "on-chain config must be imported");
        Ok(())
    }

    #[tokio::test]
    async fn test_all_present_skips() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let migration = PaymentMethodConfigMigration::new(db.clone(), mock_settings());
        migration.migrate().await?;

        // Second run must be a no-op
        let result = migration.migrate().await?;
        assert!(result.contains("skipped"), "unexpected result: {result}");
        assert_eq!(db.list_payment_method_configs().await?.len(), 2);
        Ok(())
    }
}
