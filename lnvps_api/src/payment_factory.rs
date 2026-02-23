//! Payment Method Factory
//!
//! Creates payment handlers from database-stored configurations.
//! This module bridges the gap between `PaymentMethodConfig` records in the database
//! and the concrete payment handler implementations (LightningNode, FiatPaymentService).

use anyhow::{Context, Result, bail};
use lnvps_db::{LNVpsDb, PaymentMethod, PaymentMethodConfig, ProviderConfig};
use payments_rs::fiat::FiatPaymentService;
use payments_rs::lightning::LightningNode;
use std::sync::Arc;

/// Factory for creating payment handlers from database configurations
pub struct PaymentMethodFactory {
    db: Arc<dyn LNVpsDb>,
}

impl PaymentMethodFactory {
    /// Create a new factory instance
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// Load all payment method configs from the database
    pub async fn load_configs(&self) -> Result<Vec<PaymentMethodConfig>> {
        self.db
            .list_payment_method_configs()
            .await
            .context("Failed to load payment method configs")
    }

    /// Load enabled payment method configs for a specific company
    pub async fn load_enabled_configs_for_company(
        &self,
        company_id: u64,
    ) -> Result<Vec<PaymentMethodConfig>> {
        self.db
            .list_enabled_payment_method_configs_for_company(company_id)
            .await
            .context("Failed to load enabled payment method configs for company")
    }

    /// Load all payment method configs for a specific company
    pub async fn load_configs_for_company(
        &self,
        company_id: u64,
    ) -> Result<Vec<PaymentMethodConfig>> {
        self.db
            .list_payment_method_configs_for_company(company_id)
            .await
            .context("Failed to load payment method configs for company")
    }

    /// Create a Lightning node handler from a PaymentMethodConfig
    ///
    /// Returns an error if the config is not for a Lightning payment method,
    /// is disabled, or the provider type is not supported.
    pub async fn create_lightning_node(
        &self,
        config: &PaymentMethodConfig,
    ) -> Result<Arc<dyn LightningNode>> {
        if config.payment_method != PaymentMethod::Lightning {
            bail!(
                "Cannot create Lightning node from {:?} config",
                config.payment_method
            );
        }

        if !config.enabled {
            bail!("Payment method config '{}' is disabled", config.name);
        }

        let provider_config = config
            .get_provider_config()
            .context("Failed to parse provider config")?;

        match provider_config {
            #[cfg(feature = "lnd")]
            ProviderConfig::Lnd(lnd_config) => {
                let node = payments_rs::lightning::LndNode::new(
                    &lnd_config.url,
                    &lnd_config.cert_path,
                    &lnd_config.macaroon_path,
                )
                .await
                .context("Failed to create LND node")?;
                Ok(Arc::new(node))
            }
            #[cfg(feature = "bitvora")]
            ProviderConfig::Bitvora(bitvora_config) => {
                // Webhook path is derived from provider type, not stored in DB
                let webhook_path = "/api/v1/webhook/bitvora";
                let node = payments_rs::lightning::BitvoraNode::new(
                    &bitvora_config.token,
                    &bitvora_config.webhook_secret,
                    webhook_path,
                );
                Ok(Arc::new(node))
            }
            #[allow(unreachable_patterns)]
            other => {
                bail!(
                    "Unsupported Lightning provider type: {}",
                    other.provider_type()
                )
            }
        }
    }

    /// Create a Fiat payment service handler from a PaymentMethodConfig
    ///
    /// Returns an error if the config is for Lightning, is disabled,
    /// or the provider type is not supported.
    pub async fn create_fiat_service(
        &self,
        config: &PaymentMethodConfig,
    ) -> Result<Arc<dyn FiatPaymentService>> {
        if !config.enabled {
            bail!("Payment method config '{}' is disabled", config.name);
        }

        let provider_config = config
            .get_provider_config()
            .context("Failed to parse provider config")?;

        match provider_config {
            #[cfg(feature = "revolut")]
            ProviderConfig::Revolut(revolut_config) => {
                let api = payments_rs::fiat::RevolutApi::new(payments_rs::fiat::RevolutConfig {
                    url: Some(revolut_config.url.clone()),
                    token: revolut_config.token.clone(),
                    api_version: revolut_config.api_version.clone(),
                    public_key: revolut_config.public_key.clone(),
                })
                .context("Failed to create Revolut API")?;
                Ok(Arc::new(api))
            }
            #[cfg(feature = "stripe")]
            ProviderConfig::Stripe(_stripe_config) => {
                // TODO: Implement Stripe factory when Stripe is fully supported
                bail!("Stripe payment integration not yet implemented")
            }
            ProviderConfig::Paypal(_) => {
                // TODO: Implement PayPal factory when PayPal is supported
                bail!("PayPal payment integration not yet implemented")
            }
            ProviderConfig::Lnd(_) | ProviderConfig::Bitvora(_) => {
                bail!("Cannot create fiat service from Lightning config")
            }
            #[allow(unreachable_patterns)]
            other => {
                bail!("Unsupported fiat provider type: {}", other.provider_type())
            }
        }
    }

    /// Get the Lightning node configuration for a company
    pub async fn get_lightning_node_for_company(
        &self,
        company_id: u64,
    ) -> Result<Option<Arc<dyn LightningNode>>> {
        match self
            .db
            .get_payment_method_config_for_company(company_id, PaymentMethod::Lightning)
            .await
        {
            Ok(config) => {
                if config.enabled {
                    match self.create_lightning_node(&config).await {
                        Ok(node) => Ok(Some(node)),
                        Err(e) => {
                            log::warn!(
                                "Failed to create Lightning node from config '{}': {}",
                                config.name,
                                e
                            );
                            Ok(None)
                        }
                    }
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None), // No config found for company
        }
    }

    /// Get a fiat payment service for a company and specific method
    pub async fn get_fiat_service_for_company(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> Result<Option<Arc<dyn FiatPaymentService>>> {
        if method == PaymentMethod::Lightning {
            bail!("Lightning is not a fiat payment method");
        }
        match self
            .db
            .get_payment_method_config_for_company(company_id, method)
            .await
        {
            Ok(config) => {
                if config.enabled {
                    match self.create_fiat_service(&config).await {
                        Ok(service) => Ok(Some(service)),
                        Err(e) => {
                            log::warn!(
                                "Failed to create fiat service from config '{}': {}",
                                config.name,
                                e
                            );
                            Ok(None)
                        }
                    }
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None), // No config found for company
        }
    }

    /// Get the Revolut payment service for a company
    pub async fn get_revolut_for_company(
        &self,
        company_id: u64,
    ) -> Result<Option<Arc<dyn FiatPaymentService>>> {
        self.get_fiat_service_for_company(company_id, PaymentMethod::Revolut)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{BitvoraConfig, LndConfig, RevolutProviderConfig};
    use std::path::PathBuf;

    #[allow(dead_code)]
    fn make_lightning_config(
        provider: &str,
        enabled: bool,
        company_id: u64,
    ) -> PaymentMethodConfig {
        let provider_config = match provider {
            "lnd" => ProviderConfig::Lnd(LndConfig {
                url: "https://localhost:8080".to_string(),
                cert_path: PathBuf::from("/path/to/cert"),
                macaroon_path: PathBuf::from("/path/to/macaroon"),
            }),
            "bitvora" => ProviderConfig::Bitvora(BitvoraConfig {
                token: "test-token".to_string(),
                webhook_secret: "test-secret".to_string(),
            }),
            _ => panic!("Unknown provider: {}", provider),
        };

        PaymentMethodConfig::new_with_config(
            company_id,
            PaymentMethod::Lightning,
            format!("Test {}", provider),
            enabled,
            provider_config,
        )
    }

    fn make_revolut_config(enabled: bool, company_id: u64) -> PaymentMethodConfig {
        let mut config = PaymentMethodConfig::new_with_config(
            company_id,
            PaymentMethod::Revolut,
            "Test Revolut".to_string(),
            enabled,
            ProviderConfig::Revolut(RevolutProviderConfig {
                url: "https://api.revolut.com".to_string(),
                token: "test-token".to_string(),
                api_version: "2024-09-01".to_string(),
                public_key: "pk_test_123".to_string(),
                webhook_secret: None,
            }),
        );
        config.processing_fee_rate = Some(1.0);
        config.processing_fee_base = Some(20);
        config.processing_fee_currency = Some("EUR".to_string());
        config
    }

    #[tokio::test]
    async fn test_disabled_config_not_returned() -> Result<()> {
        let db = Arc::new(MockDb::default());

        // Add a disabled revolut config for company 1
        {
            let mut configs = db.payment_method_configs.lock().await;
            configs.insert(1, make_revolut_config(false, 1));
        }

        let factory = PaymentMethodFactory::new(db);
        let result = factory.get_revolut_for_company(1).await?;

        // Disabled configs should not be returned
        assert!(result.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_create_lightning_node_wrong_method_fails() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let factory = PaymentMethodFactory::new(db);

        // Try to create lightning node from revolut config - should fail
        let config = make_revolut_config(true, 1);
        let result = factory.create_lightning_node(&config).await;

        match result {
            Err(e) => assert!(
                e.to_string().contains("Cannot create Lightning node"),
                "Expected error message about Lightning node, got: {}",
                e
            ),
            Ok(_) => panic!("Expected error for wrong payment method"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_create_fiat_service_from_lightning_fails() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let factory = PaymentMethodFactory::new(db);

        // Try to create fiat service from lightning config - should fail
        let config = make_lightning_config("bitvora", true, 1);
        let result = factory.create_fiat_service(&config).await;

        match result {
            Err(e) => assert!(
                e.to_string().contains("Cannot create fiat service"),
                "Expected error message about fiat service, got: {}",
                e
            ),
            Ok(_) => panic!("Expected error for wrong payment method"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_get_fiat_service_for_lightning_fails() -> Result<()> {
        let db = Arc::new(MockDb::default());
        let factory = PaymentMethodFactory::new(db);

        let result = factory
            .get_fiat_service_for_company(1, PaymentMethod::Lightning)
            .await;

        match result {
            Err(e) => assert!(
                e.to_string().contains("not a fiat payment method"),
                "Expected error message about non-fiat payment method, got: {}",
                e
            ),
            Ok(_) => panic!("Expected error for non-fiat payment method"),
        }

        Ok(())
    }
}
