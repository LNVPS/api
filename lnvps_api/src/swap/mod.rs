use anyhow::{Result, bail};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lnvps_db::{PaymentMethodConfig, ProviderConfig};
use std::sync::Arc;

mod fixedfloat;

pub use fixedfloat::FixedFloat;
pub use lnvps_api_common::SwapData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapOrderRequest {
    pub coin: String,
    pub receive_sats: u64,
    pub receive_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapOrder {
    pub data: SwapData,
    pub expires: DateTime<Utc>,
}

#[async_trait]
pub trait SwapProvider: Send + Sync {
    async fn create_order(&self, req: SwapOrderRequest) -> Result<SwapOrder>;
}

pub fn provider_for_config(config: &PaymentMethodConfig) -> Result<Arc<dyn SwapProvider>> {
    match config.get_provider_config() {
        Some(ProviderConfig::FixedFloat(cfg)) => Ok(Arc::new(FixedFloat::new(&cfg))),
        Some(other) => bail!("Unsupported swap provider type: {}", other.provider_type()),
        None => bail!("Failed to parse swap provider config"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_db::{FixedFloatProviderConfig, PaymentMethod, RevolutProviderConfig};

    fn config(provider: ProviderConfig) -> PaymentMethodConfig {
        PaymentMethodConfig::new_with_config(
            1,
            provider.payment_method(),
            "x".to_string(),
            true,
            provider,
        )
    }

    #[test]
    fn provider_for_config_builds_fixedfloat() {
        let cfg = config(ProviderConfig::FixedFloat(FixedFloatProviderConfig {
            api_key: "k".to_string(),
            api_secret: "s".to_string(),
            url: None,
            refcode: None,
            afftax: None,
        }));
        assert_eq!(cfg.payment_method, PaymentMethod::FixedFloat);
        assert!(provider_for_config(&cfg).is_ok());
    }

    #[test]
    fn provider_for_config_rejects_other_providers() {
        let cfg = config(ProviderConfig::Revolut(RevolutProviderConfig {
            url: "https://x".to_string(),
            token: "t".to_string(),
            api_version: "v".to_string(),
            public_key: "p".to_string(),
            webhook_secret: None,
        }));
        assert!(provider_for_config(&cfg).is_err());
    }

    #[test]
    fn provider_for_config_rejects_unparsable_config() {
        let mut cfg = config(ProviderConfig::FixedFloat(FixedFloatProviderConfig {
            api_key: "k".to_string(),
            api_secret: "s".to_string(),
            url: None,
            refcode: None,
            afftax: None,
        }));
        cfg.config = None;
        assert!(provider_for_config(&cfg).is_err());
    }
}
