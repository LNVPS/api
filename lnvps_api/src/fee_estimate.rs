//! On-chain fee-rate estimation.
//!
//! Abstracted behind the [`FeeEstimator`] trait so callers (e.g. the referral
//! on-chain payout batcher, which defers when fees are high) can be unit-tested
//! with a mock and the source can be swapped via configuration.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

use crate::settings::FeeEstimatorConfig;

/// Source of on-chain fee-rate estimates, in **sat/vByte**.
#[async_trait]
pub trait FeeEstimator: Send + Sync {
    /// Estimated next-block ("fastest") confirmation fee rate, sat/vByte.
    async fn next_block_fee_rate(&self) -> Result<u64>;
}

/// Build a [`FeeEstimator`] from configuration.
pub fn build_fee_estimator(config: &FeeEstimatorConfig) -> Arc<dyn FeeEstimator> {
    match config {
        FeeEstimatorConfig::Mempool { url } => Arc::new(MempoolFeeEstimator::new(url.clone())),
        FeeEstimatorConfig::Fixed { sat_per_vbyte } => Arc::new(FixedFeeEstimator(*sat_per_vbyte)),
    }
}

/// Fetches the recommended next-block fee rate from a mempool.space-compatible
/// instance (`GET {base_url}/api/v1/fees/recommended`).
#[derive(Clone)]
pub struct MempoolFeeEstimator {
    base_url: String,
    client: reqwest::Client,
}

impl MempoolFeeEstimator {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[derive(serde::Deserialize)]
struct RecommendedFees {
    #[serde(rename = "fastestFee")]
    fastest_fee: u64,
}

#[async_trait]
impl FeeEstimator for MempoolFeeEstimator {
    async fn next_block_fee_rate(&self) -> Result<u64> {
        let url = format!(
            "{}/api/v1/fees/recommended",
            self.base_url.trim_end_matches('/')
        );
        let fees: RecommendedFees = self
            .client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("parsing mempool.space recommended fees")?;
        Ok(fees.fastest_fee)
    }
}

/// A constant fee-rate estimator — for tests and the config-driven fixed rate
/// (e.g. regtest, where there is no mempool.space).
#[derive(Clone)]
pub struct FixedFeeEstimator(pub u64);

#[async_trait]
impl FeeEstimator for FixedFeeEstimator {
    async fn next_block_fee_rate(&self) -> Result<u64> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fixed_estimator_returns_value() {
        assert_eq!(
            FixedFeeEstimator(42).next_block_fee_rate().await.unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn mempool_estimator_parses_fastest_fee() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "fastestFee": 37,
                "halfHourFee": 20,
                "hourFee": 10,
                "economyFee": 5,
                "minimumFee": 1
            })))
            .mount(&server)
            .await;

        let est = MempoolFeeEstimator::new(server.uri());
        assert_eq!(est.next_block_fee_rate().await.unwrap(), 37);
    }

    #[tokio::test]
    async fn mempool_estimator_errors_on_http_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let est = MempoolFeeEstimator::new(server.uri());
        assert!(est.next_block_fee_rate().await.is_err());
    }

    #[test]
    fn build_from_config() {
        let _: Arc<dyn FeeEstimator> =
            build_fee_estimator(&FeeEstimatorConfig::Fixed { sat_per_vbyte: 7 });
        let _: Arc<dyn FeeEstimator> = build_fee_estimator(&FeeEstimatorConfig::Mempool {
            url: "https://mempool.space".to_string(),
        });
    }
}
