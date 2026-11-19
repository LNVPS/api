//! Read-only chain lookups used to tell a live deposit from a replaced one.
//!
//! An on-chain deposit detected in the mempool can be replaced (RBF) by a
//! transaction that no longer pays us. Nothing ever arrives for the watched
//! address again, so the payment row keeps a deposit outpoint that will never
//! confirm. Detecting that needs the two facts the wallet cannot supply:
//! whether the transaction is still known to the network at all, and whether
//! the coins it spends have since been spent by something else.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

use crate::settings::ChainExplorerConfig;

/// What spent a given output, as far as the explorer knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outspend {
    /// Transaction that spends the output, if any.
    pub spent_by: Option<String>,
    /// Whether that spending transaction is confirmed.
    pub confirmed: bool,
}

/// An outpoint in the standard `{txid}:{vout}` notation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: String,
    pub vout: u32,
}

impl OutPoint {
    /// Parse `{txid}:{vout}`.
    pub fn parse(s: &str) -> Option<Self> {
        let (txid, vout) = s.rsplit_once(':')?;
        Some(Self {
            txid: txid.to_string(),
            vout: vout.parse().ok()?,
        })
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// Read-only chain queries. Abstracted so the conflict sweep can be tested
/// without an explorer, and so the source can be swapped by configuration.
#[async_trait]
pub trait ChainExplorer: Send + Sync {
    /// Outpoints spent by `txid`, i.e. its inputs. `None` when the transaction
    /// is unknown: a replaced transaction is evicted from every mempool and
    /// stops being served at all.
    async fn tx_inputs(&self, txid: &str) -> Result<Option<Vec<OutPoint>>>;

    /// What spends `outpoint`, if anything.
    async fn outspend(&self, outpoint: &OutPoint) -> Result<Outspend>;
}

/// Build a [`ChainExplorer`] from configuration.
pub fn build_chain_explorer(config: &ChainExplorerConfig) -> Option<Arc<dyn ChainExplorer>> {
    match config {
        ChainExplorerConfig::Mempool { url } => Some(Arc::new(MempoolChainExplorer::new(url))),
        ChainExplorerConfig::None => None,
    }
}

/// Queries a mempool.space / esplora-compatible HTTP API.
#[derive(Clone)]
pub struct MempoolChainExplorer {
    base_url: String,
    client: reqwest::Client,
}

impl MempoolChainExplorer {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/{}", self.base_url.trim_end_matches('/'), path)
    }
}

#[derive(serde::Deserialize)]
struct EsploraTx {
    vin: Vec<EsploraVin>,
}

#[derive(serde::Deserialize)]
struct EsploraVin {
    txid: String,
    vout: u32,
}

#[derive(serde::Deserialize)]
struct EsploraOutspend {
    spent: bool,
    txid: Option<String>,
    #[serde(default)]
    status: Option<EsploraStatus>,
}

#[derive(serde::Deserialize)]
struct EsploraStatus {
    confirmed: bool,
}

#[async_trait]
impl ChainExplorer for MempoolChainExplorer {
    async fn tx_inputs(&self, txid: &str) -> Result<Option<Vec<OutPoint>>> {
        let res = self
            .client
            .get(self.url(&format!("tx/{txid}")))
            .send()
            .await?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let tx: EsploraTx = res
            .error_for_status()?
            .json()
            .await
            .context("parsing esplora transaction")?;
        Ok(Some(
            tx.vin
                .into_iter()
                .map(|v| OutPoint {
                    txid: v.txid,
                    vout: v.vout,
                })
                .collect(),
        ))
    }

    async fn outspend(&self, outpoint: &OutPoint) -> Result<Outspend> {
        let res: EsploraOutspend = self
            .client
            .get(self.url(&format!("tx/{}/outspend/{}", outpoint.txid, outpoint.vout)))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("parsing esplora outspend")?;
        Ok(Outspend {
            spent_by: res.txid.filter(|_| res.spent),
            confirmed: res.status.map(|s| s.confirmed).unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_outpoint_round_trip() {
        let op = OutPoint::parse("abc:12").unwrap();
        assert_eq!(op.txid, "abc");
        assert_eq!(op.vout, 12);
        assert_eq!(op.to_string(), "abc:12");
        assert!(OutPoint::parse("abc").is_none());
        assert!(OutPoint::parse("abc:x").is_none());
    }

    #[test]
    fn test_build_chain_explorer() {
        assert!(
            build_chain_explorer(&ChainExplorerConfig::Mempool {
                url: "https://mempool.space".to_string(),
            })
            .is_some()
        );
        assert!(build_chain_explorer(&ChainExplorerConfig::None).is_none());
    }

    #[tokio::test]
    async fn test_tx_inputs_parses_vin() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tx/dead"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vin": [{"txid": "parent", "vout": 12}]
            })))
            .mount(&server)
            .await;

        let inputs = MempoolChainExplorer::new(server.uri())
            .tx_inputs("dead")
            .await
            .unwrap();
        assert_eq!(inputs, Some(vec![OutPoint::parse("parent:12").unwrap()]));
    }

    /// A transaction the explorer has never heard of is reported as unknown,
    /// not as an error: that is what a replaced transaction looks like.
    #[tokio::test]
    async fn test_tx_inputs_unknown_transaction() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tx/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        assert_eq!(
            MempoolChainExplorer::new(server.uri())
                .tx_inputs("gone")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn test_outspend_reports_spender() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tx/parent/outspend/12"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "spent": true,
                "txid": "replacement",
                "vin": 0,
                "status": {"confirmed": true}
            })))
            .mount(&server)
            .await;

        let spend = MempoolChainExplorer::new(server.uri())
            .outspend(&OutPoint::parse("parent:12").unwrap())
            .await
            .unwrap();
        assert_eq!(spend.spent_by.as_deref(), Some("replacement"));
        assert!(spend.confirmed);
    }

    #[tokio::test]
    async fn test_outspend_unspent_has_no_spender() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tx/parent/outspend/0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"spent": false, "txid": null})),
            )
            .mount(&server)
            .await;

        let spend = MempoolChainExplorer::new(server.uri())
            .outspend(&OutPoint::parse("parent:0").unwrap())
            .await
            .unwrap();
        assert_eq!(spend.spent_by, None);
        assert!(!spend.confirmed);
    }

    #[tokio::test]
    async fn test_http_errors_propagate() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let explorer = MempoolChainExplorer::new(server.uri());
        assert!(explorer.tx_inputs("boom").await.is_err());
        assert!(
            explorer
                .outspend(&OutPoint::parse("boom:0").unwrap())
                .await
                .is_err()
        );
    }
}
