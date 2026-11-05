use anyhow::{Context, Result};
use async_trait::async_trait;
use lnvps_db::{LNVpsDb, PaymentMethod};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOutput {
    pub address: String,
    pub amount_msat: u64,
    pub confirmed: bool,
    pub ours: bool,
}

#[async_trait]
pub trait ChainOutputLookup: Send + Sync {
    async fn lookup(&self, txid: &str, vout: u32) -> Result<Option<ChainOutput>>;
}

pub struct MempoolOutputLookup {
    base_url: String,
    client: reqwest::Client,
    db: Arc<dyn LNVpsDb>,
}

impl MempoolOutputLookup {
    pub fn new(base_url: impl Into<String>, db: Arc<dyn LNVpsDb>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
            db,
        }
    }

    async fn is_ours(&self, address: &str) -> Result<bool> {
        if self.db.get_onchain_address_owner(address).await?.is_some() {
            return Ok(true);
        }
        for method in [PaymentMethod::OnChain, PaymentMethod::FixedFloat] {
            let payments = self.db.list_subscription_payments_by_method(method).await?;
            if payments
                .iter()
                .any(|p| p.onchain_receive_address().as_deref() == Some(address))
            {
                return Ok(true);
            }
            let topups = self.db.list_account_credit_topups_by_method(method).await?;
            if topups
                .iter()
                .any(|t| method == PaymentMethod::OnChain && t.external_data == address)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Deserialize)]
struct EsploraTx {
    vout: Vec<EsploraVout>,
    status: EsploraStatus,
}

#[derive(Deserialize)]
struct EsploraVout {
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize)]
struct EsploraStatus {
    confirmed: bool,
}

#[async_trait]
impl ChainOutputLookup for MempoolOutputLookup {
    async fn lookup(&self, txid: &str, vout: u32) -> Result<Option<ChainOutput>> {
        let url = format!("{}/api/tx/{}", self.base_url.trim_end_matches('/'), txid);
        let res = self.client.get(url).send().await?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let tx: EsploraTx = res
            .error_for_status()?
            .json()
            .await
            .context("parsing esplora transaction")?;
        let Some(out) = tx.vout.into_iter().nth(vout as usize) else {
            return Ok(None);
        };
        let Some(address) = out.scriptpubkey_address else {
            return Ok(None);
        };
        let ours = self.is_ours(&address).await?;
        Ok(Some(ChainOutput {
            ours,
            address,
            amount_msat: out.value * 1000,
            confirmed: tx.status.confirmed,
        }))
    }
}
