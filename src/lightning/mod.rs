use crate::settings::{LightningConfig, Settings};
use anyhow::Result;
use futures::Stream;
use lnvps_db::async_trait;
use std::pin::Pin;
use std::sync::Arc;

#[cfg(feature = "bitvora")]
mod bitvora;
#[cfg(feature = "lnd")]
mod lnd;

/// Generic lightning node for creating payments
#[async_trait]
pub trait LightningNode: Send + Sync {
    async fn add_invoice(&self, req: AddInvoiceRequest) -> Result<AddInvoiceResult>;
    async fn subscribe_invoices(
        &self,
        from_payment_hash: Option<Vec<u8>>,
    ) -> Result<Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>>;
}

#[derive(Debug, Clone)]
pub struct AddInvoiceRequest {
    pub amount: u64,
    pub memo: Option<String>,
    pub expire: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AddInvoiceResult {
    pub pr: String,
    pub payment_hash: String,
}

#[derive(Debug, Clone)]
pub enum InvoiceUpdate {
    /// Internal impl created an update which we don't support or care about
    Unknown,
    Error(String),
    Settled {
        payment_hash: String,
    },
}

pub async fn get_node(settings: &Settings) -> Result<Arc<dyn LightningNode>> {
    match &settings.lightning {
        #[cfg(feature = "lnd")]
        LightningConfig::LND {
            url,
            cert,
            macaroon,
        } => Ok(Arc::new(lnd::LndNode::new(url, cert, macaroon).await?)),
        #[cfg(feature = "bitvora")]
        LightningConfig::Bitvora {
            token,
            webhook_secret,
        } => Ok(Arc::new(bitvora::BitvoraNode::new(token, webhook_secret))),
        _ => anyhow::bail!("Unsupported lightning config!"),
    }
}
