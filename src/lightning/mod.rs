use crate::lightning::lnd::LndNode;
use crate::settings::Settings;
use anyhow::Result;
use futures::Stream;
use lnvps_db::async_trait;
use std::pin::Pin;
use std::sync::Arc;

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
        settle_index: u64,
    },
}

pub async fn get_node(settings: &Settings) -> Result<Arc<dyn LightningNode>> {
    Ok(Arc::new(LndNode::new(&settings.lnd).await?))
}
