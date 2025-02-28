use crate::lightning::{InvoiceUpdate, LightningNode};
use crate::worker::WorkJob;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::{error, info, warn};
use nostr::util::hex;
use rocket::futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

pub struct InvoiceHandler {
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    tx: UnboundedSender<WorkJob>,
}

impl InvoiceHandler {
    pub fn new(
        node: Arc<dyn LightningNode>,
        db: Arc<dyn LNVpsDb>,
        tx: UnboundedSender<WorkJob>,
    ) -> Self {
        Self { node, tx, db }
    }

    async fn mark_paid(&self, settle_index: u64, id: &Vec<u8>) -> Result<()> {
        let mut p = self.db.get_vm_payment(id).await?;
        p.settle_index = Some(settle_index);
        self.db.vm_payment_paid(&p).await?;

        info!("VM payment {} for {}, paid", hex::encode(p.id), p.vm_id);
        self.tx.send(WorkJob::CheckVm { vm_id: p.vm_id })?;

        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        let from_ph = self.db.last_paid_invoice().await?.map(|i| i.id.clone());
        info!(
            "Listening for invoices from {}",
            from_ph
                .as_ref()
                .map(hex::encode)
                .unwrap_or("NOW".to_string())
        );

        let mut handler = self.node.subscribe_invoices(from_ph).await?;
        while let Some(msg) = handler.next().await {
            match msg {
                InvoiceUpdate::Settled {
                    payment_hash,
                    settle_index,
                } => {
                    let r_hash = hex::decode(payment_hash)?;
                    if let Err(e) = self.mark_paid(settle_index, &r_hash).await {
                        error!("{}", e);
                    }
                }
                v => warn!("Unknown invoice update: {:?}", v),
            }
        }
        Ok(())
    }
}
