use crate::lightning::{InvoiceUpdate, LightningNode};
use crate::worker::WorkJob;
use anyhow::Result;
use lnvps_db::{LNVpsDb, VmPayment};
use log::{error, info, warn};
use nostr::util::hex;
use rocket::futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

pub struct NodeInvoiceHandler {
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    tx: UnboundedSender<WorkJob>,
}

impl NodeInvoiceHandler {
    pub fn new(
        node: Arc<dyn LightningNode>,
        db: Arc<dyn LNVpsDb>,
        tx: UnboundedSender<WorkJob>,
    ) -> Self {
        Self { node, tx, db }
    }

    async fn mark_paid(&self, id: &Vec<u8>) -> Result<()> {
        let p = self.db.get_vm_payment(id).await?;
        self.mark_payment_paid(&p).await
    }

    async fn mark_paid_ext_id(&self, external_id: &str) -> Result<()> {
        let p = self.db.get_vm_payment_by_ext_id(external_id).await?;
        self.mark_payment_paid(&p).await
    }

    async fn mark_payment_paid(&self, payment: &VmPayment) -> Result<()> {
        self.db.vm_payment_paid(&payment).await?;

        info!("VM payment {} for {}, paid", hex::encode(&payment.id), payment.vm_id);
        self.tx.send(WorkJob::CheckVm { vm_id: payment.vm_id })?;

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
                    external_id,
                } => {
                    if let Some(h) = payment_hash {
                        let r_hash = hex::decode(h)?;
                        if let Err(e) = self.mark_paid(&r_hash).await {
                            error!("{}", e);
                        }
                        continue;
                    }
                    if let Some(e) = external_id {
                        if let Err(e) = self.mark_paid_ext_id(&e).await {
                            error!("{}", e);
                        }
                        continue;
                    }
                }
                v => warn!("Unknown invoice update: {:?}", v),
            }
        }
        Ok(())
    }
}
