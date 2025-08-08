use crate::lightning::{InvoiceUpdate, LightningNode};
use lnvps_api_common::VmHistoryLogger;
use anyhow::Result;
use lnvps_api_common::WorkJob;
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
    vm_history_logger: VmHistoryLogger,
}

impl NodeInvoiceHandler {
    pub fn new(
        node: Arc<dyn LightningNode>,
        db: Arc<dyn LNVpsDb>,
        tx: UnboundedSender<WorkJob>,
    ) -> Self {
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        Self {
            node,
            tx,
            db,
            vm_history_logger,
        }
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
        // Get VM state before payment processing
        let vm_before = self.db.get_vm(payment.vm_id).await?;

        self.db.vm_payment_paid(payment).await?;

        // Get VM state after payment processing
        let vm_after = self.db.get_vm(payment.vm_id).await?;

        // Log payment received in VM history
        let payment_metadata = serde_json::json!({
            "payment_id": hex::encode(&payment.id),
            "payment_method": "lightning"
        });

        if let Err(e) = self
            .vm_history_logger
            .log_vm_payment_received(
                payment.vm_id,
                payment.amount,
                &payment.currency,
                payment.time_value,
                Some(payment_metadata),
            )
            .await
        {
            warn!("Failed to log payment for VM {}: {}", payment.vm_id, e);
        }

        // Log VM renewal if this extends the expiration
        if payment.time_value > 0 {
            if let Err(e) = self
                .vm_history_logger
                .log_vm_renewed(
                    payment.vm_id,
                    None,
                    vm_before.expires,
                    vm_after.expires,
                    Some(payment.amount),
                    Some(&payment.currency),
                    Some(serde_json::json!({
                        "time_added_seconds": payment.time_value,
                        "payment_id": hex::encode(&payment.id)
                    })),
                )
                .await
            {
                warn!("Failed to log VM {} renewal: {}", payment.vm_id, e);
            }
        }

        info!(
            "VM payment {} for {}, paid",
            hex::encode(&payment.id),
            payment.vm_id
        );
        self.tx.send(WorkJob::CheckVm {
            vm_id: payment.vm_id,
        })?;

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
