use crate::payments::handle_upgrade;
use anyhow::Result;
use chrono::Utc;
use futures::StreamExt;
use lnvps_api_common::WorkJob;
use lnvps_api_common::{VmHistoryLogger, WorkCommander};
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
use log::{error, info, warn};
use payments_rs::lightning::{InvoiceUpdate, LightningNode};
use std::sync::Arc;

pub struct NodeInvoiceHandler {
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    vm_history_logger: VmHistoryLogger,
}

impl NodeInvoiceHandler {
    pub fn new(
        node: Arc<dyn LightningNode>,
        db: Arc<dyn LNVpsDb>,
        tx: Arc<dyn WorkCommander>,
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
        let p = self.db.get_subscription_payment(id).await?;
        let vm = self.db.get_vm_by_subscription(p.subscription_id).await?;
        self.mark_payment_paid(&p, vm.id).await
    }

    async fn mark_paid_ext_id(&self, external_id: &str) -> Result<()> {
        let p = self
            .db
            .get_subscription_payment_by_ext_id(external_id)
            .await?;
        let vm = self.db.get_vm_by_subscription(p.subscription_id).await?;
        self.mark_payment_paid(&p, vm.id).await
    }

    async fn mark_payment_paid(&self, payment: &SubscriptionPayment, vm_id: u64) -> Result<()> {
        let vm_before = self.db.get_vm(vm_id).await?;

        self.db.subscription_payment_paid(payment).await?;

        let vm_after = self.db.get_vm(vm_id).await?;

        let payment_metadata = serde_json::json!({
            "payment_id": hex::encode(&payment.id),
            "payment_method": "lightning"
        });

        if let Err(e) = self
            .vm_history_logger
            .log_vm_payment_received(
                vm_id,
                payment.amount + payment.tax + payment.processing_fee,
                &payment.currency,
                payment.time_value.unwrap_or(0),
                Some(payment_metadata),
            )
            .await
        {
            warn!("Failed to log payment for VM {}: {}", vm_id, e);
        }

        let time_value = payment.time_value.unwrap_or(0);
        if time_value > 0
            && let Err(e) = self
                .vm_history_logger
                .log_vm_renewed(
                    vm_id,
                    None,
                    vm_before.expires,
                    vm_after.expires,
                    Some(payment.amount + payment.tax + payment.processing_fee),
                    Some(&payment.currency),
                    Some(serde_json::json!({
                        "time_added_seconds": time_value,
                        "payment_id": hex::encode(&payment.id)
                    })),
                )
                .await
        {
            warn!("Failed to log VM {} renewal: {}", vm_id, e);
        }

        info!(
            "Subscription payment {} for VM {}, paid",
            hex::encode(&payment.id),
            vm_id
        );

        if payment.payment_type == SubscriptionPaymentType::Upgrade {
            handle_upgrade(payment, vm_id, &self.tx, self.db.clone()).await?;

            // cancel other pending upgrade payments for this VM
            let other_upgrades = self
                .db
                .list_vm_subscription_payments(vm_id)
                .await?
                .into_iter()
                .filter(|p| {
                    !p.is_paid
                        && p.payment_type == SubscriptionPaymentType::Upgrade
                        && p.payment_method == PaymentMethod::Lightning
                        && p.id != payment.id
                })
                .collect::<Vec<_>>();

            for ugp in other_upgrades {
                let hex_id = hex::encode(&ugp.id);
                if let Err(e) = self.node.cancel_invoice(&ugp.id).await {
                    warn!("Failed to cancel invoice {}: {}", hex_id, e);
                }
                // mark as expired via update
                let mut expired = ugp;
                expired.expires = Utc::now();
                if let Err(e) = self.db.update_subscription_payment(&expired).await {
                    warn!("Failed to update invoice {}: {}", hex_id, e);
                }
            }
        } else {
            self.tx
                .send(WorkJob::CheckVm { vm_id })
                .await?;
        }

        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        let from_ph = self
            .db
            .last_paid_subscription_invoice()
            .await?
            .map(|i| i.id.clone());
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
                    ..
                } => {
                    if !payment_hash.is_empty() {
                        let r_hash = hex::decode(&payment_hash)?;
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
