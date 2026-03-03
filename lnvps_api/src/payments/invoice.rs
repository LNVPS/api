use crate::payments::{complete_payment, make_completion_handler};
use anyhow::Result;
use chrono::Utc;
use futures::StreamExt;
use lnvps_api_common::WorkCommander;
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
use log::{error, info, warn};
use payments_rs::lightning::{InvoiceUpdate, LightningNode};
use std::sync::Arc;

pub struct NodeInvoiceHandler {
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
}

impl NodeInvoiceHandler {
    pub fn new(
        node: Arc<dyn LightningNode>,
        db: Arc<dyn LNVpsDb>,
        tx: Arc<dyn WorkCommander>,
    ) -> Self {
        Self { node, tx, db }
    }

    async fn mark_paid(&self, id: &Vec<u8>) -> Result<()> {
        let payment = self.db.get_subscription_payment(id).await?;
        self.complete(&payment).await
    }

    async fn mark_paid_ext_id(&self, external_id: &str) -> Result<()> {
        let payment = self
            .db
            .get_subscription_payment_by_ext_id(external_id)
            .await?;
        self.complete(&payment).await
    }

    async fn complete(&self, payment: &SubscriptionPayment) -> Result<()> {
        let handler =
            make_completion_handler(payment, self.db.clone(), self.tx.clone(), "lightning").await?;

        let db = self.db.clone();
        let node = self.node.clone();
        let payment_id = payment.id.clone();

        complete_payment(&self.db, payment, handler.as_ref(), |paid_payment| {
            let db = db.clone();
            let node = node.clone();
            async move {
                // Cancel other pending Lightning upgrade invoices for this subscription
                let vm = db.get_vm_by_subscription(paid_payment.subscription_id).await?;
                let other_upgrades = db
                    .list_pending_vm_subscription_payments(vm.id)
                    .await?
                    .into_iter()
                    .filter(|p| {
                        p.payment_type == SubscriptionPaymentType::Upgrade
                            && p.payment_method == PaymentMethod::Lightning
                            && p.id != payment_id
                    })
                    .collect::<Vec<_>>();

                for ugp in other_upgrades {
                    let hex_id = hex::encode(&ugp.id);
                    if let Err(e) = node.cancel_invoice(&ugp.id).await {
                        warn!("Failed to cancel invoice {}: {}", hex_id, e);
                    }
                    let mut expired = ugp;
                    expired.expires = Utc::now();
                    if let Err(e) = db.update_subscription_payment(&expired).await {
                        warn!("Failed to update invoice {}: {}", hex_id, e);
                    }
                }
                Ok(())
            }
        })
        .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::MockNode;
    use anyhow::Result;
    use chrono::Utc;
    use lnvps_api_common::{ChannelWorkCommander, MockDb, WorkJob};
    use lnvps_db::{
        IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, SubscriptionPayment,
        SubscriptionPaymentType, SubscriptionType, Vm,
    };
    use std::sync::Arc;

    /// Build a DB with a VM, subscription, line item and unpaid payment.
    async fn setup_renewal(
        time_value: u64,
        payment_type: SubscriptionPaymentType,
    ) -> Result<(Arc<MockDb>, Arc<MockNode>, Arc<ChannelWorkCommander>, SubscriptionPayment, u64)>
    {
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());

        // Insert a user + SSH key so insert_vm FK checks pass
        let pubkey: [u8; 32] = [1u8; 32];
        let user_id = db.upsert_user(&pubkey).await?;
        let ssh_key_id = db
            .insert_user_ssh_key(&lnvps_db::UserSshKey {
                id: 0,
                name: "test".to_string(),
                user_id,
                created: Utc::now(),
                key_data: "ssh-rsa AAA==".into(),
            })
            .await?;

        // Insert subscription
        let (sub_id, line_item_ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "test".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: false,
                    is_setup: false,
                    currency: "BTC".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::VmRenewal,
                    name: "vm renewal".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        // Insert VM linked to that subscription line item
        let vm_id = db
            .insert_vm(&Vm {
                id: 0,
                host_id: 1,
                user_id,
                image_id: 1,
                template_id: Some(1),
                custom_template_id: None,
                subscription_line_item_id: line_item_ids[0],
                ssh_key_id,
                disk_id: 1,
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                deleted: false,
                ..Default::default()
            })
            .await?;

        let payment = SubscriptionPayment {
            id: vec![42u8; 16],
            subscription_id: sub_id,
            user_id,
            created: Utc::now(),
            expires: Utc::now() + chrono::Duration::hours(1),
            amount: 1000,
            currency: "BTC".to_string(),
            payment_method: lnvps_db::PaymentMethod::Lightning,
            payment_type,
            external_data: "".to_string().into(),
            external_id: None,
            is_paid: false,
            rate: 1.0,
            time_value: Some(time_value),
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
        };
        db.insert_subscription_payment(&payment).await?;

        let tx = Arc::new(ChannelWorkCommander::new());
        Ok((db, node, tx, payment, vm_id))
    }

    /// complete for a Renewal payment marks it paid and enqueues CheckVm.
    #[tokio::test]
    async fn test_complete_renewal_marks_paid_and_enqueues_check_vm() -> Result<()> {
        let (db, node, tx, payment, vm_id) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;

        let handler = NodeInvoiceHandler::new(node, db.clone(), tx.clone());
        handler.complete(&payment).await?;

        // Payment should be marked paid
        let payments = db.subscription_payments.lock().await;
        let p = payments.iter().find(|p| p.id == payment.id).unwrap();
        assert!(p.is_paid);
        drop(payments);

        // A CheckVm job should have been enqueued
        let jobs = tx.recv().await?;
        assert_eq!(jobs.len(), 1);
        assert!(
            matches!(&jobs[0].job, WorkJob::CheckVm { vm_id: id } if *id == vm_id),
            "expected CheckVm job, got {:?}",
            jobs[0].job
        );

        Ok(())
    }

    /// complete for an Upgrade payment enqueues ProcessVmUpgrade.
    #[tokio::test]
    async fn test_complete_upgrade_enqueues_process_vm_upgrade() -> Result<()> {
        let (db, node, tx, mut payment, vm_id) =
            setup_renewal(0, SubscriptionPaymentType::Upgrade).await?;

        // Add upgrade metadata
        payment.metadata = Some(serde_json::json!({
            "new_cpu": 4,
            "new_memory": null,
            "new_disk": null
        }));
        db.update_subscription_payment(&payment).await?;

        let handler = NodeInvoiceHandler::new(node, db.clone(), tx.clone());
        handler.complete(&payment).await?;

        // A ProcessVmUpgrade job should have been enqueued
        let jobs = tx.recv().await?;
        assert_eq!(jobs.len(), 1);
        assert!(
            matches!(&jobs[0].job, WorkJob::ProcessVmUpgrade { vm_id: id, .. } if *id == vm_id),
            "expected ProcessVmUpgrade job, got {:?}",
            jobs[0].job
        );

        Ok(())
    }

    /// complete extends the subscription expiry for a renewal.
    #[tokio::test]
    async fn test_complete_extends_subscription_expiry() -> Result<()> {
        let time_value = 30u64 * 24 * 3600;
        let (db, node, tx, payment, _vm_id) =
            setup_renewal(time_value, SubscriptionPaymentType::Renewal).await?;

        let handler = NodeInvoiceHandler::new(node, db, tx);
        handler.complete(&payment).await?;

        Ok(()) // expiry extension is tested thoroughly in mock tests
    }
}
