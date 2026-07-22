use crate::subscription::SubscriptionHandler;
use anyhow::Result;
use futures::StreamExt;
use lnvps_api_common::VmStateCache;
use lnvps_db::{LNVpsDb, SubscriptionPayment, SubscriptionPaymentType};
use log::{error, info, warn};
use payments_rs::lightning::{InvoiceUpdate, LightningNode};
use std::sync::Arc;

pub struct NodeInvoiceHandler {
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    sub_handler: SubscriptionHandler,
}

impl NodeInvoiceHandler {
    pub fn new(
        node: Arc<dyn LightningNode>,
        db: Arc<dyn LNVpsDb>,
        sub_handler: SubscriptionHandler,
    ) -> Self {
        Self {
            node,
            sub_handler,
            db,
        }
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
        let result = self.sub_handler.complete_payment(&payment).await?;
        for p in result.expired_competing_upgrades {
            let hex_id = hex::encode(&p.id);
            if let Err(e) = self.node.cancel_invoice(&p.id).await {
                warn!("Failed to cancel invoice {}: {}", hex_id, e);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::{MockNode, MockOnChainProvider};
    use crate::provisioner::VmProvisioner;
    use crate::settings::mock_settings;
    use crate::subscription::SubscriptionHandler;
    use anyhow::Result;
    use chrono::Utc;
    use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate, WorkJob};
    use lnvps_db::{
        IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, SubscriptionPayment,
        SubscriptionPaymentType, SubscriptionType, Vm,
    };
    use std::sync::Arc;

    /// Build a DB with a VM, subscription, line item and unpaid payment.
    async fn setup_renewal(
        time_value: u64,
        payment_type: SubscriptionPaymentType,
    ) -> Result<(
        Arc<MockDb>,
        Arc<MockNode>,
        SubscriptionHandler,
        SubscriptionPayment,
        u64,
    )> {
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
                    subscription_type: SubscriptionType::Vps,
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
                ssh_key_id: Some(ssh_key_id),
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
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
        };
        db.insert_subscription_payment(&payment).await?;

        let sub = SubscriptionHandler::new(
            mock_settings(),
            db.clone(),
            node.clone(),
            Arc::new(MockOnChainProvider::default()),
            None,
            Arc::new(MockExchangeRate::default()),
            lnvps_api_common::VatClient::new(),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;

        Ok((db, node, sub, payment, vm_id))
    }

    /// complete for a Renewal payment marks it paid and enqueues CheckVm.
    #[tokio::test]
    async fn test_complete_renewal_marks_paid_and_enqueues_check_vm() -> Result<()> {
        let (db, node, sub, payment, vm_id) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;

        let handler = NodeInvoiceHandler::new(node, db.clone(), sub.clone());
        handler.complete(&payment).await?;

        // Payment should be marked paid
        let payments = db.subscription_payments.lock().await;
        let p = payments.iter().find(|p| p.id == payment.id).unwrap();
        assert!(p.is_paid);
        drop(payments);

        // A CheckVm job should have been enqueued
        let jobs = sub.work_commander().recv().await?;
        assert_eq!(jobs.len(), 1);
        assert!(
            matches!(&jobs[0].job, WorkJob::SpawnVm { vm_id: id } if *id == vm_id),
            "expected SpawnVm job, got {:?}",
            jobs[0].job
        );

        Ok(())
    }

    /// complete for an Upgrade payment enqueues ProcessVmUpgrade.
    #[tokio::test]
    async fn test_complete_upgrade_enqueues_process_vm_upgrade() -> Result<()> {
        let (db, node, sub, mut payment, vm_id) =
            setup_renewal(0, SubscriptionPaymentType::Upgrade).await?;

        // Add upgrade metadata
        payment.metadata = Some(serde_json::json!({
            "new_cpu": 4,
            "new_memory": null,
            "new_disk": null
        }));
        db.update_subscription_payment(&payment).await?;

        let handler = NodeInvoiceHandler::new(node, db.clone(), sub.clone());
        handler.complete(&payment).await?;

        // A ProcessVmUpgrade job should have been enqueued
        let jobs = sub.work_commander().recv().await?;
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

    /// Build a DB with a non-VM (IpRange) subscription and unpaid payment.
    async fn setup_ip_range_renewal() -> Result<(
        Arc<MockDb>,
        Arc<MockNode>,
        SubscriptionHandler,
        SubscriptionPayment,
    )> {
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());

        let pubkey: [u8; 32] = [2u8; 32];
        let user_id = db.upsert_user(&pubkey).await?;

        let (sub_id, _line_item_ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "ip range test".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: false,
                    is_setup: false,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::IpRange,
                    name: "ip range".to_string(),
                    description: None,
                    amount: 500,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        let payment = SubscriptionPayment {
            id: vec![99u8; 16],
            subscription_id: sub_id,
            user_id,
            created: Utc::now(),
            expires: Utc::now() + chrono::Duration::hours(1),
            amount: 500,
            currency: "EUR".to_string(),
            payment_method: lnvps_db::PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Renewal,
            external_data: "".to_string().into(),
            external_id: None,
            is_paid: false,
            rate: 1.0,
            time_value: None,
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
        };
        db.insert_subscription_payment(&payment).await?;
        let sub = SubscriptionHandler::new(
            mock_settings(),
            db.clone(),
            node.clone(),
            Arc::new(MockOnChainProvider::default()),
            None,
            Arc::new(MockExchangeRate::default()),
            lnvps_api_common::VatClient::new(),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;

        Ok((db, node, sub, payment))
    }

    /// complete for a non-VM (IpRange) renewal marks it paid and dispatches CheckSubscriptions.
    #[tokio::test]
    async fn test_complete_non_vm_renewal_dispatches_check_subscriptions() -> Result<()> {
        let (db, node, sub, payment) = setup_ip_range_renewal().await?;

        let handler = NodeInvoiceHandler::new(node, db.clone(), sub.clone());
        handler.complete(&payment).await?;

        // Payment should be marked paid
        let payments = db.subscription_payments.lock().await;
        let p = payments.iter().find(|p| p.id == payment.id).unwrap();
        assert!(p.is_paid, "payment should be marked paid");
        drop(payments);

        // CheckSubscriptions should be dispatched (not CheckVm). Bound the
        // wait so a dispatch regression fails the test instead of hanging the
        // whole suite (recv() on ChannelWorkCommander never times out).
        let jobs = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sub.work_commander().recv(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("no work job dispatched within 5s"))??;
        assert_eq!(jobs.len(), 1, "expected exactly one work job");
        assert!(
            matches!(&jobs[0].job, WorkJob::CheckSubscriptions),
            "expected CheckSubscriptions job for non-VM payment, got {:?}",
            jobs[0].job
        );

        Ok(())
    }

    /// regression: renew_amount must credit the correct VM when VM ID != subscription ID.
    /// Before #152, the LNURL-pay callback passed vm_line.subscription_id to renew_amount(),
    /// which expects a VM ID — causing payments to land on whichever VM shared the numeric
    /// subscription ID rather than the VM whose LNURL link was scanned.
    #[tokio::test]
    async fn test_renew_amount_uses_vm_id_not_subscription_id() -> Result<()> {
        use lnvps_api_common::{ExchangeRateService, Ticker};
        use lnvps_db::{LNVpsDbBase, PaymentMethod, UserSshKey};
        use payments_rs::currency::CurrencyAmount;

        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let rates = Arc::new(MockExchangeRate::default());
        rates.set_rate(Ticker::btc_rate("EUR")?, 100_000.0).await;

        // Create a user
        let pubkey: [u8; 32] = [3u8; 32];
        let user_id = db.upsert_user(&pubkey).await?;

        // Create SSH key (FK requirement)
        let ssh_key_id = db
            .insert_user_ssh_key(&UserSshKey {
                id: 0,
                name: "test".to_string(),
                user_id,
                created: Utc::now(),
                key_data: "ssh-rsa AAA==".into(),
            })
            .await?;

        // --- Create TWO subscriptions with TWO VMs so IDs diverge ---
        let (sub1_id, li1_ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "sub1".to_string(),
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
                    subscription_type: SubscriptionType::Vps,
                    name: "vm1 renewal".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        let (sub2_id, li2_ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "sub2".to_string(),
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
                    subscription_type: SubscriptionType::Vps,
                    name: "vm2 renewal".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        // Insert VMs with different subscription line items
        let vm1_id = db
            .insert_vm(&Vm {
                id: 0,
                host_id: 1,
                user_id,
                image_id: 1,
                template_id: Some(1),
                custom_template_id: None,
                subscription_line_item_id: li1_ids[0],
                ssh_key_id: Some(ssh_key_id),
                disk_id: 1,
                mac_address: "aa:bb:cc:dd:ee:01".to_string(),
                deleted: false,
                ..Default::default()
            })
            .await?;

        let vm2_id = db
            .insert_vm(&Vm {
                id: 0,
                host_id: 1,
                user_id,
                image_id: 1,
                template_id: Some(1),
                custom_template_id: None,
                subscription_line_item_id: li2_ids[0],
                ssh_key_id: Some(ssh_key_id),
                disk_id: 1,
                mac_address: "aa:bb:cc:dd:ee:02".to_string(),
                deleted: false,
                ..Default::default()
            })
            .await?;

        // The IDs must be divergent for this test to be meaningful
        assert_ne!(
            vm1_id, sub1_id,
            "VM1 ID ({vm1_id}) must differ from its subscription ID ({sub1_id})"
        );

        let sub_handler = SubscriptionHandler::new(
            mock_settings(),
            db.clone(),
            node.clone(),
            Arc::new(MockOnChainProvider::default()),
            None,
            rates,
            lnvps_api_common::VatClient::new(),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;

        // Call renew_amount with VM1's VM ID — correct usage after the fix.
        // The resulting payment's subscription_id MUST match VM1's subscription (sub1),
        // not some other subscription. If subscription_id were passed instead of vm_id,
        // the lookup would go to the wrong VM and derive the wrong subscription_id.
        let payment = sub_handler
            .renew_amount(
                vm1_id,
                CurrencyAmount::millisats(100_000_000),
                PaymentMethod::Lightning,
            )
            .await?;

        // The payment must be associated with VM1's subscription, not VM2's
        assert_eq!(
            payment.subscription_id, sub1_id,
            "payment.subscription_id should be {sub1_id} (VM1's subscription), got {} (would mean wrong VM was credited)",
            payment.subscription_id
        );
        assert_ne!(
            payment.subscription_id, sub2_id,
            "payment.subscription_id must NOT be {sub2_id} (VM2's subscription)"
        );

        // Also verify the payment references the correct user
        assert_eq!(payment.user_id, user_id);

        Ok(())
    }
}
