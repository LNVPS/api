use crate::payments::invoice::NodeInvoiceHandler;
use crate::settings::Settings;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_api_common::{UpgradeConfig, VmHistoryLogger, WorkCommander, WorkJob};
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType, SubscriptionType};
use log::{error, info, warn};
use payments_rs::lightning::LightningNode;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::sleep;

mod invoice;
#[cfg(feature = "revolut")]
mod revolut;
#[cfg(feature = "stripe")]
mod stripe;

// =========================================================================
// PaymentCompletionHandler trait
// =========================================================================

/// Called after `subscription_payment_paid()` succeeds.
/// Implementors perform any product-specific side-effects (history logging,
/// work-job dispatch, resource activation, etc.).
#[async_trait]
pub(crate) trait PaymentCompletionHandler: Send + Sync {
    async fn on_payment_complete(
        &self,
        payment: &SubscriptionPayment,
    ) -> Result<()>;
}

// =========================================================================
// VmPaymentCompletionHandler
// =========================================================================

pub(crate) struct VmPaymentCompletionHandler {
    vm_id: u64,
    vm_expires_before: chrono::DateTime<chrono::Utc>,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    vm_history_logger: VmHistoryLogger,
    payment_method_label: &'static str,
}

impl VmPaymentCompletionHandler {
    pub(crate) async fn new(
        vm_id: u64,
        db: Arc<dyn LNVpsDb>,
        tx: Arc<dyn WorkCommander>,
        payment_method_label: &'static str,
    ) -> Result<Self> {
        let vm = db.get_vm(vm_id).await?;
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        Ok(Self {
            vm_id,
            vm_expires_before: vm.expires,
            db,
            tx,
            vm_history_logger,
            payment_method_label,
        })
    }
}

#[async_trait]
impl PaymentCompletionHandler for VmPaymentCompletionHandler {
    async fn on_payment_complete(&self, payment: &SubscriptionPayment) -> Result<()> {
        let vm_id = self.vm_id;
        let vm_after = self.db.get_vm(vm_id).await?;

        let payment_metadata = serde_json::json!({
            "payment_id": hex::encode(&payment.id),
            "payment_method": self.payment_method_label
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
        if time_value > 0 {
            if let Err(e) = self
                .vm_history_logger
                .log_vm_renewed(
                    vm_id,
                    None,
                    self.vm_expires_before,
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
        }

        info!(
            "Subscription payment {} for VM {}, paid",
            hex::encode(&payment.id),
            vm_id
        );

        if payment.payment_type == SubscriptionPaymentType::Upgrade {
            handle_upgrade(payment, vm_id, &self.tx, self.db.clone()).await?;
        } else {
            self.tx.send(WorkJob::CheckVm { vm_id }).await?;
        }

        Ok(())
    }
}

// =========================================================================
// NonVmPaymentCompletionHandler — generic handler for non-VM subscriptions
// =========================================================================

pub(crate) struct NonVmPaymentCompletionHandler {
    tx: Arc<dyn WorkCommander>,
}

impl NonVmPaymentCompletionHandler {
    pub(crate) fn new(tx: Arc<dyn WorkCommander>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl PaymentCompletionHandler for NonVmPaymentCompletionHandler {
    async fn on_payment_complete(&self, _payment: &SubscriptionPayment) -> Result<()> {
        // Trigger the subscription lifecycle check so the new expiry is picked up
        self.tx.send(WorkJob::CheckSubscriptions).await?;
        Ok(())
    }
}

// =========================================================================
// Composite dispatcher — selects the right handler by subscription type
// =========================================================================

pub(crate) async fn make_completion_handler(
    payment: &SubscriptionPayment,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    payment_method_label: &'static str,
) -> Result<Box<dyn PaymentCompletionHandler>> {
    let line_items = db.list_subscription_line_items(payment.subscription_id).await?;
    let has_vm = line_items.iter().any(|li| {
        matches!(
            li.subscription_type,
            SubscriptionType::VmRenewal | SubscriptionType::VmUpgrade
        )
    });

    if has_vm {
        let vm = db.get_vm_by_subscription(payment.subscription_id).await?;
        let handler = VmPaymentCompletionHandler::new(vm.id, db, tx, payment_method_label).await?;
        Ok(Box::new(handler))
    } else {
        Ok(Box::new(NonVmPaymentCompletionHandler::new(tx)))
    }
}

// =========================================================================
// Centralised complete_payment pipeline
// =========================================================================

/// Complete a payment:
/// 1. Mark paid in DB (extends subscription/vm expiry atomically)
/// 2. Run product-specific completion handler
/// 3. Run the payment-method-specific cancel function for competing upgrades
pub(crate) async fn complete_payment<F, Fut>(
    db: &Arc<dyn LNVpsDb>,
    payment: &SubscriptionPayment,
    handler: &dyn PaymentCompletionHandler,
    cancel_competing_upgrades: F,
) -> Result<()>
where
    F: FnOnce(SubscriptionPayment) -> Fut + Send,
    Fut: Future<Output = Result<()>> + Send,
{
    db.subscription_payment_paid(payment).await?;
    handler.on_payment_complete(payment).await?;
    if payment.payment_type == SubscriptionPaymentType::Upgrade {
        cancel_competing_upgrades(payment.clone()).await?;
    }
    Ok(())
}

// =========================================================================
// listen_all_payments
// =========================================================================

pub async fn listen_all_payments(
    settings: &Settings,
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    sender: Arc<dyn WorkCommander>,
) -> Result<Vec<JoinHandle<()>>> {
    let mut ret = Vec::new();
    let mut handler = NodeInvoiceHandler::new(node.clone(), db.clone(), sender.clone());
    ret.push(tokio::spawn(async move {
        loop {
            if let Err(e) = handler.listen().await {
                error!("invoice-error: {}", e);
            }
            sleep(Duration::from_secs(10)).await;
        }
    }));

    #[cfg(feature = "revolut")]
    {
        use crate::payments::revolut::RevolutPaymentHandler;

        // Load all Revolut payment configs from database
        let revolut_configs = db
            .list_payment_method_configs()
            .await?
            .into_iter()
            .filter(|c| c.payment_method == PaymentMethod::Revolut && c.enabled)
            .collect::<Vec<_>>();

        for config in revolut_configs {
            info!(
                "Starting Revolut payment handler for config: {}",
                config.name
            );
            match RevolutPaymentHandler::new(
                &config,
                &settings.public_url,
                db.clone(),
                sender.clone(),
            ) {
                Ok(mut handler) => {
                    ret.push(tokio::spawn(async move {
                        loop {
                            if let Err(e) = handler.listen().await {
                                error!("revolut-error: {}", e);
                            }
                            sleep(Duration::from_secs(30)).await;
                        }
                    }));
                }
                Err(e) => {
                    error!(
                        "Failed to create Revolut payment handler for '{}': {}",
                        config.name, e
                    );
                }
            }
        }
    }

    Ok(ret)
}

// =========================================================================
// handle_upgrade (shared utility)
// =========================================================================

pub(crate) async fn handle_upgrade(
    payment: &SubscriptionPayment,
    vm_id: u64,
    tx: &Arc<dyn WorkCommander>,
    _db: Arc<dyn LNVpsDb>,
) -> Result<()> {
    // Parse upgrade parameters from the metadata field
    if let Some(metadata) = &payment.metadata {
        if let Ok(upgrade_params) = serde_json::from_value::<UpgradeConfig>(metadata.clone()) {
            info!(
                "Processing upgrade payment for VM {} with params: CPU={:?}, Memory={:?}, Disk={:?}",
                vm_id,
                upgrade_params.new_cpu,
                upgrade_params.new_memory,
                upgrade_params.new_disk
            );
            tx.send(WorkJob::ProcessVmUpgrade {
                vm_id,
                config: upgrade_params,
            })
            .await?;
        } else {
            warn!(
                "Upgrade payment {} has invalid upgrade parameters in metadata",
                hex::encode(&payment.id)
            );
        }
    } else {
        warn!(
            "Upgrade payment {} missing metadata field",
            hex::encode(&payment.id)
        );
    }
    Ok(())
}
