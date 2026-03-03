use crate::subscription::SubscriptionLineItemHandler;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_api_common::{UpgradeConfig, VmHistoryLogger, WorkCommander, WorkJob};
use lnvps_db::{LNVpsDb, Subscription, SubscriptionPayment, SubscriptionPaymentType};
use log::{info, warn};
use std::sync::Arc;

pub struct VmLineItemHandler {
    vm_id: u64,
    vm_expires_before: chrono::DateTime<chrono::Utc>,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    vm_history_logger: VmHistoryLogger,
}

impl VmLineItemHandler {
    pub async fn new(
        vm_id: u64,
        db: Arc<dyn LNVpsDb>,
        tx: Arc<dyn WorkCommander>,
    ) -> Result<Self> {
        let vm = db.get_vm(vm_id).await?;
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        Ok(Self {
            vm_id,
            vm_expires_before: vm.expires,
            db,
            tx,
            vm_history_logger,
        })
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for VmLineItemHandler {
    async fn on_payment(&self, payment: &SubscriptionPayment, method_label: &str) -> Result<()> {
        let vm_id = self.vm_id;
        let vm_after = self.db.get_vm(vm_id).await?;

        let payment_metadata = serde_json::json!({
            "payment_id": hex::encode(&payment.id),
            "payment_method": method_label
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
            // Parse upgrade parameters from the metadata field
            if let Some(metadata) = &payment.metadata {
                if let Ok(upgrade_params) =
                    serde_json::from_value::<UpgradeConfig>(metadata.clone())
                {
                    info!(
                        "Processing upgrade payment for VM {} with params: CPU={:?}, Memory={:?}, Disk={:?}",
                        vm_id, upgrade_params.new_cpu, upgrade_params.new_memory, upgrade_params.new_disk
                    );
                    self.tx
                        .send(WorkJob::ProcessVmUpgrade {
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
        } else {
            self.tx.send(WorkJob::CheckVm { vm_id }).await?;
        }

        Ok(())
    }

    async fn on_expiring_soon(&self, sub: &Subscription) -> Result<()> {
        // VM-specific expiry notification (without NWC — NWC is handled at subscription level
        // in the worker before individual line item handlers are called)
        let vm_id = self.vm_id;
        info!("VM {} subscription {} expiring soon", vm_id, sub.id);
        // The notification is sent at subscription level by the worker; nothing extra needed here.
        Ok(())
    }

    async fn on_expired(&self, sub: &Subscription) -> Result<()> {
        // VM stop is handled by handle_vm_state / check_vms (hypervisor-driven).
        // We just dispatch CheckVm so it is picked up promptly.
        let vm_id = self.vm_id;
        info!(
            "VM {} subscription {} expired — dispatching CheckVm",
            vm_id, sub.id
        );
        self.tx.send(WorkJob::CheckVm { vm_id }).await?;
        Ok(())
    }

    async fn on_grace_period_exceeded(&self, sub: &Subscription) -> Result<()> {
        // VM deletion is handled by handle_vm_state / check_vms.
        // Dispatch CheckVm so it is picked up promptly.
        let vm_id = self.vm_id;
        info!(
            "VM {} subscription {} grace period exceeded — dispatching CheckVm",
            vm_id, sub.id
        );
        self.tx.send(WorkJob::CheckVm { vm_id }).await?;
        Ok(())
    }
}
