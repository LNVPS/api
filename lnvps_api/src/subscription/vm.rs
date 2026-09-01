use crate::provisioner::VmProvisioner;
use crate::subscription::SubscriptionLineItemHandler;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use lnvps_api_common::{
    UpgradeConfig, VmHistoryLogger, VmRunningState, VmRunningStates, VmStateCache, WorkCommander,
    WorkJob,
};
use lnvps_db::{
    LNVpsDb, LineItemType, Subscription, SubscriptionLineItem, SubscriptionPayment,
    SubscriptionPaymentType, Vm, VmHistoryActionType,
};
use log::{error, info, warn};
use std::sync::Arc;

pub struct VmLineItemHandler {
    vm: Vm,
    vm_expires_before: chrono::DateTime<chrono::Utc>,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    vm_history_logger: VmHistoryLogger,
    provisioner: VmProvisioner,
    vm_state_cache: VmStateCache,
}

impl VmLineItemHandler {
    pub async fn new(
        vm_id: u64,
        db: Arc<dyn LNVpsDb>,
        tx: Arc<dyn WorkCommander>,
        provisioner: VmProvisioner,
        vm_state_cache: VmStateCache,
    ) -> Result<Self> {
        let vm = db.get_vm(vm_id).await?;
        let vm_expires_before = db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await
            .ok()
            .and_then(|s| s.expires)
            .unwrap_or_else(chrono::Utc::now);
        let vm_history_logger = VmHistoryLogger::new(db.clone());
        Ok(Self {
            vm,
            vm_expires_before,
            db,
            tx,
            vm_history_logger,
            provisioner,
            vm_state_cache,
        })
    }

    async fn queue_notification(&self, user_id: u64, message: String, title: Option<String>) {
        if let Err(e) = self
            .tx
            .send(WorkJob::SendNotification {
                user_id,
                message,
                title,
            })
            .await
        {
            error!("Failed to queue notification: {}", e);
        }
    }

    /// Whether a `PaymentReceived` row for this payment already exists.
    ///
    /// The on-payment handling can run more than once for a single payment (an
    /// admin re-dispatch, or a redelivered work job), but one payment must
    /// appear in the audit trail once. On a read failure this reports false:
    /// a duplicated row is a smaller loss than a missing one.
    async fn payment_already_recorded(&self, vm_id: u64, payment_id: &str) -> bool {
        match self.db.list_vm_history(vm_id).await {
            Ok(history) => history.iter().any(|h| {
                matches!(h.action_type, VmHistoryActionType::PaymentReceived)
                    && h.metadata
                        .as_ref()
                        .and_then(|m| serde_json::from_slice::<serde_json::Value>(m).ok())
                        .and_then(|v| {
                            v.get("payment_id")
                                .and_then(|p| p.as_str())
                                .map(|p| p == payment_id)
                        })
                        .unwrap_or(false)
            }),
            Err(e) => {
                warn!("Failed to read history for VM {}: {}", vm_id, e);
                false
            }
        }
    }

    async fn queue_admin_notification(&self, message: String, title: Option<String>) {
        if let Err(e) = self
            .tx
            .send(WorkJob::SendAdminNotification { message, title })
            .await
        {
            warn!("Failed to send admin notification: {}", e);
        }
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for VmLineItemHandler {
    async fn on_payment(&self, payment: &SubscriptionPayment) -> Result<()> {
        let vm_id = self.vm.id;
        let vm = self.db.get_vm(vm_id).await?;
        // Get new expiry from subscription (authoritative source)
        let vm_expires_after = self
            .db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await
            .ok()
            .and_then(|s| s.expires)
            .unwrap_or_else(chrono::Utc::now);

        let payment_hex = hex::encode(&payment.id);
        let already_recorded = self.payment_already_recorded(vm_id, &payment_hex).await;

        let payment_metadata = serde_json::json!({
            "payment_id": payment_hex,
            "payment_method": payment.payment_method.to_string()
        });

        if !already_recorded {
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
        }

        let time_value = payment.time_value.unwrap_or(0);
        if time_value > 0 && !already_recorded {
            if let Err(e) = self
                .vm_history_logger
                .log_vm_renewed(
                    vm_id,
                    None,
                    self.vm_expires_before,
                    vm_expires_after,
                    Some(payment.amount + payment.tax + payment.processing_fee),
                    Some(&payment.currency),
                    Some(serde_json::json!({
                        "time_added_seconds": time_value,
                        "payment_id": payment_hex
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
                        vm_id,
                        upgrade_params.new_cpu,
                        upgrade_params.new_memory,
                        upgrade_params.new_disk
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
            // For the very first payment on a VM (mac_address == ff:ff:ff:ff:ff:ff),
            // immediately set the cache state to Creating so the UI can show a
            // meaningful "creating" status while the provisioner runs.
            let vm = self.db.get_vm(vm_id).await?;
            if vm.mac_address == "ff:ff:ff:ff:ff:ff" {
                if let Err(e) = self
                    .vm_state_cache
                    .set_state(
                        vm_id,
                        VmRunningState {
                            state: VmRunningStates::Creating,
                            ..Default::default()
                        },
                    )
                    .await
                {
                    warn!("Failed to set Creating state for VM {}: {}", vm_id, e);
                }
            }
            // Always queue SpawnVm for non-upgrade payments. The worker checks
            // whether the VM has ever been provisioned (via mac_address) and
            // falls back to CheckVm if it already exists on the host. This is
            // safe against multiple concurrent payments of any type: the
            // mac_address guard makes SpawnVm idempotent.
            self.tx.send(WorkJob::SpawnVm { vm_id }).await?;
        }

        Ok(())
    }

    async fn on_expired(&self, sub: &Subscription, line_item: &SubscriptionLineItem) -> Result<()> {
        // skip anything that isn't the vm line item (skip upgrade lines)
        if line_item.subscription_type != LineItemType::Vps {
            return Ok(());
        }
        let grace_days = crate::worker::grace_period_days_for_sub(
            sub,
            Utc::now(),
            self.provisioner.delete_after,
        );
        info!("Stopping expired VM {}", self.vm.id);
        // Stop is best-effort (the host may be unreachable or the VM already
        // stopped), but the history entry must always be written: it is the
        // idempotency marker the worker uses to avoid re-firing expiry handling.
        if let Err(e) = self.provisioner.stop_vm(self.vm.id).await {
            warn!("Failed to stop VM {}: {}", self.vm.id, e);
        }
        if let Err(e) = self
            .vm_history_logger
            .log_vm_expired(self.vm.id, None)
            .await
        {
            warn!("Failed to log VM {} expiration: {}", self.vm.id, e);
        }
        self.queue_notification(
            self.vm.user_id,
            format!(
                "Your VM #{} has expired and has been stopped.\n\nPlease renew your subscription within {} day(s) to restore access. If not renewed, the VM and all its data will be permanently deleted.",
                self.vm.id, grace_days
            ),
            Some(format!("[VM{}] Expired", self.vm.id)),
        ).await;
        Ok(())
    }

    async fn on_grace_period_exceeded(
        &self,
        sub: &Subscription,
        line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        // skip anything that isn't the vm line item (skip upgrade lines)
        if line_item.subscription_type != LineItemType::Vps {
            return Ok(());
        }
        let vm_id = self.vm.id;
        info!("VM {} subscription {} grace period exceeded", vm_id, sub.id);
        if self.vm.deleted {
            return Ok(());
        }

        // An on-chain renewal deposit may still be confirming (issue #194's
        // deletion guard only covers never-paid VMs). If a payment for this
        // VM has a mempool sighting (`external_id` holds the deposit outpoint)
        // but is not yet settled, defer deletion so the confirmation can land.
        let now = Utc::now();
        if self
            .db
            .list_vm_subscription_payments(vm_id)
            .await
            .map(|ps| {
                ps.iter()
                    .any(|p| crate::worker::payment_blocks_unpaid_deletion(p, now))
            })
            .unwrap_or(false)
        {
            info!(
                "VM {} has an on-chain deposit still confirming, deferring deletion",
                vm_id
            );
            return Ok(());
        }

        if let Err(e) = self.provisioner.delete_vm(vm_id, false).await {
            warn!("Failed to delete expired VM {}: {}", vm_id, e);
        } else {
            if let Err(e) = self
                .vm_history_logger
                .log_vm_deleted(vm_id, None, Some("expired and exceeded grace period"), None)
                .await
            {
                warn!("Failed to log VM {} deletion: {}", vm_id, e);
            }
        }
        let title = Some(format!("[VM{}] Deleted", self.vm.id));
        self.queue_admin_notification(
            format!(
                "VM #{} has been permanently deleted after exceeding the grace period without renewal.\nUser ID: {}",
                self.vm.id, self.vm.user_id
            ),
            title,
        )
        .await;
        Ok(())
    }
}
