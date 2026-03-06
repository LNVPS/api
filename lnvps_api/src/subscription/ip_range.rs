use crate::subscription::SubscriptionLineItemHandler;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_api_common::{WorkCommander, WorkJob};
use lnvps_db::{LNVpsDb, Subscription, SubscriptionPayment};
use log::info;
use std::sync::Arc;

pub struct IpRangeLineItemHandler {
    line_item_id: u64,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
}

impl IpRangeLineItemHandler {
    pub fn new(line_item_id: u64, db: Arc<dyn LNVpsDb>, tx: Arc<dyn WorkCommander>) -> Self {
        Self {
            line_item_id,
            db,
            tx,
        }
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for IpRangeLineItemHandler {
    async fn on_payment(&self, _payment: &SubscriptionPayment, _method_label: &str) -> Result<()> {
        // Trigger the lifecycle worker to pick up the new expiry and activate the allocation
        self.tx.send(WorkJob::CheckSubscriptions).await?;
        Ok(())
    }

    async fn on_expiring_soon(&self, sub: &Subscription) -> Result<()> {
        // Expiry notification is sent at subscription level by the worker.
        info!(
            "IP range line item {} subscription {} expiring soon",
            self.line_item_id, sub.id
        );
        Ok(())
    }

    async fn on_expired(&self, sub: &Subscription) -> Result<()> {
        // Deactivate the ip_range_subscription row(s) linked to this line item
        info!(
            "IP range line item {} subscription {} expired — deactivating allocation",
            self.line_item_id, sub.id
        );
        let ip_subs = self
            .db
            .list_ip_range_subscriptions_by_line_item(self.line_item_id)
            .await?;
        for mut ips in ip_subs {
            if ips.is_active {
                ips.is_active = false;
                ips.ended_at = Some(chrono::Utc::now());
                if let Err(e) = self.db.update_ip_range_subscription(&ips).await {
                    log::warn!(
                        "Failed to deactivate ip_range_subscription {}: {}",
                        ips.id,
                        e
                    );
                }
            }
        }
        Ok(())
    }

    async fn on_grace_period_exceeded(&self, sub: &Subscription) -> Result<()> {
        info!(
            "IP range line item {} subscription {} grace period exceeded",
            self.line_item_id, sub.id
        );
        // Nothing more to do — allocation was already deactivated on_expired.
        Ok(())
    }
}
