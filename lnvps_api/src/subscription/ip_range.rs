//! Subscription-lifecycle adapter for IP-range line items.
//!
//! Thin glue that maps the [`SubscriptionLineItemHandler`] lifecycle onto the
//! [`IpRangeProvisioner`] domain layer (mirroring how [`super::VmLineItemHandler`]
//! delegates to [`crate::provisioner::VmProvisioner`]). All allocation and LIR
//! registry logic lives in the provisioner.

use crate::provisioner::IpRangeProvisioner;
use crate::subscription::SubscriptionLineItemHandler;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_db::{Subscription, SubscriptionLineItem, SubscriptionPayment};
use log::info;

pub struct IpRangeLineItemHandler {
    provisioner: IpRangeProvisioner,
    /// The line item this handler fulfils.
    line_item_id: u64,
}

impl IpRangeLineItemHandler {
    pub fn new(provisioner: IpRangeProvisioner, line_item_id: u64) -> Self {
        Self {
            provisioner,
            line_item_id,
        }
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for IpRangeLineItemHandler {
    async fn on_payment(&self, payment: &SubscriptionPayment) -> Result<()> {
        self.provisioner
            .allocate_on_payment(self.line_item_id, payment)
            .await
    }

    async fn on_expired(&self, sub: &Subscription, line_item: &SubscriptionLineItem) -> Result<()> {
        info!(
            "IP range line item {} subscription {} expired — deactivating allocation",
            line_item.id, sub.id
        );
        self.provisioner.deactivate_line_item(line_item).await
    }

    async fn on_grace_period_exceeded(
        &self,
        sub: &Subscription,
        line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        info!(
            "IP range line item {} subscription {} grace period exceeded",
            line_item.id, sub.id
        );
        // Nothing more to do — allocation was already deactivated on_expired.
        Ok(())
    }
}
