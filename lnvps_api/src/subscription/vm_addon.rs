use crate::subscription::SubscriptionLineItemHandler;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_db::{Subscription, SubscriptionLineItem, SubscriptionPayment};

pub struct VmAddonLineItemHandler;

#[async_trait]
impl SubscriptionLineItemHandler for VmAddonLineItemHandler {
    async fn on_payment(&self, _payment: &SubscriptionPayment) -> Result<()> {
        Ok(())
    }

    async fn on_expired(
        &self,
        _sub: &Subscription,
        _line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        Ok(())
    }

    async fn on_grace_period_exceeded(
        &self,
        _sub: &Subscription,
        _line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        Ok(())
    }
}
