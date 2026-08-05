//! The one-off fee that lets a marketplace node be approved.
//!
//! Unlike every other line item handler this provisions nothing. The fee buys
//! review and a listing, not a resource: paying it makes the node *eligible* for
//! approval, and an admin still has to approve it. That is the whole point of
//! charging at approval rather than at registration — hardware is vetted before
//! money changes hands, and hardware that fails review costs its operator
//! nothing.
//!
//! The expiry callbacks are unreachable rather than unimplemented. A fee
//! subscription bills nothing recurring, and `subscription_payment_paid` leaves
//! such a subscription's `expires` as NULL, which every expiry query filters on
//! (`WHERE ... expires IS NOT NULL`). Reaching them means that invariant broke,
//! so they say so loudly instead of quietly deactivating a node whose operator
//! paid in full.

use crate::subscription::SubscriptionLineItemHandler;
use anyhow::{Result, bail};
use async_trait::async_trait;
use lnvps_db::{Subscription, SubscriptionLineItem, SubscriptionPayment};
use log::info;

pub struct MarketplaceNodeFeeLineItemHandler {
    /// The line item this handler fulfils.
    line_item_id: u64,
}

impl MarketplaceNodeFeeLineItemHandler {
    pub fn new(line_item_id: u64) -> Self {
        Self { line_item_id }
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for MarketplaceNodeFeeLineItemHandler {
    async fn on_payment(&self, _payment: &SubscriptionPayment) -> Result<()> {
        // Nothing to provision. The node becomes approvable because the gate
        // reads the payment state directly, so there is no flag to flip here
        // that could disagree with what was actually paid.
        info!(
            "Marketplace node listing fee paid for line item {}",
            self.line_item_id
        );
        Ok(())
    }

    async fn on_expired(&self, sub: &Subscription, line_item: &SubscriptionLineItem) -> Result<()> {
        bail!(
            "Marketplace node fee subscription {} (line item {}) expired, but a one-off fee must \
             never acquire an expiry — check the one-off branch in subscription_payment_paid",
            sub.id,
            line_item.id
        )
    }

    async fn on_grace_period_exceeded(
        &self,
        sub: &Subscription,
        line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        bail!(
            "Marketplace node fee subscription {} (line item {}) exceeded a grace period it should \
             never have had — check the one-off branch in subscription_payment_paid",
            sub.id,
            line_item.id
        )
    }
}
