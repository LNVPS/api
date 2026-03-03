//! Generic subscription line-item lifecycle management.
//!
//! Every product type (VM, IP range, ASN sponsoring, DNS hosting, …) implements
//! [`SubscriptionLineItemHandler`].  Both the payment pipeline and the lifecycle
//! worker call into this single trait, so adding a new product means implementing
//! the trait once in one place.
//!
//! # Usage
//!
//! Build a handler for a specific line item with [`line_item_handler`].
//! The payment pipeline calls [`SubscriptionLineItemHandler::on_payment`].
//! The lifecycle worker calls [`SubscriptionLineItemHandler::on_expiring_soon`],
//! [`SubscriptionLineItemHandler::on_expired`], and
//! [`SubscriptionLineItemHandler::on_grace_period_exceeded`].

use anyhow::Result;
use async_trait::async_trait;
use lnvps_api_common::WorkCommander;
use lnvps_db::{LNVpsDb, Subscription, SubscriptionLineItem, SubscriptionPayment, SubscriptionType};
use std::sync::Arc;

mod vm;
mod ip_range;

pub use vm::VmLineItemHandler;
pub use ip_range::IpRangeLineItemHandler;

// =========================================================================
// Trait
// =========================================================================

/// Manages the full lifecycle of a single subscription line item.
#[async_trait]
pub trait SubscriptionLineItemHandler: Send + Sync {
    /// Called after `subscription_payment_paid()` has marked the payment as
    /// paid in the DB and extended `subscription.expires`.
    async fn on_payment(
        &self,
        payment: &SubscriptionPayment,
        method_label: &str,
    ) -> Result<()>;

    /// Called when `subscription.expires` is within the warning window.
    async fn on_expiring_soon(&self, sub: &Subscription) -> Result<()>;

    /// Called when `subscription.expires` has passed.
    async fn on_expired(&self, sub: &Subscription) -> Result<()>;

    /// Called when `subscription.expires + delete_after` has passed.
    async fn on_grace_period_exceeded(&self, sub: &Subscription) -> Result<()>;
}

// =========================================================================
// Factory
// =========================================================================

/// Build the appropriate [`SubscriptionLineItemHandler`] for the given line item.
pub async fn line_item_handler(
    li: &SubscriptionLineItem,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
) -> Result<Box<dyn SubscriptionLineItemHandler>> {
    match li.subscription_type {
        SubscriptionType::VmRenewal | SubscriptionType::VmUpgrade => {
            let vm = db.get_vm_by_subscription_line_item(li.id).await?;
            Ok(Box::new(VmLineItemHandler::new(vm.id, db, tx).await?))
        }
        SubscriptionType::IpRange => {
            Ok(Box::new(IpRangeLineItemHandler::new(li.id, db, tx)))
        }
        SubscriptionType::AsnSponsoring | SubscriptionType::DnsHosting => {
            // Not yet implemented — use the generic fallback that only dispatches
            // CheckSubscriptions so expiry is acknowledged by the lifecycle worker.
            Ok(Box::new(IpRangeLineItemHandler::new(li.id, db, tx)))
        }
    }
}
