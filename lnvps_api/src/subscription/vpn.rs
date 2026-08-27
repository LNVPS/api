//! A consumer VPN plan's billing lifecycle.
//!
//! There is almost nothing here, and that is the design rather than an
//! omission. Whether a customer's devices are configured on a route server is
//! derived from their billing state at reconcile time (`list_active_vpn_devices`
//! joins through the line item to the subscription), so paying, lapsing and
//! being cancelled require no state change of their own. A handler that flipped
//! an `enabled` flag here would be a second copy of the answer, free to
//! disagree with the first, and a customer who paid at 3am while the worker was
//! down would stay cut off until somebody noticed.
//!
//! What the events *are* good for is promptness. The peer set is only pushed to
//! a route server when something asks, so each event queues a reconcile of the
//! interfaces terminating this plan's service. Miss one and the customer waits
//! for the next scheduled poll instead of being wrong forever.
//!
//! Devices are never deleted here, including when a grace period runs out. The
//! plan row is reused if the customer comes back, and keeping their keys and
//! addresses means paying again is all it takes to be working, with no configs
//! to redistribute.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use chrono::Utc;
use lnvps_api_common::{WorkCommander, WorkJob};
use lnvps_db::{
    LNVpsDb, LineItemType, Subscription, SubscriptionLineItem, SubscriptionPayment, VpnService,
    VpnSubscription,
};
use log::{info, warn};

use crate::subscription::SubscriptionLineItemHandler;

/// Start, or restart, a customer's VPN plan on `service`.
///
/// A customer has at most one plan, so this is idempotent while theirs is live:
/// asking again returns what they already have rather than selling a second
/// one. A plan that has lapsed is *repointed* at a fresh subscription instead of
/// being replaced, so the customer's devices keep their keys and addresses and
/// paying is all it takes to be working again.
///
/// The plan is created unpaid. `is_setup` stays false until the subscription is
/// paid through the ordinary flow, and the planner only configures devices on a
/// paid plan, so nothing reaches a route server before the money does.
pub async fn create_vpn_plan(
    db: &Arc<dyn LNVpsDb>,
    user_id: u64,
    service: &VpnService,
) -> Result<VpnSubscription> {
    if !service.enabled {
        return Err(anyhow!("VPN service {} is not selling", service.name));
    }

    let existing = db.get_vpn_subscription_for_user(user_id).await?;
    if let Some(plan) = &existing {
        let sub = db
            .get_subscription_by_line_item_id(plan.subscription_line_item_id)
            .await?;
        if sub.billing_state(Utc::now()) != lnvps_db::BillingState::Expired {
            // Live, or awaiting its first payment. Either way there is nothing
            // to sell them: pay the subscription they already have.
            return Ok(plan.clone());
        }
    }

    let (_, line_items) = db
        .insert_subscription_with_line_items(
            &Subscription {
                id: 0,
                user_id,
                company_id: service.company_id,
                name: format!("{} VPN", service.name),
                description: None,
                created: Utc::now(),
                expires: None,
                is_active: true,
                is_setup: false,
                currency: service.currency.clone(),
                interval_amount: service.interval_amount,
                interval_type: service.interval_type,
                setup_fee: service.setup_amount,
                auto_renewal_enabled: true,
                external_id: None,
            },
            vec![SubscriptionLineItem {
                id: 0,
                subscription_id: 0,
                subscription_type: LineItemType::Vpn,
                name: format!("{} VPN", service.name),
                description: None,
                amount: service.amount,
                setup_amount: service.setup_amount,
                configuration: None,
            }],
        )
        .await?;
    let line_item_id = line_items[0];

    let id = match existing {
        // A returning customer keeps their row, and with it every device they
        // registered. Only which line item bills them changes.
        Some(plan) => {
            db.update_vpn_subscription(&VpnSubscription {
                subscription_line_item_id: line_item_id,
                ..plan.clone()
            })
            .await?;
            plan.id
        }
        None => {
            db.insert_vpn_subscription(&VpnSubscription {
                id: 0,
                vpn_service_id: service.id,
                user_id,
                subscription_line_item_id: line_item_id,
                device_limit: service.default_device_limit,
                created: Utc::now(),
            })
            .await?
        }
    };

    Ok(db.get_vpn_subscription(id).await?)
}

pub struct VpnLineItemHandler {
    db: Arc<dyn LNVpsDb>,
    line_item_id: u64,
    tx: Arc<dyn WorkCommander>,
}

impl VpnLineItemHandler {
    pub fn new(db: Arc<dyn LNVpsDb>, line_item_id: u64, tx: Arc<dyn WorkCommander>) -> Self {
        Self {
            db,
            line_item_id,
            tx,
        }
    }

    /// Push the service's interfaces, so the change lands now rather than at
    /// the next scheduled poll.
    ///
    /// Every billing event does exactly this, because every billing event
    /// changes the same thing: whether this plan's devices are in the peer set
    /// the planner computes.
    ///
    /// Failing to queue is logged, not returned. The reconcile is an
    /// optimisation over the poll that would have happened anyway, and failing
    /// the payment callback over it would leave a customer charged and their
    /// subscription not marked paid.
    async fn reconcile_service(&self) -> Result<()> {
        let plan = self
            .db
            .get_vpn_subscription_by_line_item(self.line_item_id)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "Line item {} is a VPN plan with no vpn_subscription row",
                    self.line_item_id
                )
            })?;

        for pool in self.db.list_vpn_service_pools(plan.vpn_service_id).await? {
            if let Err(e) = self
                .tx
                .send(WorkJob::ReconcileTunnelPeers { pool_id: pool.id })
                .await
            {
                warn!(
                    "Could not queue a reconcile of tunnel pool {} for VPN plan {}: {e}",
                    pool.id, plan.id
                );
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for VpnLineItemHandler {
    async fn on_payment(&self, _payment: &SubscriptionPayment) -> Result<()> {
        info!("VPN plan paid for line item {}", self.line_item_id);
        self.reconcile_service().await
    }

    async fn on_expired(
        &self,
        sub: &Subscription,
        _line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        info!(
            "VPN subscription {} expired; its devices leave the peer set on reconcile",
            sub.id
        );
        self.reconcile_service().await
    }

    async fn on_grace_period_exceeded(
        &self,
        sub: &Subscription,
        _line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        // Deliberately does not delete the devices. The plan row is reused if
        // this customer comes back, and their keys and addresses surviving is
        // what makes returning a payment rather than a re-setup.
        info!(
            "VPN subscription {} passed its grace period; devices are kept for a return",
            sub.id
        );
        self.reconcile_service().await
    }
}

#[cfg(test)]
mod tests;
