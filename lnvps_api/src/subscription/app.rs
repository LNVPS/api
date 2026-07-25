//! Subscription-lifecycle adapter for managed-app line items.
//!
//! Managed apps are provisioned out-of-band by `lnvps_operator`, which
//! reconciles a deployment once its subscription is **set up** (paid at least
//! once) and scales it to **0 replicas** when the subscription expires (data
//! retained). So payment and expiry need no synchronous action here — the
//! operator observes subscription state on its own loop.
//!
//! The one lifecycle event that does need action is the grace period being
//! exceeded: we soft-delete the deployment so the operator garbage-collects its
//! namespace and volumes on the next reconcile — mirroring how a VM is deleted
//! after its grace period.

use crate::subscription::SubscriptionLineItemHandler;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_db::{LNVpsDb, Subscription, SubscriptionLineItem, SubscriptionPayment};
use log::info;
use std::sync::Arc;

pub struct AppLineItemHandler {
    db: Arc<dyn LNVpsDb>,
    /// The line item this handler fulfils.
    line_item_id: u64,
}

impl AppLineItemHandler {
    pub fn new(db: Arc<dyn LNVpsDb>, line_item_id: u64) -> Self {
        Self { db, line_item_id }
    }
}

#[async_trait]
impl SubscriptionLineItemHandler for AppLineItemHandler {
    async fn on_payment(&self, _payment: &SubscriptionPayment) -> Result<()> {
        // The subscription is marked set up by `subscription_payment_paid`; the
        // operator provisions the deployment on its next reconcile. Nothing to
        // do synchronously here.
        Ok(())
    }

    async fn on_expired(&self, sub: &Subscription, line_item: &SubscriptionLineItem) -> Result<()> {
        // The operator scales the deployment to 0 replicas on expiry (data
        // retained); no action needed here.
        info!(
            "App line item {} (subscription {}) expired — operator will scale it to 0 (data retained)",
            line_item.id, sub.id
        );
        Ok(())
    }

    async fn on_grace_period_exceeded(
        &self,
        sub: &Subscription,
        line_item: &SubscriptionLineItem,
    ) -> Result<()> {
        // Grace period exhausted: soft-delete the deployment so the operator
        // tears down its namespace + volumes on the next reconcile.
        match self
            .db
            .get_app_deployment_by_line_item(self.line_item_id)
            .await
        {
            Ok(dep) if !dep.deleted => {
                info!(
                    "App deployment {} (line item {}, subscription {}) grace period exceeded — deleting",
                    dep.id, line_item.id, sub.id
                );
                self.db.delete_app_deployment(dep.id).await?;
            }
            Ok(_) => {} // already deleted
            Err(e) => info!(
                "App line item {} grace period exceeded but no deployment found: {}",
                line_item.id, e
            ),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lnvps_api_common::MockDb;
    use lnvps_db::{
        AppDeployment, AppDeploymentDesiredState, AppDeploymentStatus, EncryptedString,
        LNVpsDbBase, PaymentMethod, SubscriptionLineItem, SubscriptionPaymentType,
        SubscriptionType,
    };

    fn payment() -> SubscriptionPayment {
        SubscriptionPayment {
            id: vec![1],
            subscription_id: 1,
            user_id: 1,
            created: Utc::now(),
            expires: Utc::now(),
            amount: 1000,
            currency: "USD".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Purchase,
            external_data: EncryptedString::new(String::new()),
            external_id: None,
            is_paid: true,
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
        }
    }

    fn line_item(id: u64) -> SubscriptionLineItem {
        SubscriptionLineItem {
            id,
            subscription_id: 1,
            subscription_type: SubscriptionType::App,
            name: "app".to_string(),
            description: None,
            amount: 1000,
            setup_amount: 0,
            configuration: None,
        }
    }

    fn subscription() -> Subscription {
        Subscription {
            id: 1,
            user_id: 1,
            company_id: 1,
            name: "app".to_string(),
            description: None,
            created: Utc::now(),
            expires: None,
            is_active: true,
            is_setup: true,
            currency: "USD".to_string(),
            interval_amount: 1,
            interval_type: lnvps_db::IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: false,
            external_id: None,
        }
    }

    async fn seed_deployment(db: &MockDb, line_item_id: u64) -> u64 {
        db.insert_app_deployment(&AppDeployment {
            id: 0,
            user_id: 1,
            app_id: 1,
            cluster_id: 1,
            subscription_line_item_id: line_item_id,
            name: "inst".to_string(),
            namespace: "app-1".to_string(),
            hostname: None,
            custom_domain: None,
            config: None,
            desired_state: AppDeploymentDesiredState::Running,
            status: AppDeploymentStatus::Running,
            status_message: None,
            created: Utc::now(),
            deleted: false,
        })
        .await
        .unwrap()
    }

    /// Payment + expiry are no-ops (the operator handles provisioning/scaling);
    /// they must not touch the deployment.
    #[tokio::test]
    async fn payment_and_expiry_are_noops() {
        let db = std::sync::Arc::new(MockDb::default());
        let id = seed_deployment(&db, 5).await;
        let h = AppLineItemHandler::new(db.clone(), 5);

        h.on_payment(&payment()).await.unwrap();
        h.on_expired(&subscription(), &line_item(5)).await.unwrap();

        assert!(!db.get_app_deployment(id).await.unwrap().deleted);
    }

    /// Grace period exceeded soft-deletes the deployment so the operator GCs it.
    #[tokio::test]
    async fn grace_period_soft_deletes_deployment() {
        let db = std::sync::Arc::new(MockDb::default());
        let id = seed_deployment(&db, 7).await;
        let h = AppLineItemHandler::new(db.clone(), 7);

        h.on_grace_period_exceeded(&subscription(), &line_item(7))
            .await
            .unwrap();

        assert!(db.get_app_deployment(id).await.unwrap().deleted);
    }

    /// A missing deployment (already gone) is tolerated, not an error.
    #[tokio::test]
    async fn grace_period_no_deployment_is_ok() {
        let db = std::sync::Arc::new(MockDb::default());
        let h = AppLineItemHandler::new(db.clone(), 99);
        h.on_grace_period_exceeded(&subscription(), &line_item(99))
            .await
            .unwrap();
    }
}
