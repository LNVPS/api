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

use crate::subscription::{AppUpgradeConfig, SubscriptionLineItemHandler};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use lnvps_db::{
    LNVpsDb, Subscription, SubscriptionLineItem, SubscriptionPayment, SubscriptionPaymentType,
};
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
    async fn on_payment(&self, payment: &SubscriptionPayment) -> Result<()> {
        // A settled upgrade payment is the point at which a resize becomes
        // real: apply the paid-for multiplier to the deployment and reprice the
        // line item, so the operator scales the workload on its next reconcile
        // and future renewals bill at the new size. Doing this only on payment
        // means an abandoned upgrade never changes anything.
        if payment.payment_type == SubscriptionPaymentType::Upgrade {
            // Every app upgrade payment is created by
            // `create_app_upgrade_payment`, which always serializes an
            // `AppUpgradeConfig` into the metadata. Missing or malformed
            // metadata therefore means the payment record is corrupt — and the
            // customer has already been charged. Fail loudly: swallowing it
            // would leave them paid up at the old size with nothing but an
            // info-level log to show for it.
            let metadata = payment.metadata.clone().ok_or_else(|| {
                anyhow!(
                    "app upgrade payment {} (line item {}) has no metadata; cannot tell what size was paid for",
                    hex::encode(&payment.id),
                    self.line_item_id
                )
            })?;
            let cfg: AppUpgradeConfig =
                serde_json::from_value(metadata.clone()).with_context(|| {
                    format!(
                        "app upgrade payment {} (line item {}) has unreadable metadata: {metadata}",
                        hex::encode(&payment.id),
                        self.line_item_id
                    )
                })?;

            let mut dep = self
                .db
                .get_app_deployment_by_line_item(self.line_item_id)
                .await?;
            // Increase-only, re-checked here: a replayed or out-of-order
            // payment must never shrink a deployment (PVCs cannot shrink).
            if cfg.new_multiplier > dep.resource_multiplier.max(1) {
                let app = self.db.get_app(dep.app_id).await?;
                info!(
                    "App deployment {} upgraded {}x -> {}x (line item {})",
                    dep.id,
                    dep.resource_multiplier.max(1),
                    cfg.new_multiplier,
                    self.line_item_id
                );
                dep.resource_multiplier = cfg.new_multiplier;
                self.db.update_app_deployment(&dep).await?;

                // Reprice the line item so renewals charge the new size.
                let mut li = self
                    .db
                    .get_subscription_line_item(self.line_item_id)
                    .await?;
                li.amount = app.amount * cfg.new_multiplier as u64;
                self.db.update_subscription_line_item(&li).await?;
            }
            return Ok(());
        }

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
            refunded_payment_id: None,
        }
    }

    fn mock_app(amount: u64) -> lnvps_db::App {
        lnvps_db::App {
            id: 1,
            name: "relay".to_string(),
            display_name: "Relay".to_string(),
            description: None,
            icon: None,
            repo_url: None,
            category: "Nostr relay".to_string(),
            seo_title: None,
            seo_description: None,
            compose: String::new(),
            amount,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: lnvps_db::IntervalType::Month,
            setup_amount: 0,
            enabled: true,
            cpu_milli: 500,
            memory_bytes: 1024,
            storage_bytes: 4096,
            created: Utc::now(),
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
            resource_multiplier: 1,
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

    /// A settled upgrade payment applies the paid-for multiplier and reprices
    /// the line item so renewals bill at the new size.
    #[tokio::test]
    async fn upgrade_payment_applies_multiplier_and_reprices() {
        let db = std::sync::Arc::new(MockDb::default());
        let id = seed_deployment(&db, 11).await;
        {
            // Catalog app priced at 1000/base-unit.
            let mut apps = db.apps.lock().await;
            apps.insert(1, mock_app(1000));
            let mut items = db.subscription_line_items.lock().await;
            items.insert(11, line_item(11));
        }
        let h = AppLineItemHandler::new(db.clone(), 11);

        let mut p = payment();
        p.payment_type = SubscriptionPaymentType::Upgrade;
        p.metadata = Some(serde_json::json!({ "new_multiplier": 4 }));
        h.on_payment(&p).await.unwrap();

        assert_eq!(
            db.get_app_deployment(id).await.unwrap().resource_multiplier,
            4
        );
        assert_eq!(
            db.get_subscription_line_item(11).await.unwrap().amount,
            4000,
            "line item repriced to app.amount x multiplier"
        );
    }

    /// An upgrade payment must never shrink a deployment: PVCs cannot shrink,
    /// so a replayed or out-of-order payment carrying a smaller multiplier is
    /// ignored rather than applied.
    #[tokio::test]
    async fn upgrade_payment_never_shrinks_deployment() {
        let db = std::sync::Arc::new(MockDb::default());
        let id = seed_deployment(&db, 12).await;
        {
            let mut deps = db.app_deployments.lock().await;
            deps.get_mut(&id).unwrap().resource_multiplier = 8;
            let mut apps = db.apps.lock().await;
            apps.insert(1, mock_app(1000));
            let mut items = db.subscription_line_items.lock().await;
            items.insert(12, line_item(12));
        }
        let h = AppLineItemHandler::new(db.clone(), 12);

        let mut p = payment();
        p.payment_type = SubscriptionPaymentType::Upgrade;
        p.metadata = Some(serde_json::json!({ "new_multiplier": 2 }));
        h.on_payment(&p).await.unwrap();

        assert_eq!(
            db.get_app_deployment(id).await.unwrap().resource_multiplier,
            8,
            "a smaller multiplier must be ignored"
        );
        assert_eq!(
            db.get_subscription_line_item(12).await.unwrap().amount,
            1000,
            "price must not change either"
        );
    }

    /// An upgrade payment always carries an `AppUpgradeConfig` (written by
    /// `create_app_upgrade_payment`), so missing or malformed metadata means the
    /// record is corrupt *and the customer has already paid*. That must surface
    /// as an error rather than silently leaving them at the old size.
    #[tokio::test]
    async fn upgrade_payment_with_unusable_metadata_errors() {
        let db = std::sync::Arc::new(MockDb::default());
        let id = seed_deployment(&db, 13).await;
        let h = AppLineItemHandler::new(db.clone(), 13);

        // No metadata at all.
        let mut p = payment();
        p.payment_type = SubscriptionPaymentType::Upgrade;
        p.metadata = None;
        let err = h
            .on_payment(&p)
            .await
            .expect_err("missing metadata must error");
        assert!(err.to_string().contains("no metadata"), "{err}");

        // Present, but not an AppUpgradeConfig (e.g. a VM UpgradeConfig).
        p.metadata = Some(serde_json::json!({ "new_cpu": 4 }));
        let err = h
            .on_payment(&p)
            .await
            .expect_err("unreadable metadata must error");
        assert!(err.to_string().contains("unreadable metadata"), "{err}");

        // Either way the deployment is untouched.
        assert_eq!(
            db.get_app_deployment(id).await.unwrap().resource_multiplier,
            1
        );
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
