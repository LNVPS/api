use crate::payments::complete_payment;
use anyhow::{Context, Result};
use lnvps_api_common::WorkCommander;
use lnvps_db::{LNVpsDb, PaymentMethod, PaymentMethodConfig, ProviderConfig, SubscriptionPaymentType};
use log::{error, info, warn};
use payments_rs::fiat::{StripeApi, StripeConfig, StripeWebhookEvent};
use payments_rs::webhook::WEBHOOK_BRIDGE;
use std::sync::Arc;

pub struct StripePaymentHandler {
    api: StripeApi,
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,
    config_id: u64,
}

impl StripePaymentHandler {
    pub fn new(
        config: &PaymentMethodConfig,
        db: Arc<dyn LNVpsDb>,
        sender: Arc<dyn WorkCommander>,
    ) -> Result<Self> {
        let provider_config = config
            .get_provider_config()
            .context("Failed to parse provider config")?;

        let stripe_config = provider_config
            .as_stripe()
            .context("Config is not a Stripe provider")?;

        let api = StripeApi::new(StripeConfig {
            url: None,
            api_key: stripe_config.secret_key.clone(),
            webhook_secret: Some(stripe_config.webhook_secret.clone()),
        })?;

        Ok(Self {
            api,
            config_id: config.id,
            db,
            tx: sender,
        })
    }

    async fn try_complete_payment(&self, ext_id: &str) -> Result<()> {
        let payment = self
            .db
            .get_subscription_payment_by_ext_id(ext_id)
            .await?;

        let db = self.db.clone();
        let api = self.api.clone();
        let tx = self.tx.clone();
        let payment_id = payment.id.clone();

        complete_payment(&self.db, &payment, tx, "stripe", |paid_payment| {
            let db = db.clone();
            let api = api.clone();
            async move {
                // Cancel other pending Stripe upgrade payment intents for this subscription
                let vm = db.get_vm_by_subscription(paid_payment.subscription_id).await?;
                let other_upgrades = db
                    .list_pending_vm_subscription_payments(vm.id)
                    .await?
                    .into_iter()
                    .filter(|p| {
                        p.payment_type == SubscriptionPaymentType::Upgrade
                            && p.payment_method == PaymentMethod::Stripe
                            && p.id != payment_id
                    })
                    .collect::<Vec<_>>();

                for ugp in other_upgrades {
                    let hex_id = hex::encode(&ugp.id);
                    if let Some(eid) = ugp.external_id.as_ref() {
                        if let Err(e) = api.cancel_payment_intent(eid).await {
                            warn!("Failed to cancel Stripe payment intent {}: {}", hex_id, e);
                        }
                    } else {
                        warn!("External id does not exist on Stripe payment: {}", hex_id);
                    }
                    let mut expired = ugp;
                    expired.expires = chrono::Utc::now();
                    if let Err(e) = db.update_subscription_payment(&expired).await {
                        warn!("Failed to update payment {}: {}", hex_id, e);
                    }
                }
                Ok(())
            }
        })
        .await?;

        info!(
            "Subscription payment {} paid via Stripe",
            hex::encode(&payment.id)
        );
        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        let webhook_secret = self
            .api
            .webhook_secret()
            .context("Stripe webhook secret not configured")?
            .to_string();

        let mut rx = WEBHOOK_BRIDGE.listen();

        info!("Stripe payment handler listening for webhook events");

        while let Ok(msg) = rx.recv().await {
            if !msg.endpoint.contains("stripe") {
                continue;
            }

            let event = match StripeWebhookEvent::verify(&webhook_secret, &msg) {
                Ok(e) => e,
                Err(e) => {
                    warn!("Failed to verify Stripe webhook signature: {}", e);
                    continue;
                }
            };

            // Handle payment_intent.succeeded — look up our payment by external_id
            if event.event_type == "payment_intent.succeeded" {
                let ext_id: Option<String> = event
                    .data
                    .object
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned());
                if let Some(ext_id) = ext_id {
                    if let Err(e) = self.try_complete_payment(&ext_id).await {
                        error!("Stripe payment completion failed for {}: {}", ext_id, e);
                    }
                }
            }
        }

        Ok(())
    }
}
