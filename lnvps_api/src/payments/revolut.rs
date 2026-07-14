use crate::subscription::SubscriptionHandler;
use anyhow::{Context, Result};
use chrono::Utc;
use isocountry::CountryCode;
use lnvps_db::{
    LNVpsDb, PaymentMethodConfig, ProviderConfig, SubscriptionPaymentType, UserPaymentMethod,
};
use log::{error, info, warn};
use payments_rs::fiat::{
    RevolutApi, RevolutConfig, RevolutOrderState, RevolutWebhookBody, RevolutWebhookEvent,
};
use payments_rs::webhook::WEBHOOK_BRIDGE;
use reqwest::Url;
use std::sync::Arc;

pub struct RevolutPaymentHandler {
    api: RevolutApi,
    db: Arc<dyn LNVpsDb>,
    subscription_handler: SubscriptionHandler,
    public_url: String,
    config_id: u64,
}

impl RevolutPaymentHandler {
    pub fn new(
        config: &PaymentMethodConfig,
        public_url: &str,
        db: Arc<dyn LNVpsDb>,
        subscription_handler: SubscriptionHandler,
    ) -> Result<Self> {
        let provider_config = config
            .get_provider_config()
            .context("Failed to parse provider config")?;

        let revolut_config = provider_config
            .as_revolut()
            .context("Config is not a Revolut provider")?;

        let api = RevolutApi::new(RevolutConfig {
            url: Some(revolut_config.url.clone()),
            token: revolut_config.token.clone(),
            api_version: revolut_config.api_version.clone(),
            public_key: revolut_config.public_key.clone(),
        })?;

        Ok(Self {
            api,
            public_url: public_url.to_string(),
            config_id: config.id,
            db,
            subscription_handler,
        })
    }

    pub async fn listen(&mut self) -> Result<()> {
        let this_webhook = Url::parse(&self.public_url)?.join("/api/v1/webhook/revolut")?;

        // First, check if we have a webhook secret stored in the database
        let mut config = self.db.get_payment_method_config(self.config_id).await?;
        let provider_config = config
            .get_provider_config()
            .context("Failed to parse provider config")?;
        let revolut_config = provider_config
            .as_revolut()
            .context("Config is not a Revolut provider")?;

        let secret = if let Some(secret) = &revolut_config.webhook_secret {
            // We have a stored secret, verify the webhook still exists
            let webhooks = self.api.list_webhooks().await?;
            let existing = webhooks.iter().find(|wh| wh.url == this_webhook.as_str());

            if existing.is_some() {
                info!("Using stored webhook secret for '{}'", this_webhook);
                secret.clone()
            } else {
                // Webhook was deleted externally, need to re-register
                info!(
                    "Webhook was deleted externally, re-registering for '{}'",
                    this_webhook
                );
                self.register_webhook_and_store_secret(&this_webhook, &mut config)
                    .await?
            }
        } else {
            // No stored secret, check if webhook exists
            let webhooks = self.api.list_webhooks().await?;
            let existing = webhooks.iter().find(|wh| wh.url == this_webhook.as_str());

            if let Some(wh) = existing {
                // Webhook exists but we don't have the secret stored
                // Delete it and re-create to obtain the secret
                info!(
                    "Webhook exists for '{}' but secret not stored, deleting and re-creating",
                    this_webhook
                );
                self.api.delete_webhook(&wh.id).await?;
            }

            // Register new webhook and store secret
            self.register_webhook_and_store_secret(&this_webhook, &mut config)
                .await?
        };

        // listen to events
        let mut listener = WEBHOOK_BRIDGE.listen();
        while let Ok(m) = listener.recv().await {
            if m.endpoint != "/api/v1/webhook/revolut" {
                continue;
            }
            let msg = match RevolutWebhookBody::verify(&secret, &m) {
                Err(e) => {
                    error!("Signature verification failed: {}", e);
                    continue;
                }
                Ok(m) => m,
            };

            match msg.event {
                RevolutWebhookEvent::OrderCompleted => {
                    let order_ref = &msg.merchant_order_ext_ref.as_ref().unwrap_or(&msg.order_id);
                    if let Err(e) = self.try_complete_payment(order_ref).await {
                        error!("Failed to complete order {}: {}", order_ref, e);
                    }
                }
                RevolutWebhookEvent::OrderAuthorised => {
                    info!("Order {} authorised, awaiting completion", msg.order_id);
                }
                RevolutWebhookEvent::OrderCancelled => {
                    warn!("Order {} was cancelled", msg.order_id);
                }
            }
        }
        Ok(())
    }

    /// Register a new webhook with Revolut and store the signing secret in the database
    async fn register_webhook_and_store_secret(
        &self,
        webhook_url: &Url,
        config: &mut PaymentMethodConfig,
    ) -> Result<String> {
        info!("Registering webhook for '{}'", webhook_url);
        let wh = self
            .api
            .create_webhook(
                webhook_url.as_str(),
                vec![
                    RevolutWebhookEvent::OrderCompleted,
                    RevolutWebhookEvent::OrderAuthorised,
                    RevolutWebhookEvent::OrderCancelled,
                ],
            )
            .await?;

        let secret = wh.signing_secret.context("Signing secret is missing")?;

        // Update the config with the new webhook secret
        let mut provider_config = config
            .get_provider_config()
            .context("Failed to parse provider config")?;

        if let ProviderConfig::Revolut(ref mut revolut_config) = provider_config {
            revolut_config.webhook_secret = Some(secret.clone());
            config.set_provider_config(provider_config);
            self.db.update_payment_method_config(config).await?;
            info!("Stored webhook secret in database for config {}", config.id);
        }

        Ok(secret)
    }

    /// Fetch the customer's merchant-initiated (off-session capable) saved
    /// payment method and persist it as a `UserPaymentMethod` for automatic
    /// renewals. Idempotent: skips methods already stored for the user.
    async fn capture_saved_payment_method(&self, user_id: u64, customer_id: &str) -> Result<()> {
        let methods = self
            .api
            .get_customer_payment_methods(customer_id, true)
            .await?;
        let Some(method) = methods.into_iter().next() else {
            return Ok(());
        };

        // Dedupe: compare against already-stored Revolut methods (external_id is
        // encrypted with a non-deterministic cipher, so compare decrypted).
        let existing = self
            .db
            .list_user_payment_methods(user_id, Some("revolut"))
            .await
            .unwrap_or_default();
        let already_stored = existing.iter().any(|m| {
            let stored: String = m.external_id.clone().into();
            stored == method.id
        });
        if already_stored {
            return Ok(());
        }

        let card = method.method_details.as_ref();
        let pm = UserPaymentMethod {
            id: 0,
            user_id,
            created: Utc::now(),
            provider: "revolut".to_string(),
            name: None,
            external_customer_id: Some(customer_id.to_string().into()),
            external_id: method.id.clone().into(),
            card_brand: card.and_then(|c| c.brand.clone()),
            card_last_four: card.and_then(|c| c.last4.clone()),
            exp_month: card.and_then(|c| c.expiry_month),
            exp_year: card.and_then(|c| c.expiry_year),
            // First saved method for the user becomes the default.
            is_default: existing.is_empty(),
            enabled: true,
        };
        self.db.insert_user_payment_method(&pm).await?;
        info!(
            "Saved Revolut payment method for user {} (off-session automatic renewals)",
            user_id
        );
        Ok(())
    }

    async fn try_complete_payment(&self, ext_id: &str) -> Result<()> {
        let mut payment = self.db.get_subscription_payment_by_ext_id(ext_id).await?;

        // Verify the Revolut order is completed and store order JSON
        let order = self.api.get_order(ext_id).await?;
        if !matches!(order.state, RevolutOrderState::Completed) {
            error!("Invalid order state {:?}", order);
            return Ok(());
        }
        payment.external_data = serde_json::to_string(&order)?.into();

        // Update user country from the card country if not set (best-effort).
        if let Some(cc) = order
            .payments
            .as_ref()
            .and_then(|p| p.first())
            .and_then(|p| p.payment_method.as_ref())
            .and_then(|p| p.card_country_code.clone())
            .and_then(|c| CountryCode::for_alpha2(&c).ok())
        {
            if let Ok(mut user) = self.db.get_user(payment.user_id).await {
                if user.country_code.is_none() {
                    user.country_code = Some(cc.alpha3().to_string());
                    let _ = self.db.update_user(&user).await;
                }
            }
        }

        // Capture any saved payment method for future off-session
        // (merchant-initiated) automatic renewals. We store only opaque Revolut
        // token references plus non-sensitive card metadata, never card data.
        // The reusable payment method is NOT on the order — fetch it from the
        // customer's saved payment methods (filtered to merchant capability).
        if let Some(customer_id) = order.customer_id() {
            if let Err(e) = self.capture_saved_payment_method(payment.user_id, &customer_id).await {
                warn!(
                    "Failed to capture saved Revolut payment method for user {}: {}",
                    payment.user_id, e
                );
            }
        }

        let result = self.subscription_handler.complete_payment(&payment).await?;
        for p in result.expired_competing_upgrades {
            if let Some(eid) = p.external_id.as_ref() {
                if let Err(e) = self.api.cancel_order(eid).await {
                    warn!("Failed to cancel order {}: {}", hex::encode(p.id), e);
                }
            } else {
                warn!(
                    "External id does not exist on fiat payment: {}",
                    hex::encode(p.id)
                );
            }
        }
        Ok(())
    }
}
