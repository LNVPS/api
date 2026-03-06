use crate::payments::invoice::NodeInvoiceHandler;
use crate::settings::Settings;
use crate::subscription::line_item_handler;
use anyhow::Result;
use lnvps_api_common::WorkCommander;
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
use log::{error, info, warn};
use payments_rs::lightning::LightningNode;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::sleep;

mod invoice;
#[cfg(feature = "revolut")]
mod revolut;
#[cfg(feature = "stripe")]
mod stripe;

// =========================================================================
// Centralised complete_payment pipeline
// =========================================================================

/// Complete a payment:
/// 1. Mark paid in DB (extends subscription/vm expiry atomically)
/// 2. Call `SubscriptionLineItemHandler::on_payment` for each line item
/// 3. Run the payment-method-specific cancel function for competing upgrades
pub(crate) async fn complete_payment<F, Fut>(
    db: &Arc<dyn LNVpsDb>,
    payment: &SubscriptionPayment,
    tx: Arc<dyn WorkCommander>,
    method_label: &'static str,
    cancel_competing_upgrades: F,
) -> Result<()>
where
    F: FnOnce(SubscriptionPayment) -> Fut + Send,
    Fut: Future<Output = Result<()>> + Send,
{
    db.subscription_payment_paid(payment).await?;

    let line_items = db.list_subscription_line_items(payment.subscription_id).await?;
    for li in &line_items {
        match line_item_handler(li, db.clone(), tx.clone()).await {
            Ok(handler) => {
                if let Err(e) = handler.on_payment(payment, method_label).await {
                    warn!(
                        "on_payment failed for line item {} (sub {}): {}",
                        li.id, payment.subscription_id, e
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Failed to build handler for line item {} (sub {}): {}",
                    li.id, payment.subscription_id, e
                );
            }
        }
    }

    if payment.payment_type == SubscriptionPaymentType::Upgrade {
        cancel_competing_upgrades(payment.clone()).await?;
    }

    info!(
        "Payment {} for subscription {} complete",
        hex::encode(&payment.id),
        payment.subscription_id
    );
    Ok(())
}

// =========================================================================
// listen_all_payments
// =========================================================================

pub async fn listen_all_payments(
    settings: &Settings,
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    sender: Arc<dyn WorkCommander>,
) -> Result<Vec<JoinHandle<()>>> {
    let mut ret = Vec::new();
    let mut handler = NodeInvoiceHandler::new(node.clone(), db.clone(), sender.clone());
    ret.push(tokio::spawn(async move {
        loop {
            if let Err(e) = handler.listen().await {
                error!("invoice-error: {}", e);
            }
            sleep(Duration::from_secs(10)).await;
        }
    }));

    #[cfg(feature = "revolut")]
    {
        use crate::payments::revolut::RevolutPaymentHandler;

        // Load all Revolut payment configs from database
        let revolut_configs = db
            .list_payment_method_configs()
            .await?
            .into_iter()
            .filter(|c| c.payment_method == PaymentMethod::Revolut && c.enabled)
            .collect::<Vec<_>>();

        for config in revolut_configs {
            info!(
                "Starting Revolut payment handler for config: {}",
                config.name
            );
            match RevolutPaymentHandler::new(
                &config,
                &settings.public_url,
                db.clone(),
                sender.clone(),
            ) {
                Ok(mut handler) => {
                    ret.push(tokio::spawn(async move {
                        loop {
                            if let Err(e) = handler.listen().await {
                                error!("revolut-error: {}", e);
                            }
                            sleep(Duration::from_secs(30)).await;
                        }
                    }));
                }
                Err(e) => {
                    error!(
                        "Failed to create Revolut payment handler for '{}': {}",
                        config.name, e
                    );
                }
            }
        }
    }

    #[cfg(feature = "stripe")]
    {
        use crate::payments::stripe::StripePaymentHandler;

        let stripe_configs = db
            .list_payment_method_configs()
            .await?
            .into_iter()
            .filter(|c| c.payment_method == PaymentMethod::Stripe && c.enabled)
            .collect::<Vec<_>>();

        for config in stripe_configs {
            info!("Starting Stripe payment handler for config: {}", config.name);
            match StripePaymentHandler::new(&config, db.clone(), sender.clone()) {
                Ok(mut handler) => {
                    ret.push(tokio::spawn(async move {
                        loop {
                            if let Err(e) = handler.listen().await {
                                error!("stripe-error: {}", e);
                            }
                            sleep(Duration::from_secs(30)).await;
                        }
                    }));
                }
                Err(e) => {
                    error!(
                        "Failed to create Stripe payment handler for '{}': {}",
                        config.name, e
                    );
                }
            }
        }
    }

    Ok(ret)
}


