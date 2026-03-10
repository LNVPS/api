use crate::payments::invoice::NodeInvoiceHandler;
use crate::settings::Settings;
use crate::subscription::SubscriptionHandler;
use anyhow::Result;
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
// listen_all_payments
// =========================================================================

pub async fn listen_all_payments(
    settings: &Settings,
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    sub_handler: SubscriptionHandler,
) -> Result<Vec<JoinHandle<()>>> {
    let mut ret = Vec::new();
    let mut handler = NodeInvoiceHandler::new(node.clone(), db.clone(), sub_handler.clone());
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
                sub_handler.clone(),
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
            info!(
                "Starting Stripe payment handler for config: {}",
                config.name
            );
            match StripePaymentHandler::new(&config, db.clone(), sub_handler.clone()) {
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
