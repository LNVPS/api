use crate::lightning::LightningNode;
use crate::payments::invoice::NodeInvoiceHandler;
use crate::settings::Settings;
use crate::worker::WorkJob;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use log::error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

mod invoice;
#[cfg(feature = "revolut")]
mod revolut;

pub fn listen_all_payments(
    settings: &Settings,
    node: Arc<dyn LightningNode>,
    db: Arc<dyn LNVpsDb>,
    sender: UnboundedSender<WorkJob>,
) -> Result<()> {
    let mut handler = NodeInvoiceHandler::new(node.clone(), db.clone(), sender.clone());
    tokio::spawn(async move {
        loop {
            if let Err(e) = handler.listen().await {
                error!("invoice-error: {}", e);
            }
            sleep(Duration::from_secs(1)).await;
        }
    });

    #[cfg(feature = "revolut")]
    {
        use crate::payments::revolut::RevolutPaymentHandler;
        if let Some(r) = &settings.revolut {
            let mut handler = RevolutPaymentHandler::new(
                r.clone(),
                &settings.public_url,
                db.clone(),
                sender.clone(),
            )?;
            tokio::spawn(async move {
                loop {
                    if let Err(e) = handler.listen().await {
                        error!("revolut-error: {}", e);
                    }
                    sleep(Duration::from_secs(30)).await;
                }
            });
        }
    }

    Ok(())
}
