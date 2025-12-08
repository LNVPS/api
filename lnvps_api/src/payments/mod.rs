use crate::settings::Settings;
use anyhow::Result;
use lnvps_api_common::{UpgradeConfig, WorkJob};
use lnvps_db::{LNVpsDb, VmPayment};
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use payments_rs::lightning::LightningNode;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;
use crate::payments::invoice::NodeInvoiceHandler;

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
            sleep(Duration::from_secs(10)).await;
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

pub(crate) async fn handle_upgrade(
    payment: &VmPayment,
    tx: &UnboundedSender<WorkJob>,
    db: Arc<dyn LNVpsDb>,
) -> Result<()> {
    // Parse upgrade parameters from the dedicated upgrade_params field
    if let Some(upgrade_params_json) = &payment.upgrade_params {
        if let Ok(upgrade_params) = serde_json::from_str::<UpgradeConfig>(upgrade_params_json) {
            info!("Processing upgrade payment for VM {} with params: CPU={:?}, Memory={:?}, Disk={:?}",
                          payment.vm_id, upgrade_params.new_cpu, upgrade_params.new_memory, upgrade_params.new_disk);
            tx.send(WorkJob::ProcessVmUpgrade {
                vm_id: payment.vm_id,
                config: upgrade_params,
            })?;
        } else {
            warn!(
                "Upgrade payment {} has invalid upgrade parameters JSON",
                hex::encode(&payment.id)
            );
        }
    } else {
        warn!(
            "Upgrade payment {} missing upgrade_params field",
            hex::encode(&payment.id)
        );
    }
    Ok(())
}
