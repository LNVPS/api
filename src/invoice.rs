use crate::worker::WorkJob;
use anyhow::Result;
use fedimint_tonic_lnd::lnrpc::invoice::InvoiceState;
use fedimint_tonic_lnd::lnrpc::InvoiceSubscription;
use fedimint_tonic_lnd::Client;
use lnvps_db::LNVpsDb;
use log::{error, info};
use nostr::util::hex;
use rocket::futures::StreamExt;
use tokio::sync::mpsc::UnboundedSender;

pub struct InvoiceHandler {
    lnd: Client,
    db: Box<dyn LNVpsDb>,
    tx: UnboundedSender<WorkJob>,
}

impl InvoiceHandler {
    pub fn new<D: LNVpsDb + 'static>(lnd: Client, db: D, tx: UnboundedSender<WorkJob>) -> Self {
        Self {
            lnd,
            tx,
            db: Box::new(db),
        }
    }

    async fn mark_paid(&self, settle_index: u64, id: &Vec<u8>) -> Result<()> {
        let mut p = self.db.get_vm_payment(id).await?;
        p.settle_index = Some(settle_index);
        self.db.vm_payment_paid(&p).await?;

        info!("VM payment {} for {}, paid", hex::encode(p.id), p.vm_id);
        self.tx.send(WorkJob::CheckVm { vm_id: p.vm_id })?;

        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        let from_settle_index = if let Some(p) = self.db.last_paid_invoice().await? {
            p.settle_index.unwrap_or(0)
        } else {
            0
        };
        info!("Listening for invoices from {from_settle_index}");

        let handler = self
            .lnd
            .lightning()
            .subscribe_invoices(InvoiceSubscription {
                add_index: 0,
                settle_index: from_settle_index,
            })
            .await?;

        let mut stream = handler.into_inner();
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(i) => {
                    if i.state == InvoiceState::Settled as i32 {
                        if let Err(e) = self.mark_paid(i.settle_index, &i.r_hash).await {
                            error!("{}", e);
                        }
                    }
                }
                Err(e) => error!("{}", e),
            }
        }
        Ok(())
    }
}
