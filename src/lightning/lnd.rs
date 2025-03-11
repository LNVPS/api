use crate::lightning::{AddInvoiceRequest, AddInvoiceResult, InvoiceUpdate, LightningNode};
use anyhow::Result;
use fedimint_tonic_lnd::invoicesrpc::lookup_invoice_msg::InvoiceRef;
use fedimint_tonic_lnd::invoicesrpc::LookupInvoiceMsg;
use fedimint_tonic_lnd::lnrpc::invoice::InvoiceState;
use fedimint_tonic_lnd::lnrpc::{Invoice, InvoiceSubscription};
use fedimint_tonic_lnd::{connect, Client};
use futures::StreamExt;
use lnvps_db::async_trait;
use nostr_sdk::async_utility::futures_util::Stream;
use std::path::Path;
use std::pin::Pin;

pub struct LndNode {
    client: Client,
}

impl LndNode {
    pub async fn new(url: &str, cert: &Path, macaroon: &Path) -> Result<Self> {
        let lnd = connect(url.to_string(), cert, macaroon).await?;
        Ok(Self { client: lnd })
    }
}

#[async_trait]
impl LightningNode for LndNode {
    async fn add_invoice(&self, req: AddInvoiceRequest) -> Result<AddInvoiceResult> {
        let mut client = self.client.clone();
        let ln = client.lightning();
        let res = ln
            .add_invoice(Invoice {
                memo: req.memo.unwrap_or_default(),
                value_msat: req.amount as i64,
                expiry: req.expire.unwrap_or(3600) as i64,
                ..Default::default()
            })
            .await?;

        let inner = res.into_inner();
        Ok(AddInvoiceResult {
            pr: inner.payment_request,
            payment_hash: hex::encode(inner.r_hash),
        })
    }

    async fn subscribe_invoices(
        &self,
        from_payment_hash: Option<Vec<u8>>,
    ) -> Result<Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>> {
        let mut client = self.client.clone();
        let from_settle_index = if let Some(ph) = from_payment_hash {
            if let Ok(inv) = client
                .invoices()
                .lookup_invoice_v2(LookupInvoiceMsg {
                    lookup_modifier: 0,
                    invoice_ref: Some(InvoiceRef::PaymentHash(ph)),
                })
                .await
            {
                inv.into_inner().settle_index
            } else {
                0
            }
        } else {
            0
        };

        let stream = client
            .lightning()
            .subscribe_invoices(InvoiceSubscription {
                add_index: 0,
                settle_index: from_settle_index,
            })
            .await?;

        let stream = stream.into_inner();
        Ok(Box::pin(stream.map(|i| match i {
            Ok(m) => {
                if m.state == InvoiceState::Settled as i32 {
                    InvoiceUpdate::Settled {
                        payment_hash: hex::encode(m.r_hash),
                    }
                } else {
                    InvoiceUpdate::Unknown
                }
            }
            Err(e) => InvoiceUpdate::Error(e.to_string()),
        })))
    }
}
