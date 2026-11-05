use anyhow::{Context, Result};
use async_trait::async_trait;
use lnvps_db::{LNVpsDb, PaymentMethod};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOutput {
    pub address: String,
    pub amount_msat: u64,
    pub confirmed: bool,
    pub ours: bool,
}

#[async_trait]
pub trait ChainOutputLookup: Send + Sync {
    async fn lookup(&self, txid: &str, vout: u32) -> Result<Option<ChainOutput>>;
}

pub struct MempoolOutputLookup {
    base_url: String,
    client: reqwest::Client,
    db: Arc<dyn LNVpsDb>,
}

impl MempoolOutputLookup {
    pub fn new(base_url: impl Into<String>, db: Arc<dyn LNVpsDb>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
            db,
        }
    }

    async fn is_ours(&self, address: &str) -> Result<bool> {
        if self.db.get_onchain_address_owner(address).await?.is_some() {
            return Ok(true);
        }
        for method in [PaymentMethod::OnChain, PaymentMethod::FixedFloat] {
            let payments = self.db.list_subscription_payments_by_method(method).await?;
            if payments
                .iter()
                .any(|p| p.onchain_receive_address().as_deref() == Some(address))
            {
                return Ok(true);
            }
            let topups = self.db.list_account_credit_topups_by_method(method).await?;
            if topups
                .iter()
                .any(|t| method == PaymentMethod::OnChain && t.external_data == address)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Deserialize)]
struct EsploraTx {
    vout: Vec<EsploraVout>,
    status: EsploraStatus,
}

#[derive(Deserialize)]
struct EsploraVout {
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Deserialize)]
struct EsploraStatus {
    confirmed: bool,
}

pub(crate) fn parse_esplora_output(body: &[u8], vout: u32) -> Result<Option<(String, u64, bool)>> {
    let tx: EsploraTx = serde_json::from_slice(body).context("parsing esplora transaction")?;
    let Some(out) = tx.vout.into_iter().nth(vout as usize) else {
        return Ok(None);
    };
    let Some(address) = out.scriptpubkey_address else {
        return Ok(None);
    };
    Ok(Some((address, out.value * 1000, tx.status.confirmed)))
}

#[async_trait]
impl ChainOutputLookup for MempoolOutputLookup {
    async fn lookup(&self, txid: &str, vout: u32) -> Result<Option<ChainOutput>> {
        let url = format!("{}/api/tx/{}", self.base_url.trim_end_matches('/'), txid);
        let res = self.client.get(url).send().await?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = res.error_for_status()?.bytes().await?;
        let Some((address, amount_msat, confirmed)) = parse_esplora_output(&body, vout)? else {
            return Ok(None);
        };
        let ours = self.is_ours(&address).await?;
        Ok(Some(ChainOutput {
            ours,
            address,
            amount_msat,
            confirmed,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{LNVpsDbBase, SubscriptionPayment, SubscriptionPaymentType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const FIXTURE: &str = include_str!("../../tests/fixtures/esplora_tx_fa5bfab0.json");
    const TXID: &str = "fa5bfab0401c66ffdba7ba17adad3db427694c600efc19ae77f99557b8d23d3e";
    const OUT0: &str = "bc1qg50jag4ykx2a2xkegkrdhq8fyz7lnkpglfz0z2";

    async fn serve(status: &'static str, body: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        format!("http://{addr}")
    }

    fn lookup_for(url: String, db: Arc<MockDb>) -> MempoolOutputLookup {
        MempoolOutputLookup::new(url, db)
    }

    async fn db_owning(address: Option<&str>) -> Arc<MockDb> {
        let db = Arc::new(MockDb::default());
        if let Some(address) = address {
            db.insert_subscription_payment(&SubscriptionPayment {
                id: vec![1; 32],
                subscription_id: 1,
                user_id: 1,
                created: chrono::Utc::now(),
                expires: chrono::Utc::now(),
                amount: 1,
                currency: "BTC".to_string(),
                payment_method: PaymentMethod::OnChain,
                payment_type: SubscriptionPaymentType::Renewal,
                external_data: address.into(),
                external_id: None,
                is_paid: false,
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
                renewal_source: None,
            })
            .await
            .unwrap();
        }
        db
    }

    #[test]
    fn parses_confirmed_real_transaction_outputs() {
        let (addr, msat, confirmed) = parse_esplora_output(FIXTURE.as_bytes(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(addr, OUT0);
        assert_eq!(msat, 27_187_000);
        assert!(confirmed);
        let (addr, msat, _) = parse_esplora_output(FIXTURE.as_bytes(), 2)
            .unwrap()
            .unwrap();
        assert_eq!(addr, "bc1qgv5fuheq50ghnju8lafqvps7h96ztfjtcvmsnd");
        assert_eq!(msat, 51_143_274_000);
        assert!(
            parse_esplora_output(FIXTURE.as_bytes(), 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parses_unconfirmed_transaction() {
        let mut v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        v["status"] = serde_json::json!({"confirmed": false});
        let (_, _, confirmed) = parse_esplora_output(v.to_string().as_bytes(), 0)
            .unwrap()
            .unwrap();
        assert!(!confirmed);
    }

    #[test]
    fn output_without_address_is_not_payable() {
        let mut v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        v["vout"][0] = serde_json::json!({"scriptpubkey_type": "op_return", "value": 0});
        assert!(
            parse_esplora_output(v.to_string().as_bytes(), 0)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn lookup_confirmed_output_to_our_address() {
        let url = serve("200 OK", FIXTURE.to_string()).await;
        let out = lookup_for(url, db_owning(Some(OUT0)).await)
            .lookup(TXID, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(out.confirmed && out.ours);
        assert_eq!(out.amount_msat, 27_187_000);
    }

    #[tokio::test]
    async fn lookup_spent_output_still_counts_as_received() {
        let url = serve("200 OK", FIXTURE.to_string()).await;
        let out = lookup_for(
            url,
            db_owning(Some("13uapEHb3Fy1JAkuEi6tFF44M1b77TNywG")).await,
        )
        .lookup(TXID, 1)
        .await
        .unwrap()
        .unwrap();
        assert!(out.confirmed && out.ours);
        assert_eq!(out.amount_msat, 8_321_068_000);
    }

    #[tokio::test]
    async fn lookup_wrong_address_is_not_ours() {
        let url = serve("200 OK", FIXTURE.to_string()).await;
        let out = lookup_for(url, db_owning(Some("bc1qsomethingelse")).await)
            .lookup(TXID, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(!out.ours);
    }

    #[tokio::test]
    async fn lookup_unknown_transaction_is_none() {
        let url = serve("404 Not Found", "Transaction not found".to_string()).await;
        assert!(
            lookup_for(url, db_owning(None).await)
                .lookup(TXID, 0)
                .await
                .unwrap()
                .is_none()
        );
    }
}
