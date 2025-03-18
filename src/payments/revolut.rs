use crate::api::{WebhookMessage, WEBHOOK_BRIDGE};
use crate::fiat::{RevolutApi, RevolutWebhookEvent};
use crate::settings::RevolutConfig;
use crate::worker::WorkJob;
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use isocountry::CountryCode;
use lnvps_db::LNVpsDb;
use log::{error, info, warn};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

pub struct RevolutPaymentHandler {
    api: RevolutApi,
    db: Arc<dyn LNVpsDb>,
    sender: UnboundedSender<WorkJob>,
    public_url: String,
}

impl RevolutPaymentHandler {
    pub fn new(
        settings: RevolutConfig,
        public_url: &str,
        db: Arc<dyn LNVpsDb>,
        sender: UnboundedSender<WorkJob>,
    ) -> Result<Self> {
        Ok(Self {
            api: RevolutApi::new(settings)?,
            public_url: public_url.to_string(),
            db,
            sender,
        })
    }

    pub async fn listen(&mut self) -> Result<()> {
        let this_webhook = Url::parse(&self.public_url)?.join("/api/v1/webhook/revolut")?;
        let webhooks = self.api.list_webhooks().await?;
        for wh in webhooks {
            info!("Deleting old webhook: {} {}", wh.id, wh.url);
            self.api.delete_webhook(&wh.id).await?
        }
        info!("Setting up webhook for '{}'", this_webhook);
        let wh = self
            .api
            .create_webhook(
                this_webhook.as_str(),
                vec![
                    RevolutWebhookEvent::OrderCompleted,
                    RevolutWebhookEvent::OrderAuthorised,
                ],
            )
            .await?;

        let secret = wh.signing_secret.context("Signing secret is missing")?;
        // listen to events
        let mut listenr = WEBHOOK_BRIDGE.listen();
        while let Ok(m) = listenr.recv().await {
            if m.endpoint != "/api/v1/webhook/revolut" {
                continue;
            }
            let body: RevolutWebhook = serde_json::from_slice(m.body.as_slice())?;
            info!("Received webhook {:?}", body);
            if let Err(e) = verify_webhook(&secret, &m) {
                error!("Signature verification failed: {}", e);
                continue;
            }

            if let RevolutWebhookEvent::OrderCompleted = body.event {
                if let Err(e) = self.try_complete_payment(&body.order_id).await {
                    error!("Failed to complete order: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn try_complete_payment(&self, ext_id: &str) -> Result<()> {
        let mut p = self.db.get_vm_payment_by_ext_id(ext_id).await?;

        // save payment state json into external_data
        // TODO: encrypt payment_data
        let order = self.api.get_order(ext_id).await?;
        p.external_data = serde_json::to_string(&order)?;

        // check user country matches card country
        if let Some(cc) = order
            .payments
            .and_then(|p| p.first().cloned())
            .and_then(|p| p.payment_method)
            .and_then(|p| p.card_country_code)
            .and_then(|c| CountryCode::for_alpha2(&c).ok())
        {
            let vm = self.db.get_vm(p.vm_id).await?;
            let mut user = self.db.get_user(vm.user_id).await?;
            if user.country_code.is_none() {
                // update user country code to match card country
                user.country_code = Some(cc.alpha3().to_string());
                self.db.update_user(&user).await?;
            }
        }

        self.db.vm_payment_paid(&p).await?;
        self.sender.send(WorkJob::CheckVm { vm_id: p.vm_id })?;
        info!("VM payment {} for {}, paid", hex::encode(p.id), p.vm_id);
        Ok(())
    }
}

type HmacSha256 = Hmac<sha2::Sha256>;
fn verify_webhook(secret: &str, msg: &WebhookMessage) -> Result<()> {
    let sig = msg
        .headers
        .get("revolut-signature")
        .ok_or_else(|| anyhow!("Missing Revolut-Signature header"))?;
    let timestamp = msg
        .headers
        .get("revolut-request-timestamp")
        .ok_or_else(|| anyhow!("Missing Revolut-Request-Timestamp header"))?;

    // check if any signatures match
    for sig in sig.split(",") {
        let mut sig_split = sig.split("=");
        let (version, code) = (
            sig_split.next().context("Invalid signature format")?,
            sig_split.next().context("Invalid signature format")?,
        );
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(version.as_bytes());
        mac.update(b".");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(msg.body.as_slice());
        let result = mac.finalize().into_bytes();

        if hex::encode(result) == code {
            return Ok(());
        } else {
            warn!(
                "Invalid signature found {} != {}",
                code,
                hex::encode(result)
            );
        }
    }

    bail!("No valid signature found!");
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevolutWebhook {
    pub event: RevolutWebhookEvent,
    pub order_id: String,
    pub merchant_order_ext_ref: Option<String>,
}
