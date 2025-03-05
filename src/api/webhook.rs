use log::warn;
use reqwest::header::HeaderMap;
use rocket::data::{FromData, ToByteUnit};
use rocket::http::Status;
use rocket::{post, routes, Data, Route};
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::io::AsyncReadExt;
use tokio::sync::broadcast;

/// Messaging bridge for webhooks to other parts of the system (bitvora)
pub static WEBHOOK_BRIDGE: LazyLock<WebhookBridge> = LazyLock::new(|| WebhookBridge::new());

pub fn routes() -> Vec<Route> {
    if cfg!(feature = "bitvora") {
        routes![bitvora_webhook]
    } else {
        routes![]
    }
}

#[post("/api/v1/webhook/bitvora", data = "<req>")]
async fn bitvora_webhook(req: WebhookMessage) -> Status {
    WEBHOOK_BRIDGE.send(req);
    Status::Ok
}

#[derive(Debug, Clone)]
pub struct WebhookMessage {
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
}

#[rocket::async_trait]
impl<'r> FromData<'r> for WebhookMessage {
    type Error = ();

    async fn from_data(
        req: &'r rocket::Request<'_>,
        data: Data<'r>,
    ) -> rocket::data::Outcome<'r, Self, Self::Error> {
        let header = req
            .headers()
            .iter()
            .map(|v| (v.name.to_string(), v.value.to_string()))
            .collect();
        let body = if let Ok(d) = data.open(4.megabytes()).into_bytes().await {
            d
        } else {
            return rocket::data::Outcome::Error((Status::BadRequest, ()));
        };
        let msg = WebhookMessage {
            headers: header,
            body: body.value.to_vec(),
        };
        rocket::data::Outcome::Success(msg)
    }
}
#[derive(Debug)]
pub struct WebhookBridge {
    tx: broadcast::Sender<WebhookMessage>,
}

impl WebhookBridge {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self { tx }
    }

    pub fn send(&self, message: WebhookMessage) {
        if let Err(e) = self.tx.send(message) {
            warn!("Failed to send webhook message: {}", e);
        }
    }

    pub fn listen(&self) -> broadcast::Receiver<WebhookMessage> {
        self.tx.subscribe()
    }
}
