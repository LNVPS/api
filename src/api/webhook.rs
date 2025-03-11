use log::warn;
use rocket::data::{FromData, ToByteUnit};
use rocket::http::Status;
use rocket::{post, routes, Data, Route};
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::sync::broadcast;

/// Messaging bridge for webhooks to other parts of the system (bitvora/revout)
pub static WEBHOOK_BRIDGE: LazyLock<WebhookBridge> = LazyLock::new(WebhookBridge::new);

pub fn routes() -> Vec<Route> {
    let mut routes = vec![];

    #[cfg(feature = "bitvora")]
    routes.append(&mut routes![bitvora_webhook]);

    #[cfg(feature = "revolut")]
    routes.append(&mut routes![revolut_webhook]);

    routes
}

#[cfg(feature = "bitvora")]
#[post("/api/v1/webhook/bitvora", data = "<req>")]
async fn bitvora_webhook(req: WebhookMessage) -> Status {
    WEBHOOK_BRIDGE.send(req);
    Status::Ok
}

#[cfg(feature = "revolut")]
#[post("/api/v1/webhook/revolut", data = "<req>")]
async fn revolut_webhook(req: WebhookMessage) -> Status {
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

impl Default for WebhookBridge {
    fn default() -> Self {
        Self::new()
    }
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
