use crate::api::RouterState;
use axum::Router;
use axum::extract::Request;
use axum::routing::any;
use futures::StreamExt;
use payments_rs::webhook::{WEBHOOK_BRIDGE, WebhookMessage};

#[cfg(feature = "bitvora")]
compile_error!("Bitvora service has been shut down and is no longer available. Remove the 'bitvora' feature from your build.");

pub fn router() -> Router<RouterState> {
    let mut router = Router::new();

    #[cfg(feature = "bitvora")]
    {
        router = router.route("/api/v1/webhook/bitvora", any(send_webhook));
    }

    #[cfg(feature = "revolut")]
    {
        router = router.route("/api/v1/webhook/revolut", any(send_webhook));
    }

    router
}

async fn send_webhook(req: Request) {
    let mut msg = WebhookMessage {
        endpoint: req.uri().path().to_string(),
        body: Vec::new(),
        headers: req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
            .collect(),
    };
    let mut s = req.into_body().into_data_stream();
    while let Some(Ok(f)) = s.next().await {
        msg.body.extend_from_slice(&f);
    }

    WEBHOOK_BRIDGE.send(msg);
}
