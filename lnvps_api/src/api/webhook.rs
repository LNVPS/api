use payments_rs::webhook::{WEBHOOK_BRIDGE, WebhookMessage};
use rocket::http::Status;
use rocket::{Route, post, routes};

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
