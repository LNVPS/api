use rocket::Route;

mod model;
#[cfg(feature = "nostr-domain")]
mod nostr_domain;
mod routes;
mod webhook;

pub fn routes() -> Vec<Route> {
    let mut r = routes::routes();
    r.append(&mut webhook::routes());
    #[cfg(feature = "nostr-domain")]
    r.append(&mut nostr_domain::routes());
    r
}

pub use webhook::WebhookMessage;
pub use webhook::WEBHOOK_BRIDGE;
