use rocket::Route;

mod model;
mod routes;
mod webhook;

pub fn routes() -> Vec<Route> {
    let mut r = routes::routes();
    r.append(&mut webhook::routes());
    r
}

pub use webhook::WebhookMessage;
pub use webhook::WEBHOOK_BRIDGE;
