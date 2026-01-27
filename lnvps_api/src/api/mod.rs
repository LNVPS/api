use rocket::Route;

mod contact;
mod model;
#[cfg(feature = "nostr-domain")]
mod nostr_domain;
mod routes;
mod subscriptions;
mod webhook;

pub fn routes() -> Vec<Route> {
    let mut r = routes::routes();
    r.append(&mut webhook::routes());
    r.append(&mut subscriptions::routes());
    r.append(&mut contact::routes());
    #[cfg(feature = "nostr-domain")]
    r.append(&mut nostr_domain::routes());
    r
}
