use axum::Router;
use axum::extract::FromRef;
use lnvps_api_common::{
    ExchangeRateService, RedisWorkFeedback, VatClient, VmStateCache, WorkCommander,
};
use lnvps_db::LNVpsDb;
use std::sync::Arc;

mod access_policies;
mod agent;
mod apps;
mod auth;
mod bulk_message;
mod companies;
mod cost_plans;
mod costs;
mod custom_pricing;
mod discounts;
mod dns_servers;
mod docs;
mod hosts;
mod ip_ranges;
mod ip_space;
mod marketplace;
mod model;
mod passkeys;
mod payment_methods;
mod referrals;
mod regions;
mod reports;
mod roles;
mod routers;
mod subscriptions;
mod tunnel_pools;
mod user_payment_methods;
mod users;
mod vm_ip_assignments;
mod vm_os_images;
mod vm_templates;
mod vms;
mod websocket;

#[derive(Clone, FromRef)]
pub(crate) struct RouterState {
    pub db: Arc<dyn LNVpsDb>,
    /// How the admin API calls a marketplace node. `None` in a deployment that
    /// runs no marketplace, where the node endpoints answer with that reason
    /// rather than with a key nobody configured.
    pub node_control: Option<lnvps_api_common::node_control::NodeControl>,
    pub work_commander: Arc<dyn WorkCommander>,
    pub feedback: Option<RedisWorkFeedback>,
    pub vm_state_cache: VmStateCache,
    pub exchange: Arc<dyn ExchangeRateService>,
    /// EU VAT rate table, shared with the refresh task. Starts empty, so a
    /// caller that reports a rate must check [`VatClient::rate_count`] before
    /// presenting 0% as a determination rather than as "not loaded yet".
    pub vat: VatClient,
}

pub fn admin_router(
    db: Arc<dyn LNVpsDb>,
    work_commander: Arc<dyn WorkCommander>,
    vm_state_cache: VmStateCache,
    exchange: Arc<dyn ExchangeRateService>,
    feedback: Option<RedisWorkFeedback>,
    node_control: Option<lnvps_api_common::node_control::NodeControl>,
    vat: VatClient,
) -> Router {
    Router::new()
        .merge(docs::router())
        .merge(users::router())
        .merge(agent::router())
        .merge(passkeys::router())
        .merge(bulk_message::router())
        .merge(vms::router())
        .merge(hosts::router())
        .merge(regions::router())
        .merge(roles::router())
        .merge(vm_os_images::router())
        .merge(vm_templates::router())
        .merge(companies::router())
        .merge(cost_plans::router())
        .merge(costs::router())
        .merge(custom_pricing::router())
        .merge(ip_ranges::router())
        .merge(ip_space::router())
        .merge(access_policies::router())
        .merge(routers::router())
        .merge(discounts::router())
        .merge(dns_servers::router())
        .merge(vm_ip_assignments::router())
        .merge(subscriptions::router())
        .merge(referrals::router())
        .merge(marketplace::router())
        .merge(tunnel_pools::router())
        .merge(apps::router())
        .merge(reports::router())
        .merge(websocket::router())
        .merge(payment_methods::router())
        .merge(user_payment_methods::router())
        .with_state(RouterState {
            node_control,
            db,
            work_commander,
            vm_state_cache,
            feedback,
            exchange,
            vat,
        })
}
