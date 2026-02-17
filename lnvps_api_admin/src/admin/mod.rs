use axum::Router;
use axum::extract::FromRef;
use lnvps_api_common::{ExchangeRateService, RedisWorkFeedback, VmStateCache, WorkCommander};
use lnvps_db::LNVpsDb;
use std::sync::Arc;

mod access_policies;
mod auth;
mod bulk_message;
mod companies;
mod cost_plans;
mod custom_pricing;
mod docs;
mod hosts;
mod ip_ranges;
mod ip_space;
mod model;
mod payment_methods;
mod regions;
mod reports;
mod roles;
mod routers;
mod subscriptions;
mod users;
mod vm_ip_assignments;
mod vm_os_images;
mod vm_templates;
mod vms;
mod websocket;

#[derive(Clone, FromRef)]
pub(crate) struct RouterState {
    pub db: Arc<dyn LNVpsDb>,
    pub work_commander: Arc<dyn WorkCommander>,
    pub feedback: Option<RedisWorkFeedback>,
    pub vm_state_cache: VmStateCache,
    pub exchange: Arc<dyn ExchangeRateService>,
}

pub fn admin_router(
    db: Arc<dyn LNVpsDb>,
    work_commander: Arc<dyn WorkCommander>,
    vm_state_cache: VmStateCache,
    exchange: Arc<dyn ExchangeRateService>,
    feedback: Option<RedisWorkFeedback>,
) -> Router {
    Router::new()
        .merge(docs::router())
        .merge(users::router())
        .merge(bulk_message::router())
        .merge(vms::router())
        .merge(hosts::router())
        .merge(regions::router())
        .merge(roles::router())
        .merge(vm_os_images::router())
        .merge(vm_templates::router())
        .merge(companies::router())
        .merge(cost_plans::router())
        .merge(custom_pricing::router())
        .merge(ip_ranges::router())
        .merge(ip_space::router())
        .merge(access_policies::router())
        .merge(routers::router())
        .merge(vm_ip_assignments::router())
        .merge(subscriptions::router())
        .merge(reports::router())
        .merge(websocket::router())
        .merge(payment_methods::router())
        .with_state(RouterState {
            db,
            work_commander,
            vm_state_cache,
            feedback,
            exchange,
        })
}
