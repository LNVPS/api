use axum::Router;
use axum::extract::FromRef;
use lnvps_api_common::{ExchangeRateService, VmStateCache, WorkCommander};
use lnvps_db::LNVpsDb;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub(crate) struct PageQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

mod access_policies;
mod auth;
mod bulk_message;
mod companies;
mod cost_plans;
mod custom_pricing;
mod hosts;
mod ip_ranges;
mod model;
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
    pub work_commander: Option<WorkCommander>,
    pub vm_state_cache: VmStateCache,
    pub exchange: Arc<dyn ExchangeRateService>,
}

pub fn admin_router(
    db: Arc<dyn LNVpsDb>,
    work_commander: Option<WorkCommander>,
    vm_state_cache: VmStateCache,
    exchange: Arc<dyn ExchangeRateService>,
) -> Router {
    Router::new()
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
        .merge(access_policies::router())
        .merge(routers::router())
        .merge(vm_ip_assignments::router())
        .merge(subscriptions::router())
        .merge(reports::router())
        .merge(websocket::router())
        .with_state(RouterState {
            db,
            work_commander,
            vm_state_cache,
            exchange,
        })
}
