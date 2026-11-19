use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiData, ApiResult, deserialize_from_str_optional};
use lnvps_db::{AdminAction, AdminResource, IpOrderState, VmIpWait};
use serde::{Deserialize, Serialize};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/admin/v1/vm_ip_waits", get(admin_list_vm_ip_waits))
}

#[derive(Serialize, Debug)]
pub struct AdminVmIpWait {
    pub vm_id: u64,
    pub user_id: Option<u64>,
    pub region_id: u64,
    pub ip4_needed: u16,
    pub released: bool,
    pub waiting_since: DateTime<Utc>,
    pub ip_order_id: Option<u64>,
    pub ip_order_state: Option<IpOrderState>,
    pub ip_order_error: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct WaitQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    region_id: Option<u64>,
}

async fn admin_list_vm_ip_waits(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<WaitQuery>,
) -> ApiResult<Vec<AdminVmIpWait>> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    let waits: Vec<VmIpWait> = this.db.list_vm_ip_waits(q.region_id).await?;
    let mut out = Vec::new();
    for w in waits {
        let order = match w.ip_order_id {
            Some(id) => this.db.get_ip_order(id).await.ok(),
            None => None,
        };
        let user_id = this.db.get_vm(w.vm_id).await.ok().map(|v| v.user_id);
        out.push(AdminVmIpWait {
            vm_id: w.vm_id,
            user_id,
            region_id: w.region_id,
            ip4_needed: w.ip4_needed,
            released: w.released,
            waiting_since: w.created,
            ip_order_id: w.ip_order_id,
            ip_order_state: order.as_ref().map(|o| o.state),
            ip_order_error: order.and_then(|o| o.error),
        });
    }
    ApiData::ok(out)
}
