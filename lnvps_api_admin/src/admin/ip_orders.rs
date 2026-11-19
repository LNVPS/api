use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::ip_provider::{
    NewIpOrder, approve_ip_order, create_ip_order, reject_ip_order,
};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, WorkJob,
    deserialize_from_str_optional,
};
use lnvps_db::{
    AdminAction, AdminResource, IpOrder, IpOrderAudit, IpOrderRange, IpOrderState, LNVpsDb,
};
use serde::{Deserialize, Serialize};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::JobResponse;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/ip_orders",
            get(admin_list_ip_orders).post(admin_create_ip_order),
        )
        .route("/api/admin/v1/ip_orders/{id}", get(admin_get_ip_order))
        .route(
            "/api/admin/v1/ip_orders/{id}/approve",
            post(admin_approve_ip_order),
        )
        .route(
            "/api/admin/v1/ip_orders/{id}/reject",
            post(admin_reject_ip_order),
        )
        .route(
            "/api/admin/v1/ip_order_ranges",
            get(admin_list_ip_order_ranges),
        )
        .route(
            "/api/admin/v1/ip_ranges/{id}/release",
            post(admin_release_ip_range),
        )
}

#[derive(Serialize, Debug)]
pub struct AdminIpOrder {
    pub id: u64,
    pub provider: String,
    pub region_id: u64,
    pub idempotency_key: Option<String>,
    pub country: Option<String>,
    pub destination: Option<String>,
    pub prefix_len: u16,
    pub quantity: u32,
    pub state: IpOrderState,
    pub provider_order_id: Option<String>,
    pub cost: u64,
    pub currency: String,
    pub auto: bool,
    pub requested_by: Option<u64>,
    pub approved_by: Option<u64>,
    pub approved_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub created: DateTime<Utc>,
    pub ordered_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
}

impl From<IpOrder> for AdminIpOrder {
    fn from(o: IpOrder) -> Self {
        Self {
            id: o.id,
            provider: o.provider,
            region_id: o.region_id,
            idempotency_key: o.idempotency_key,
            country: o.country,
            destination: o.destination,
            prefix_len: o.prefix_len,
            quantity: o.quantity,
            state: o.state,
            provider_order_id: o.provider_order_id,
            cost: o.cost,
            currency: o.currency,
            auto: o.auto,
            requested_by: o.requested_by,
            approved_by: o.approved_by,
            approved_at: o.approved_at,
            error: o.error,
            created: o.created,
            ordered_at: o.ordered_at,
            delivered_at: o.delivered_at,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct AdminIpOrderAudit {
    pub id: u64,
    pub event: String,
    pub detail: Option<String>,
    pub actor_user_id: Option<u64>,
    pub created: DateTime<Utc>,
}

impl From<IpOrderAudit> for AdminIpOrderAudit {
    fn from(a: IpOrderAudit) -> Self {
        Self {
            id: a.id,
            event: a.event,
            detail: a.detail,
            actor_user_id: a.actor_user_id,
            created: a.created,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct AdminIpOrderRange {
    pub id: u64,
    pub ip_order_id: u64,
    pub ip_range_id: u64,
    pub cidr: String,
    pub provider: Option<String>,
    pub cost: Option<u64>,
    pub currency: Option<String>,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug)]
pub struct AdminIpOrderDetail {
    #[serde(flatten)]
    pub order: AdminIpOrder,
    pub ranges: Vec<AdminIpOrderRange>,
    pub audit: Vec<AdminIpOrderAudit>,
}

async fn range_view(
    db: &dyn LNVpsDb,
    r: IpOrderRange,
    order: Option<&IpOrder>,
) -> AdminIpOrderRange {
    let fetched;
    let order = match order {
        Some(o) => Some(o),
        None => {
            fetched = db.get_ip_order(r.ip_order_id).await.ok();
            fetched.as_ref()
        }
    };
    AdminIpOrderRange {
        id: r.id,
        ip_order_id: r.ip_order_id,
        ip_range_id: r.ip_range_id,
        cidr: r.cidr,
        provider: order.map(|o| o.provider.clone()),
        cost: order.map(|o| o.cost),
        currency: order.map(|o| o.currency.clone()),
        released_at: r.released_at,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    region_id: Option<u64>,
    state: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CreateIpOrderRequest {
    pub provider: String,
    pub region_id: u64,
    pub country: Option<String>,
    pub destination: Option<String>,
    pub prefix_len: Option<u16>,
    pub quantity: Option<u32>,
    pub idempotency_key: Option<String>,
}

async fn admin_list_ip_orders(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<ListQuery>,
) -> ApiPaginatedResult<AdminIpOrder> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    let state = q
        .state
        .as_deref()
        .map(|s| s.parse::<IpOrderState>())
        .transpose()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .list_ip_orders(state, q.region_id, limit, offset)
        .await?;
    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

async fn admin_get_ip_order(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminIpOrderDetail> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    let order = this.db.get_ip_order(id).await?;
    let mut ranges = vec![];
    for r in this.db.list_ip_order_ranges_for_order(id).await? {
        ranges.push(range_view(this.db.as_ref(), r, Some(&order)).await);
    }
    let audit = this
        .db
        .list_ip_order_audit(id)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    ApiData::ok(AdminIpOrderDetail {
        order: order.into(),
        ranges,
        audit,
    })
}

async fn admin_create_ip_order(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateIpOrderRequest>,
) -> ApiResult<AdminIpOrder> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Create)?;
    let (order, created) = create_ip_order(
        this.db.as_ref(),
        NewIpOrder {
            provider: req.provider,
            region_id: req.region_id,
            country: req.country,
            destination: req.destination,
            prefix_len: req.prefix_len.unwrap_or(32),
            quantity: req.quantity.unwrap_or(1),
            idempotency_key: req.idempotency_key,
            auto: false,
            requested_by: Some(auth.user_id),
        },
    )
    .await
    .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if created {
        this.work_commander
            .send(WorkJob::ProcessIpOrder { order_id: order.id })
            .await?;
    }
    ApiData::ok(order.into())
}

async fn admin_approve_ip_order(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminIpOrder> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Update)?;
    let order = approve_ip_order(this.db.as_ref(), id, auth.user_id)
        .await
        .map_err(|e| ApiError::conflict(e.to_string()))?;
    this.work_commander
        .send(WorkJob::ProcessIpOrder { order_id: id })
        .await?;
    ApiData::ok(order.into())
}

async fn admin_reject_ip_order(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminIpOrder> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Update)?;
    let order = reject_ip_order(this.db.as_ref(), id, auth.user_id)
        .await
        .map_err(|e| ApiError::conflict(e.to_string()))?;
    ApiData::ok(order.into())
}

async fn admin_list_ip_order_ranges(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<ListQuery>,
) -> ApiPaginatedResult<AdminIpOrderRange> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this.db.list_ip_order_ranges(limit, offset).await?;
    let mut out = vec![];
    for r in rows {
        out.push(range_view(this.db.as_ref(), r, None).await);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_release_ip_range(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<JobResponse> {
    auth.require_permission(AdminResource::IpOrder, AdminAction::Delete)?;
    let link = this
        .db
        .get_ip_order_range_by_range(id)
        .await?
        .ok_or_else(|| ApiError::bad_request("This range was not bought from a provider"))?;
    if link.released_at.is_some() {
        return Err(ApiError::conflict("This range has already been released"));
    }
    let allocated = this.db.list_vm_ip_assignments_in_range(id).await?.len();
    if allocated > 0 {
        return Err(ApiError::conflict(format!(
            "Range has {allocated} allocated IP(s) and cannot be released"
        )));
    }
    let job_id = this
        .work_commander
        .send(WorkJob::ReleaseIpRange {
            ip_range_id: id,
            admin_user_id: Some(auth.user_id),
        })
        .await?;
    ApiData::ok(JobResponse { job_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDbBase;

    #[tokio::test]
    async fn range_view_carries_provider_and_cost() {
        let db = MockDb::default();
        let id = db
            .insert_ip_order(&IpOrder {
                provider: "ovh".to_string(),
                region_id: 1,
                cost: 199,
                currency: "EUR".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        let link = IpOrderRange {
            id: 1,
            ip_order_id: id,
            ip_range_id: 5,
            cidr: "203.0.113.5/32".to_string(),
            released_at: None,
        };
        let view = range_view(&db, link, None).await;
        assert_eq!(view.provider.as_deref(), Some("ovh"));
        assert_eq!(view.cost, Some(199));
        assert_eq!(view.currency.as_deref(), Some("EUR"));
        assert_eq!(view.cidr, "203.0.113.5/32");
    }

    #[test]
    fn order_and_audit_convert_to_api_models() {
        let order = AdminIpOrder::from(IpOrder {
            id: 3,
            state: IpOrderState::Ordered,
            ..Default::default()
        });
        assert_eq!(order.id, 3);
        assert_eq!(serde_json::to_value(&order).unwrap()["state"], "ordered");
        let audit = AdminIpOrderAudit::from(IpOrderAudit {
            id: 1,
            ip_order_id: 3,
            event: "approved".to_string(),
            detail: None,
            actor_user_id: Some(2),
            created: Utc::now(),
        });
        assert_eq!(audit.event, "approved");
    }
}
