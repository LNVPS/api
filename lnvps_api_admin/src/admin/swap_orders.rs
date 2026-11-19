use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiPaginatedData, ApiPaginatedResult};
use lnvps_db::{AdminAction, AdminResource, SwapOrderClient};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/admin/v1/swap_orders", get(admin_list_swap_orders))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SwapOrderQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    order_id: Option<String>,
}

#[derive(Serialize)]
pub struct AdminSwapOrderClient {
    pub id: u64,
    pub user_id: u64,
    pub order_id: String,
    pub payment_id: String,
    pub coin: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub created: DateTime<Utc>,
}

impl From<SwapOrderClient> for AdminSwapOrderClient {
    fn from(r: SwapOrderClient) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            order_id: r.order_id,
            payment_id: hex::encode(r.payment_id),
            coin: r.coin,
            ip: r.ip,
            user_agent: r.user_agent,
            accept_language: r.accept_language,
            created: r.created,
        }
    }
}

async fn admin_list_swap_orders(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<SwapOrderQuery>,
) -> ApiPaginatedResult<AdminSwapOrderClient> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .admin_list_swap_order_clients(limit, offset, q.user_id, q.order_id.as_deref())
        .await?;
    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_order_client_serialises_payment_id_as_hex() {
        let out = AdminSwapOrderClient::from(SwapOrderClient {
            payment_id: vec![0xab, 0xcd],
            order_id: "XYZ".to_string(),
            ..Default::default()
        });
        assert_eq!(out.payment_id, "abcd");
        assert_eq!(out.order_id, "XYZ");
    }
}
