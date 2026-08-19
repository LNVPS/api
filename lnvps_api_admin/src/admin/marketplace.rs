//! Admin side of the marketplace: review registered hardware, approve it into
//! the fleet, and control what its operator is paid.
//!
//! Two resources, deliberately separate. [`AdminResource::MarketplaceNode`]
//! covers placement state — approve, suspend, drain, trust tier — and
//! [`AdminResource::MarketplaceOperator`] covers money: the revenue-share
//! override and the payout target. Stopping a misbehaving node at 3am should
//! not require the ability to change what somebody is paid.
//!
//! Approval is the only way a node becomes placeable, and it is the only place
//! the gates are enforced: a paid listing fee (decision 16) and a pinned TLS
//! certificate (decision 14). Everything else can move a node *out* of the
//! approved state, never into it.

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

use lnvps_api_common::node_control::NodeStatus;
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery,
    deserialize_from_str_optional,
};
use lnvps_db::{
    AdminAction, AdminResource, LNVpsDb, MarketplaceNode, MarketplaceNodeStatus,
    MarketplaceOperator, MarketplaceTrustTier, PayoutMode, VmHost, VmHostKind,
};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/admin/v1/marketplace/nodes", get(admin_list_nodes))
        .route(
            "/api/admin/v1/marketplace/nodes/{id}",
            get(admin_get_node)
                .patch(admin_update_node)
                .delete(admin_delete_node),
        )
        .route(
            "/api/admin/v1/marketplace/nodes/{id}/approve",
            post(admin_approve_node),
        )
        .route(
            "/api/admin/v1/marketplace/nodes/{id}/status",
            get(admin_node_status),
        )
        .route(
            "/api/admin/v1/marketplace/nodes/{id}/health",
            get(admin_node_health),
        )
        .route(
            "/api/admin/v1/marketplace/operators",
            get(admin_list_operators),
        )
        .route(
            "/api/admin/v1/marketplace/operators/{id}",
            get(admin_get_operator).patch(admin_update_operator),
        )
}

/// One probe's findings.
#[derive(Serialize, Debug)]
pub struct AdminNodeHealthInfo {
    pub id: u64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub passed: bool,
    /// Why it failed, in the words of whatever failed. Verbatim: an admin
    /// deciding whether to suspend somebody's node needs what actually
    /// happened, not a category.
    pub failure: Option<String>,
    /// Asking for the VM to being able to log in — what a customer waits.
    pub provision_ms: Option<u32>,
    /// Memory the guest allocated *and touched*, in MB.
    pub memory_mb: Option<u32>,
    pub disk_write_mb: Option<u32>,
    pub disk_read_mb: Option<u32>,
    /// What was asked for, so the numbers above can be read. Regions sell
    /// different shapes, and raw seconds across different ones rank machines by
    /// what we happened to request rather than by how good they are.
    pub cpu: u16,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub image: String,
}

impl From<lnvps_db::MarketplaceNodeHealth> for AdminNodeHealthInfo {
    fn from(h: lnvps_db::MarketplaceNodeHealth) -> Self {
        Self {
            id: h.id,
            created: h.created,
            passed: h.passed,
            failure: h.failure,
            provision_ms: h.provision_ms,
            memory_mb: h.memory_mb,
            disk_write_mb: h.disk_write_mb,
            disk_read_mb: h.disk_read_mb,
            cpu: h.cpu,
            memory_bytes: h.memory_bytes,
            disk_bytes: h.disk_bytes,
            image: h.image,
        }
    }
}

/// A registered node as an admin sees it.
#[derive(Serialize, Debug)]
pub struct AdminMarketplaceNodeInfo {
    pub id: u64,
    pub operator_id: u64,
    /// The account behind the operator enrolment, so an admin reviewing
    /// hardware can see whose it is without a second lookup.
    pub operator_user_id: u64,
    pub operator_pubkey: String,
    pub name: String,
    /// `pending`, `approved`, `suspended` or `draining`.
    pub status: String,
    /// `untrusted`, `verified` or `partner`.
    pub trust_tier: String,
    /// SHA-256 of the certificate the node's control API serves, hex. `null`
    /// means the node cannot be reached and cannot be approved.
    pub tls_fingerprint: Option<String>,
    /// The node's data-plane tunnel, once one is allocated.
    pub tunnel_id: Option<u64>,
    /// The backing host row, created by approval. `null` before then.
    pub host_id: Option<u64>,
    /// Whether the one-off listing fee has been paid. `false` also covers "not
    /// started" — either way there is nothing to approve against.
    pub fee_paid: bool,
    /// The subscription billing the listing fee, once the operator starts it.
    pub fee_subscription_id: Option<u64>,
    pub last_seen: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
}

/// An operator enrolment as an admin sees it.
#[derive(Serialize, Debug)]
pub struct AdminMarketplaceOperatorInfo {
    pub id: u64,
    pub user_id: u64,
    pub user_pubkey: String,
    /// Payout target; its meaning depends on `mode`.
    pub address: Option<String>,
    /// `lightning_address`, `nwc`, `account_credit` or `on_chain`.
    pub mode: String,
    /// Minimum accrued earnings (satoshis) before an automated payout runs.
    pub payout_threshold: Option<u64>,
    /// Revenue-share override as a whole percentage; `null` means the company
    /// default applies.
    pub rate: Option<f32>,
    pub enabled: bool,
    /// How many nodes this operator has registered.
    pub node_count: u64,
    pub created: DateTime<Utc>,
}

/// Filters for the node review queue.
#[derive(Deserialize, Default)]
#[serde(default)]
struct ListNodesQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    /// Restrict to one lifecycle state, e.g. `pending` for the review queue.
    status: Option<String>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    operator_id: Option<u64>,
}

/// Approve a node into the fleet.
#[derive(Deserialize, Debug)]
pub struct AdminApproveNodeRequest {
    /// Region the backing host is created in. Required for a node that has
    /// never been approved; ignored when re-approving one that already has a
    /// host, because moving a host between regions would move its IP space
    /// along with it.
    pub region_id: Option<u64>,
    /// Host name. Defaults to the node's own label, which is the operator's
    /// and need not be unique or meaningful to LNVPS.
    pub name: Option<String>,
    /// Trust tier to grant. Omitted leaves whatever the node already has,
    /// which for a fresh registration is `untrusted`.
    pub trust_tier: Option<String>,
    /// Total CPU cores the host may sell. Defaults to 0, which is a host that
    /// takes nothing: real figures arrive with node telemetry, and guessing
    /// them here would oversell hardware nobody has measured.
    pub cpu: Option<u16>,
    /// Total memory in bytes. Defaults to 0, for the same reason as `cpu`.
    pub memory: Option<u64>,
    /// Overcommit factors, defaulting to 1.0 (no overcommit). Untrusted
    /// hardware is not a good place to oversubscribe.
    pub load_cpu: Option<f32>,
    pub load_memory: Option<f32>,
    pub load_disk: Option<f32>,
}

/// Change a node's placement state or trust tier.
///
/// Deliberately cannot set `approved`: that transition runs the fee and
/// certificate gates, and lives in [`admin_approve_node`] alone.
#[derive(Deserialize, Debug, Default)]
pub struct AdminUpdateNodeRequest {
    /// `suspended` or `draining`.
    pub status: Option<String>,
    /// `untrusted`, `verified` or `partner`.
    pub trust_tier: Option<String>,
}

/// Change an operator's revenue share or payout configuration.
#[derive(Deserialize, Debug, Default)]
pub struct AdminUpdateOperatorRequest {
    /// Set (`Some(Some(rate))`) or clear (`Some(None)`) the per-operator
    /// revenue-share override, as a whole percentage. Clearing it falls back to
    /// `company.marketplace_rate`.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub rate: Option<Option<f32>>,
    /// Set or clear the minimum accrued earnings before an automated payout.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub payout_threshold: Option<Option<u64>>,
    /// Payout target address.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub address: Option<Option<String>>,
    /// Payout rail: `lightning_address`, `nwc`, `account_credit` or `on_chain`.
    pub mode: Option<String>,
    /// Stop or resume placement across every node this operator owns, without
    /// deleting anything or withholding earnings already accrued.
    pub enabled: Option<bool>,
}

/// Build the admin view of a node, resolving the operator, its backing host and
/// whether the listing fee has actually been paid.
async fn node_info(
    db: &Arc<dyn LNVpsDb>,
    node: MarketplaceNode,
) -> Result<AdminMarketplaceNodeInfo, ApiError> {
    let operator = db.get_marketplace_operator(node.operator_id).await?;
    let user = db.get_user(operator.user_id).await?;
    let host = db.get_marketplace_node_host(node.id).await?;
    let (fee_paid, fee_subscription_id) = fee_state(db, &node).await?;

    Ok(AdminMarketplaceNodeInfo {
        id: node.id,
        operator_id: node.operator_id,
        operator_user_id: operator.user_id,
        operator_pubkey: hex::encode(user.pubkey),
        name: node.name,
        status: node.status.to_string(),
        trust_tier: node.trust_tier.to_string(),
        tls_fingerprint: node.tls_fingerprint.map(hex::encode),
        tunnel_id: node.tunnel_id,
        host_id: host.map(|h| h.id),
        fee_paid,
        fee_subscription_id,
        last_seen: node.last_seen,
        created: node.created,
    })
}

/// Whether a node's listing fee is paid, and which subscription bills it.
///
/// A one-off fee never gets an expiry, so `is_setup` — set by the same update
/// that records the payment — is the only flag that says it was paid.
async fn fee_state(
    db: &Arc<dyn LNVpsDb>,
    node: &MarketplaceNode,
) -> Result<(bool, Option<u64>), ApiError> {
    let Some(line_item_id) = node.subscription_line_item_id else {
        return Ok((false, None));
    };
    let line_item = db.get_subscription_line_item(line_item_id).await?;
    let subscription = db.get_subscription(line_item.subscription_id).await?;
    Ok((subscription.is_setup, Some(subscription.id)))
}

async fn operator_info(
    db: &Arc<dyn LNVpsDb>,
    operator: MarketplaceOperator,
) -> Result<AdminMarketplaceOperatorInfo, ApiError> {
    let user = db.get_user(operator.user_id).await?;
    let node_count = db.list_marketplace_nodes(operator.id).await?.len() as u64;
    Ok(AdminMarketplaceOperatorInfo {
        id: operator.id,
        user_id: operator.user_id,
        user_pubkey: hex::encode(user.pubkey),
        address: operator.address,
        mode: operator.mode.to_string(),
        payout_threshold: operator.payout_threshold,
        rate: operator.rate,
        enabled: operator.enabled,
        node_count,
        created: operator.created,
    })
}

/// List registered nodes, newest first.
async fn admin_list_nodes(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListNodesQuery>,
) -> ApiPaginatedResult<AdminMarketplaceNodeInfo> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let status = match params
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(
            MarketplaceNodeStatus::from_str(s).map_err(|e| ApiError::bad_request(e.to_string()))?,
        ),
        None => None,
    };

    let (rows, total) = this
        .db
        .admin_list_marketplace_nodes_paginated(limit, offset, status, params.operator_id)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for node in rows {
        out.push(node_info(&this.db, node).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_node(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminMarketplaceNodeInfo> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::View)?;
    let node = this.db.get_marketplace_node(id).await?;
    ApiData::ok(node_info(&this.db, node).await?)
}

/// Ask a node how it is, right now.
///
/// Live rather than remembered: the stored `last_seen` says a node was there,
/// which is the question nobody is asking when a customer's VM is unreachable.
/// This is also the only way to see a node's data plane before it has been
/// enabled, which is what an operator debugging a failed approval needs.
/// A node's probe history, newest first.
///
/// A series rather than a verdict, because that is the question an admin
/// actually has: one bad run is a bad afternoon, and a node worth suspending is
/// one whose numbers have been getting worse. Paged at the database — a node
/// probed every six hours for a year is over a thousand rows.
///
/// Remembered rather than live, unlike `/status`: these are measurements that
/// were made, and re-running one on demand would put load on an operator's
/// machine because somebody opened a page.
async fn admin_node_health(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminNodeHealthInfo> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::View)?;
    // Checked so an unknown node is a 404 rather than an empty series, which
    // reads as "this node has never been probed".
    let node = this.db.get_marketplace_node(id).await?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .list_marketplace_node_health(node.id, limit, offset)
        .await?;

    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total.max(0) as u64,
        limit,
        offset,
    )
}

async fn admin_node_status(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<NodeStatus> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::View)?;
    let node = this.db.get_marketplace_node(id).await?;
    let host = this
        .db
        .get_marketplace_node_host(node.id)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request(
                "This node has not been approved, so it has no host and no control address",
            )
        })?;
    let control = this.node_control.as_ref().ok_or_else(|| {
        ApiError::bad_request(
            "This deployment has no marketplace control key configured, so no node can be called",
        )
    })?;

    // The node's own failure, verbatim: "connection refused", "certificate does
    // not match the pin", "clock is 400s out". Each sends an operator somewhere
    // different, and a generic 502 sends them nowhere.
    let status = control
        .status(&node, &host)
        .await
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    ApiData::ok(status)
}

/// Approve a node: create its backing host and make it placeable.
async fn admin_approve_node(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminApproveNodeRequest>,
) -> ApiResult<AdminMarketplaceNodeInfo> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::Update)?;
    let node = approve_node(&this.db, id, &req).await?;
    ApiData::ok(node_info(&this.db, node).await?)
}

/// The approval itself, without the extractors, so the gates can be tested
/// against a database rather than only through a running server.
pub(crate) async fn approve_node(
    db: &Arc<dyn LNVpsDb>,
    id: u64,
    req: &AdminApproveNodeRequest,
) -> Result<MarketplaceNode, ApiError> {
    let node = db.get_marketplace_node(id).await?;

    // Without a pinned certificate every control call to this node fails
    // closed, so approving it would produce a host that accepts placements and
    // can never be told to do anything.
    if node.tls_fingerprint.is_none() {
        return Err(ApiError::bad_request(
            "This node has no pinned TLS certificate, so it cannot be reached. \
             It must re-register before it can be approved.",
        ));
    }

    let trust_tier = match req.trust_tier.as_deref() {
        Some(t) => {
            MarketplaceTrustTier::from_str(t).map_err(|e| ApiError::bad_request(e.to_string()))?
        }
        None => node.trust_tier,
    };

    // A node approved before is being un-suspended, not listed again: it has a
    // host, its fee was collected then, and its region is settled.
    let existing_host = db.get_marketplace_node_host(node.id).await?;

    if existing_host.is_none() {
        let region_id = req.region_id.ok_or_else(|| {
            ApiError::bad_request("region_id is required when approving a node for the first time")
        })?;
        let region = db.get_host_region(region_id).await?;
        let company = db.get_company(region.company_id).await?;

        // The fee is per node and non-refundable, and it is charged in the
        // company that will sell the capacity. Approving against a paid fee
        // from a different company would let an operator pay whichever
        // company charges least and list anywhere.
        if company.marketplace_node_fee > 0 {
            let (paid, subscription_id) = fee_state(db, &node).await?;
            if !paid {
                return Err(ApiError::bad_request(
                    "The listing fee for this node has not been paid",
                ));
            }
            let subscription_id = subscription_id.expect("a paid fee has a subscription");
            let subscription = db.get_subscription(subscription_id).await?;
            if subscription.company_id != region.company_id {
                return Err(ApiError::bad_request(
                    "The listing fee for this node was paid to a different company than the \
                     region it is being approved into",
                ));
            }
        }

        let name = req
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .unwrap_or(node.name.as_str())
            .to_string();

        db.create_host(&VmHost {
            id: 0,
            kind: VmHostKind::MarketplaceNode,
            region_id,
            name,
            // The control endpoint is the node's tunnel address, which does not
            // exist until the data plane is allocated. It is left blank on
            // purpose, and the host stays disabled until then — a blank address
            // must be a hard error wherever a host is dialled, never a silent
            // fallback to some default.
            ip: String::new(),
            cpu: req.cpu.unwrap_or(0),
            memory: req.memory.unwrap_or(0),
            // Approval does not switch the host on. Networking, attestation and
            // the first telemetry all have to land first.
            enabled: false,
            // There is no API token: the node authenticates LNVPS by the pinned
            // control pubkey, and LNVPS authenticates the node by its pinned
            // certificate. A token here would be a secret nothing reads.
            api_token: String::new().into(),
            load_cpu: req.load_cpu.unwrap_or(1.0),
            load_memory: req.load_memory.unwrap_or(1.0),
            load_disk: req.load_disk.unwrap_or(1.0),
            marketplace_node_id: Some(node.id),
            ..Default::default()
        })
        .await?;
    }

    let approved = MarketplaceNode {
        status: MarketplaceNodeStatus::Approved,
        trust_tier,
        ..node
    };
    db.update_marketplace_node(&approved).await?;
    Ok(db.get_marketplace_node(approved.id).await?)
}

/// Suspend, drain, or re-tier a node.
async fn admin_update_node(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateNodeRequest>,
) -> ApiResult<AdminMarketplaceNodeInfo> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::Update)?;
    let node = update_node(&this.db, id, &req).await?;
    ApiData::ok(node_info(&this.db, node).await?)
}

pub(crate) async fn update_node(
    db: &Arc<dyn LNVpsDb>,
    id: u64,
    req: &AdminUpdateNodeRequest,
) -> Result<MarketplaceNode, ApiError> {
    let node = db.get_marketplace_node(id).await?;

    let status = match req.status.as_deref() {
        Some(s) => {
            let status = MarketplaceNodeStatus::from_str(s)
                .map_err(|e| ApiError::bad_request(e.to_string()))?;
            // Approval is the only path that checks the fee and the pinned
            // certificate. Letting this endpoint set `approved` would be a way
            // around both.
            if status.accepts_placement() {
                return Err(ApiError::bad_request(
                    "Use the approve endpoint to make a node placeable",
                ));
            }
            status
        }
        None => node.status,
    };
    let trust_tier = match req.trust_tier.as_deref() {
        Some(t) => {
            MarketplaceTrustTier::from_str(t).map_err(|e| ApiError::bad_request(e.to_string()))?
        }
        None => node.trust_tier,
    };

    let updated = MarketplaceNode {
        status,
        trust_tier,
        ..node
    };
    db.update_marketplace_node(&updated).await?;

    // Suspension and draining have to stop placement now, not once increment 7
    // teaches the scheduler about node status: the host row is what the
    // provisioner reads.
    if !updated.status.accepts_placement()
        && let Some(mut host) = db.get_marketplace_node_host(updated.id).await?
        && host.enabled
    {
        host.enabled = false;
        db.update_host(&host).await?;
    }

    Ok(db.get_marketplace_node(updated.id).await?)
}

/// Reject a registration, or remove a node that has been offboarded.
///
/// There is no `rejected` state: the registration is deleted, so an operator
/// whose hardware was turned away can fix whatever was wrong and register the
/// same machine again. A node still backing a host cannot be deleted — that
/// host has to be detached first, which is what offboarding does.
async fn admin_delete_node(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::MarketplaceNode, AdminAction::Delete)?;

    // Fetch first so a missing node is a 404 rather than a silent success.
    let node = this.db.get_marketplace_node(id).await?;
    if this.db.get_marketplace_node_host(node.id).await?.is_some() {
        return Err(ApiError::bad_request(
            "This node still backs a host. Drain it and remove the host before deleting the node.",
        ));
    }
    this.db.delete_marketplace_node(node.id).await?;
    ApiData::ok(())
}

async fn admin_list_operators(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminMarketplaceOperatorInfo> {
    auth.require_permission(AdminResource::MarketplaceOperator, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .admin_list_marketplace_operators_paginated(limit, offset)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for operator in rows {
        out.push(operator_info(&this.db, operator).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_operator(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminMarketplaceOperatorInfo> {
    auth.require_permission(AdminResource::MarketplaceOperator, AdminAction::View)?;
    let operator = this.db.get_marketplace_operator(id).await?;
    ApiData::ok(operator_info(&this.db, operator).await?)
}

async fn admin_update_operator(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateOperatorRequest>,
) -> ApiResult<AdminMarketplaceOperatorInfo> {
    auth.require_permission(AdminResource::MarketplaceOperator, AdminAction::Update)?;
    let operator = update_operator(&this.db, id, &req).await?;
    ApiData::ok(operator_info(&this.db, operator).await?)
}

pub(crate) async fn update_operator(
    db: &Arc<dyn LNVpsDb>,
    id: u64,
    req: &AdminUpdateOperatorRequest,
) -> Result<MarketplaceOperator, ApiError> {
    let mut operator = db.get_marketplace_operator(id).await?;

    if let Some(rate) = req.rate {
        // A negative share would pay LNVPS out of the operator's pocket, and
        // one over 100% would pay out more than the invoice was worth.
        if let Some(r) = rate
            && !(0.0..=100.0).contains(&r)
        {
            return Err(ApiError::bad_request(
                "rate must be between 0 and 100 percent",
            ));
        }
        operator.rate = rate;
    }
    if let Some(threshold) = req.payout_threshold {
        operator.payout_threshold = threshold;
    }
    if let Some(address) = &req.address {
        operator.address = address
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_string);
    }
    if let Some(mode) = &req.mode {
        operator.mode =
            PayoutMode::from_str(mode).map_err(|e| ApiError::bad_request(e.to_string()))?;
    }
    if let Some(enabled) = req.enabled {
        operator.enabled = enabled;
    }

    db.update_marketplace_operator(&operator).await?;
    Ok(db.get_marketplace_operator(id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lnvps_api_common::MockDb;
    use lnvps_db::{Company, IntervalType, Subscription, SubscriptionLineItem, SubscriptionType};

    use crate::admin::model::Permission;
    use lnvps_api_common::node_control::NodeStatus;
    use lnvps_api_common::{ChannelWorkCommander, MockExchangeRate, VatClient, VmStateCache};

    const FINGERPRINT: [u8; 32] = [0xab; 32];

    pub(super) fn state(db: &Arc<dyn LNVpsDb>) -> RouterState {
        RouterState {
            node_control: None,
            db: db.clone(),
            work_commander: Arc::new(ChannelWorkCommander::new()),
            feedback: None,
            vm_state_cache: VmStateCache::new(),
            exchange: Arc::new(MockExchangeRate::default()),
            vat: VatClient::new(),
        }
    }

    /// An admin holding every action on one marketplace resource and nothing on
    /// the other — which is the split the two resources exist to make.
    pub(super) fn auth_for(resource: AdminResource) -> AdminAuth {
        AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: [
                AdminAction::View,
                AdminAction::Create,
                AdminAction::Update,
                AdminAction::Delete,
            ]
            .into_iter()
            .map(|action| Permission { resource, action })
            .collect(),
            nip98_auth: None,
        }
    }

    /// A database with one operator, one registered node and a company that
    /// charges `fee` to list it.
    pub(super) async fn fixture(fee: u64) -> (Arc<dyn LNVpsDb>, u64) {
        let mock = MockDb::default();
        mock.set_marketplace_node_fee(1, fee).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);

        let user_id = db.upsert_user(&[7u8; 32]).await.unwrap();
        let operator_id = db
            .insert_marketplace_operator(&MarketplaceOperator {
                user_id,
                enabled: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let node_id = db
            .insert_marketplace_node(&MarketplaceNode {
                operator_id,
                name: "rack 1".to_string(),
                tls_fingerprint: Some(FINGERPRINT.to_vec()),
                status: MarketplaceNodeStatus::Pending,
                ..Default::default()
            })
            .await
            .unwrap();
        (db, node_id)
    }

    fn approve(region_id: u64) -> AdminApproveNodeRequest {
        AdminApproveNodeRequest {
            region_id: Some(region_id),
            name: None,
            trust_tier: None,
            cpu: None,
            memory: None,
            load_cpu: None,
            load_memory: None,
            load_disk: None,
        }
    }

    /// Bill a node's listing fee against `company_id`, optionally settling it
    /// the way a Lightning payment would.
    async fn bill_fee(db: &Arc<dyn LNVpsDb>, node_id: u64, company_id: u64, paid: bool) {
        let mut node = db.get_marketplace_node(node_id).await.unwrap();
        let operator = db.get_marketplace_operator(node.operator_id).await.unwrap();
        let (subscription_id, line_items) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id: operator.user_id,
                    company_id,
                    name: "fee".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: false,
                    is_setup: false,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 5000,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::MarketplaceNodeFee,
                    name: "fee".to_string(),
                    description: None,
                    amount: 0,
                    setup_amount: 5000,
                    configuration: None,
                }],
            )
            .await
            .unwrap();

        if paid {
            let mut subscription = db.get_subscription(subscription_id).await.unwrap();
            // What payment sets for a one-off: no expiry, `is_setup` true.
            subscription.is_setup = true;
            subscription.is_active = true;
            db.update_subscription(&subscription).await.unwrap();
        }

        node.subscription_line_item_id = Some(line_items[0]);
        db.update_marketplace_node(&node).await.unwrap();
    }

    /// A second company with its own region, for the "paid somewhere cheaper"
    /// case.
    async fn second_region(db: &Arc<dyn LNVpsDb>) -> u64 {
        let company_id = db
            .admin_create_company(&Company {
                name: "Other Company".to_string(),
                base_currency: "EUR".to_string(),
                marketplace_node_fee: 5000,
                created: Utc::now(),
                ..Default::default()
            })
            .await
            .unwrap();
        db.admin_create_region("other", true, company_id)
            .await
            .unwrap()
    }

    /// Approval is what creates the backing host, and it must arrive switched
    /// off with no control endpoint: the address only exists once the data
    /// plane is allocated.
    #[tokio::test]
    async fn approving_creates_a_disabled_host_bound_to_the_node() {
        let (db, node_id) = fixture(0).await;

        let node = approve_node(&db, node_id, &approve(1)).await.unwrap();
        assert_eq!(node.status, MarketplaceNodeStatus::Approved);

        let host = db
            .get_marketplace_node_host(node_id)
            .await
            .unwrap()
            .expect("approval did not create a host");
        assert_eq!(host.kind, VmHostKind::MarketplaceNode);
        assert_eq!(host.marketplace_node_id, Some(node_id));
        assert!(
            !host.enabled,
            "an approved node must not take VMs before its tunnel exists"
        );
        assert!(
            host.ip.is_empty(),
            "a host with no tunnel must have no control endpoint"
        );
        assert_eq!(
            host.name, "rack 1",
            "the host should fall back to the node's own label"
        );
        assert_eq!(
            host.cpu, 0,
            "capacity must come from telemetry, not from a guess at approval time"
        );
    }

    /// The operator's label is theirs and need not mean anything to LNVPS, so
    /// an admin can name the host — but a blank name is a fallback, not a host
    /// with no name at all.
    #[tokio::test]
    async fn an_admin_can_name_the_host_but_cannot_leave_it_blank() {
        let (db, node_id) = fixture(0).await;
        approve_node(
            &db,
            node_id,
            &AdminApproveNodeRequest {
                name: Some("  lon-community-3  ".to_string()),
                ..approve(1)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.get_marketplace_node_host(node_id)
                .await
                .unwrap()
                .unwrap()
                .name,
            "lon-community-3"
        );

        let (db, node_id) = fixture(0).await;
        approve_node(
            &db,
            node_id,
            &AdminApproveNodeRequest {
                name: Some("   ".to_string()),
                ..approve(1)
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.get_marketplace_node_host(node_id)
                .await
                .unwrap()
                .unwrap()
                .name,
            "rack 1"
        );
    }

    /// The fee gate is the whole point of decision 16: hardware is reviewed for
    /// free, and paid for before it can earn.
    #[tokio::test]
    async fn an_unpaid_node_cannot_be_approved() {
        let (db, node_id) = fixture(5000).await;

        let err = approve_node(&db, node_id, &approve(1))
            .await
            .expect_err("approved a node whose listing fee was never paid");
        assert!(format!("{err:?}").contains("listing fee"), "{err:?}");
        assert!(
            db.get_marketplace_node_host(node_id)
                .await
                .unwrap()
                .is_none(),
            "a refused approval must not leave a host behind"
        );

        // Started but not settled is still unpaid.
        bill_fee(&db, node_id, 1, false).await;
        assert!(
            approve_node(&db, node_id, &approve(1)).await.is_err(),
            "an unpaid invoice was treated as payment"
        );

        bill_fee(&db, node_id, 1, true).await;
        approve_node(&db, node_id, &approve(1)).await.unwrap();
    }

    /// One payment must not list hardware in a company that never received it.
    #[tokio::test]
    async fn a_fee_paid_to_one_company_does_not_list_a_node_in_another() {
        let (db, node_id) = fixture(5000).await;
        let other_region = second_region(&db).await;
        bill_fee(&db, node_id, 1, true).await;

        let err = approve_node(&db, node_id, &approve(other_region))
            .await
            .expect_err("a fee paid to one company approved a node in another");
        assert!(format!("{err:?}").contains("different company"), "{err:?}");

        // The company that was actually paid still works.
        approve_node(&db, node_id, &approve(1)).await.unwrap();
    }

    /// Without a pinned certificate every control call fails closed, so the
    /// host would accept placements it could never act on.
    #[tokio::test]
    async fn a_node_with_no_pinned_certificate_cannot_be_approved() {
        let (db, node_id) = fixture(0).await;
        let mut node = db.get_marketplace_node(node_id).await.unwrap();
        node.tls_fingerprint = None;
        db.update_marketplace_node(&node).await.unwrap();

        let err = approve_node(&db, node_id, &approve(1))
            .await
            .expect_err("approved a node that cannot be reached");
        assert!(format!("{err:?}").contains("TLS certificate"), "{err:?}");
    }

    /// Re-approving a suspended node is an un-suspension, not a second listing:
    /// it must not create a second host, or charge again.
    #[tokio::test]
    async fn re_approving_reuses_the_existing_host() {
        let (db, node_id) = fixture(5000).await;
        bill_fee(&db, node_id, 1, true).await;
        approve_node(&db, node_id, &approve(1)).await.unwrap();
        let host_id = db
            .get_marketplace_node_host(node_id)
            .await
            .unwrap()
            .unwrap()
            .id;

        update_node(
            &db,
            node_id,
            &AdminUpdateNodeRequest {
                status: Some("suspended".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // No region this time: the host already has one, and moving it would
        // move its IP space too.
        let node = approve_node(
            &db,
            node_id,
            &AdminApproveNodeRequest {
                region_id: None,
                ..approve(1)
            },
        )
        .await
        .unwrap();
        assert_eq!(node.status, MarketplaceNodeStatus::Approved);
        assert_eq!(
            db.get_marketplace_node_host(node_id)
                .await
                .unwrap()
                .unwrap()
                .id,
            host_id,
            "re-approval created a second host"
        );
    }

    /// A first approval has nowhere to put the host without a region, and a
    /// silent default would list hardware in whichever region happened to be
    /// first.
    #[tokio::test]
    async fn a_first_approval_needs_a_region() {
        let (db, node_id) = fixture(0).await;
        let err = approve_node(
            &db,
            node_id,
            &AdminApproveNodeRequest {
                region_id: None,
                ..approve(1)
            },
        )
        .await
        .expect_err("a node was approved into no region at all");
        assert!(format!("{err:?}").contains("region_id"), "{err:?}");
    }

    /// Suspension has to stop placement immediately. The provisioner reads the
    /// host row, so disabling the node without disabling the host would leave a
    /// suspended machine still taking VMs.
    #[tokio::test]
    async fn suspending_disables_the_backing_host() {
        let (db, node_id) = fixture(0).await;
        approve_node(&db, node_id, &approve(1)).await.unwrap();

        // Stand in for increment 4 having switched the host on.
        let mut host = db
            .get_marketplace_node_host(node_id)
            .await
            .unwrap()
            .unwrap();
        host.enabled = true;
        db.update_host(&host).await.unwrap();

        for status in ["suspended", "draining"] {
            let mut host = db
                .get_marketplace_node_host(node_id)
                .await
                .unwrap()
                .unwrap();
            host.enabled = true;
            db.update_host(&host).await.unwrap();

            let node = update_node(
                &db,
                node_id,
                &AdminUpdateNodeRequest {
                    status: Some(status.to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(node.status.to_string(), status);
            assert!(
                !db.get_marketplace_node_host(node_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .enabled,
                "a {status} node was left taking placements"
            );
        }
    }

    /// The status endpoint must not be a way past the fee and certificate
    /// checks, which only the approval path makes.
    #[tokio::test]
    async fn a_node_cannot_be_approved_through_the_status_endpoint() {
        let (db, node_id) = fixture(5000).await;

        let err = update_node(
            &db,
            node_id,
            &AdminUpdateNodeRequest {
                status: Some("approved".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect_err("an unpaid node was approved without passing the gates");
        assert!(format!("{err:?}").contains("approve endpoint"), "{err:?}");

        assert_eq!(
            db.get_marketplace_node(node_id).await.unwrap().status,
            MarketplaceNodeStatus::Pending
        );
    }

    /// A spelling nobody defined must be refused, not silently mapped to a
    /// default — "offline" is not "suspended", and a rejected payout rail is
    /// better than paying to the wrong kind of address.
    #[tokio::test]
    async fn unknown_enum_spellings_are_refused_rather_than_defaulted() {
        let (db, node_id) = fixture(0).await;
        let operator_id = db.get_marketplace_node(node_id).await.unwrap().operator_id;

        for req in [
            AdminUpdateNodeRequest {
                status: Some("offline".to_string()),
                ..Default::default()
            },
            AdminUpdateNodeRequest {
                trust_tier: Some("trusted".to_string()),
                ..Default::default()
            },
        ] {
            assert!(
                update_node(&db, node_id, &req).await.is_err(),
                "accepted {req:?}"
            );
        }
        assert_eq!(
            db.get_marketplace_node(node_id).await.unwrap().status,
            MarketplaceNodeStatus::Pending
        );

        assert!(
            update_operator(
                &db,
                operator_id,
                &AdminUpdateOperatorRequest {
                    mode: Some("paypal".to_string()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
        );
    }

    /// Trust tier is placement policy and moves independently of status.
    #[tokio::test]
    async fn trust_tier_can_be_changed_without_touching_status() {
        let (db, node_id) = fixture(0).await;
        let node = update_node(
            &db,
            node_id,
            &AdminUpdateNodeRequest {
                status: None,
                trust_tier: Some("partner".to_string()),
            },
        )
        .await
        .unwrap();
        assert_eq!(node.trust_tier, MarketplaceTrustTier::Partner);
        assert_eq!(node.status, MarketplaceNodeStatus::Pending);
    }

    /// A revenue share outside 0–100% pays the operator out of thin air, or
    /// bills them for hosting.
    #[tokio::test]
    async fn an_impossible_revenue_share_is_refused() {
        let (db, node_id) = fixture(0).await;
        let operator_id = db.get_marketplace_node(node_id).await.unwrap().operator_id;

        for rate in [-1.0f32, 101.0] {
            assert!(
                update_operator(
                    &db,
                    operator_id,
                    &AdminUpdateOperatorRequest {
                        rate: Some(Some(rate)),
                        ..Default::default()
                    }
                )
                .await
                .is_err(),
                "a {rate}% revenue share was accepted"
            );
        }

        let operator = update_operator(
            &db,
            operator_id,
            &AdminUpdateOperatorRequest {
                rate: Some(Some(30.0)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(operator.rate, Some(30.0));

        // Clearing it falls back to the company default, which is the same
        // override-then-default shape referrals use.
        let operator = update_operator(
            &db,
            operator_id,
            &AdminUpdateOperatorRequest {
                rate: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(operator.rate, None);
    }

    /// An omitted field must leave its value alone, or a rename would silently
    /// reset somebody's payout address.
    #[tokio::test]
    async fn omitted_operator_fields_are_left_alone() {
        let (db, node_id) = fixture(0).await;
        let operator_id = db.get_marketplace_node(node_id).await.unwrap().operator_id;

        update_operator(
            &db,
            operator_id,
            &AdminUpdateOperatorRequest {
                address: Some(Some("operator@example.com".to_string())),
                mode: Some("lightning_address".to_string()),
                payout_threshold: Some(Some(10_000)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let operator = update_operator(
            &db,
            operator_id,
            &AdminUpdateOperatorRequest {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(operator.address.as_deref(), Some("operator@example.com"));
        assert_eq!(operator.payout_threshold, Some(10_000));
        assert_eq!(operator.mode, PayoutMode::LightningAddress);
        assert!(!operator.enabled);
    }

    /// The admin view has to answer "can this be approved?" without a second
    /// round trip: whose hardware it is, whether the fee settled, and whether
    /// there is a host yet.
    #[tokio::test]
    async fn the_admin_view_resolves_operator_fee_and_host() {
        let (db, node_id) = fixture(5000).await;
        let node = db.get_marketplace_node(node_id).await.unwrap();

        let before = node_info(&db, node.clone()).await.unwrap();
        assert_eq!(before.operator_pubkey, hex::encode([7u8; 32]));
        assert_eq!(before.tls_fingerprint, Some(hex::encode(FINGERPRINT)));
        assert_eq!(before.status, "pending");
        assert!(!before.fee_paid);
        assert_eq!(before.fee_subscription_id, None);
        assert_eq!(before.host_id, None);

        bill_fee(&db, node_id, 1, true).await;
        approve_node(&db, node_id, &approve(1)).await.unwrap();

        let node = db.get_marketplace_node(node_id).await.unwrap();
        let after = node_info(&db, node).await.unwrap();
        assert!(after.fee_paid);
        assert!(after.fee_subscription_id.is_some());
        assert_eq!(
            after.host_id,
            db.get_marketplace_node_host(node_id)
                .await
                .unwrap()
                .map(|h| h.id)
        );
        assert_eq!(after.status, "approved");
    }

    /// An operator listing is what an admin reviews before changing a payout,
    /// so it has to say how much hardware is behind the enrolment.
    #[tokio::test]
    async fn operators_are_listed_with_their_node_count() {
        let (db, node_id) = fixture(0).await;
        let operator_id = db.get_marketplace_node(node_id).await.unwrap().operator_id;

        let (rows, total) = db
            .admin_list_marketplace_operators_paginated(50, 0)
            .await
            .unwrap();
        assert_eq!(total, 1);

        let info = operator_info(&db, rows[0].clone()).await.unwrap();
        assert_eq!(info.id, operator_id);
        assert_eq!(info.user_pubkey, hex::encode([7u8; 32]));
        assert_eq!(info.node_count, 1);
        assert_eq!(info.mode, PayoutMode::default().to_string());
    }

    /// The handlers, end to end through the extractors, including the routes
    /// they are mounted on.
    #[tokio::test]
    async fn the_endpoints_serve_the_node_lifecycle() {
        let (db, node_id) = fixture(0).await;
        let this = state(&db);
        let auth = || auth_for(AdminResource::MarketplaceNode);

        // Mounting is part of the contract: a handler nothing routes to is not
        // an endpoint.
        let _: Router<RouterState> = router();

        let listed = admin_list_nodes(
            auth(),
            State(this.clone()),
            Query(ListNodesQuery {
                status: Some("pending".to_string()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(listed.total, 1);
        assert_eq!(listed.data[0].id, node_id);

        assert!(
            admin_list_nodes(
                auth(),
                State(this.clone()),
                Query(ListNodesQuery {
                    status: Some("online".to_string()),
                    ..Default::default()
                }),
            )
            .await
            .is_err(),
            "an unknown status was accepted and silently ignored"
        );

        // Unfiltered, the queue is every node.
        let all = admin_list_nodes(
            auth(),
            State(this.clone()),
            Query(ListNodesQuery::default()),
        )
        .await
        .unwrap();
        assert_eq!(all.total, 1);

        let got = admin_get_node(auth(), State(this.clone()), Path(node_id))
            .await
            .unwrap();
        assert_eq!(got.data.status, "pending");

        // A tier nobody defined must not be waved through as the default.
        assert!(
            admin_approve_node(
                auth(),
                State(this.clone()),
                Path(node_id),
                Json(AdminApproveNodeRequest {
                    trust_tier: Some("trusted".to_string()),
                    ..approve(1)
                }),
            )
            .await
            .is_err()
        );

        let approved = admin_approve_node(
            auth(),
            State(this.clone()),
            Path(node_id),
            Json(AdminApproveNodeRequest {
                trust_tier: Some("verified".to_string()),
                ..approve(1)
            }),
        )
        .await
        .unwrap();
        assert_eq!(approved.data.status, "approved");
        assert_eq!(approved.data.trust_tier, "verified");
        assert!(approved.data.host_id.is_some());

        let suspended = admin_update_node(
            auth(),
            State(this.clone()),
            Path(node_id),
            Json(AdminUpdateNodeRequest {
                status: Some("suspended".to_string()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(suspended.data.status, "suspended");

        // A node backing a host cannot be deleted: that host is what customer
        // VMs are placed on.
        assert!(
            admin_delete_node(auth(), State(this.clone()), Path(node_id))
                .await
                .is_err()
        );

        // Rejecting a registration that was never approved is the delete path
        // that exists today — there is no `rejected` state to move it to.
        let operator_id = db.get_marketplace_node(node_id).await.unwrap().operator_id;
        let pending_id = db
            .insert_marketplace_node(&MarketplaceNode {
                operator_id,
                name: "rack 2".to_string(),
                tls_fingerprint: Some([0xcd; 32].to_vec()),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = admin_delete_node(auth(), State(this.clone()), Path(pending_id))
            .await
            .unwrap();
        assert!(db.get_marketplace_node(pending_id).await.is_err());

        // A node that never existed is a 404, not a silent success.
        assert!(
            admin_delete_node(auth(), State(this.clone()), Path(pending_id))
                .await
                .is_err()
        );
    }

    /// The operator endpoints, and the reason they are a separate resource:
    /// node permissions must not reach the money, and vice versa.
    #[tokio::test]
    async fn payout_control_is_granted_separately_from_placement_control() {
        let (db, node_id) = fixture(0).await;
        let this = state(&db);
        let operator_id = db.get_marketplace_node(node_id).await.unwrap().operator_id;
        let node_admin = || auth_for(AdminResource::MarketplaceNode);
        let payout_admin = || auth_for(AdminResource::MarketplaceOperator);

        let listed = admin_list_operators(
            payout_admin(),
            State(this.clone()),
            Query(PageQuery::default()),
        )
        .await
        .unwrap();
        assert_eq!(listed.total, 1);

        let got = admin_get_operator(payout_admin(), State(this.clone()), Path(operator_id))
            .await
            .unwrap();
        assert!(got.data.enabled);

        let updated = admin_update_operator(
            payout_admin(),
            State(this.clone()),
            Path(operator_id),
            Json(AdminUpdateOperatorRequest {
                rate: Some(Some(25.0)),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(updated.data.rate, Some(25.0));

        // Somebody who can suspend a node must not be able to change what its
        // operator is paid...
        assert!(
            admin_update_operator(
                node_admin(),
                State(this.clone()),
                Path(operator_id),
                Json(AdminUpdateOperatorRequest::default()),
            )
            .await
            .is_err()
        );
        assert!(
            admin_list_operators(
                node_admin(),
                State(this.clone()),
                Query(PageQuery::default())
            )
            .await
            .is_err()
        );
        assert!(
            admin_get_operator(node_admin(), State(this.clone()), Path(operator_id))
                .await
                .is_err()
        );

        // ...and the payout admin must not be able to approve hardware.
        assert!(
            admin_approve_node(
                payout_admin(),
                State(this.clone()),
                Path(node_id),
                Json(approve(1)),
            )
            .await
            .is_err()
        );
        assert!(
            admin_list_nodes(
                payout_admin(),
                State(this.clone()),
                Query(ListNodesQuery::default()),
            )
            .await
            .is_err()
        );
        assert!(
            admin_get_node(payout_admin(), State(this.clone()), Path(node_id))
                .await
                .is_err()
        );
        assert!(
            admin_update_node(
                payout_admin(),
                State(this.clone()),
                Path(node_id),
                Json(AdminUpdateNodeRequest::default()),
            )
            .await
            .is_err()
        );
        assert!(
            admin_delete_node(payout_admin(), State(this.clone()), Path(node_id))
                .await
                .is_err()
        );
    }

    /// The review queue is filtered in the database, and a node that has been
    /// dealt with must leave it.
    #[tokio::test]
    async fn the_pending_queue_only_shows_nodes_awaiting_review() {
        let (db, node_id) = fixture(0).await;
        let (pending, total) = db
            .admin_list_marketplace_nodes_paginated(
                50,
                0,
                Some(MarketplaceNodeStatus::Pending),
                None,
            )
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(pending[0].id, node_id);

        approve_node(&db, node_id, &approve(1)).await.unwrap();
        let (_, total) = db
            .admin_list_marketplace_nodes_paginated(
                50,
                0,
                Some(MarketplaceNodeStatus::Pending),
                None,
            )
            .await
            .unwrap();
        assert_eq!(total, 0, "an approved node stayed in the review queue");
    }
}

#[cfg(test)]
mod health_tests {
    use super::tests::*;
    use super::*;
    use lnvps_db::MarketplaceNodeHealth;

    fn a_result(node_id: u64, passed: bool, provision_ms: u32) -> MarketplaceNodeHealth {
        MarketplaceNodeHealth {
            node_id,
            passed,
            failure: (!passed).then(|| "could not log in".to_string()),
            provision_ms: passed.then_some(provision_ms),
            memory_mb: passed.then_some(1900),
            disk_write_mb: passed.then_some(410),
            disk_read_mb: passed.then_some(1200),
            cpu: 2,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            disk_bytes: 40 * 1024 * 1024 * 1024,
            image: "https://example.com/debian_12.img".to_string(),
            ..Default::default()
        }
    }

    /// The series comes back newest first, with the shape each row was measured
    /// at: without it, numbers from different regions rank machines by what
    /// LNVPS happened to ask them for.
    #[tokio::test]
    async fn a_nodes_probe_history_is_a_series() -> Result<(), ApiError> {
        let (db, node_id) = fixture(0).await;
        let this = state(&db);

        for ms in [90_000u32, 60_000, 30_000] {
            db.insert_marketplace_node_health(&a_result(node_id, true, ms))
                .await?;
        }

        let got = admin_node_health(
            auth_for(AdminResource::MarketplaceNode),
            State(this),
            Path(node_id),
            Query(PageQuery::default()),
        )
        .await?;

        assert_eq!(got.0.total, 3);
        let rows = got.0.data;
        assert_eq!(rows[0].provision_ms, Some(30_000), "newest first");
        assert_eq!(rows[0].cpu, 2);
        assert_eq!(rows[0].memory_bytes, 2 * 1024 * 1024 * 1024);
        Ok(())
    }

    /// A failure is a row, with the reason verbatim. An admin deciding whether
    /// to suspend somebody's hardware needs what actually happened, and a node
    /// that never completes a probe is indistinguishable from one nobody probed
    /// unless the failures are visible.
    #[tokio::test]
    async fn failures_are_visible_with_their_reason() -> Result<(), ApiError> {
        let (db, node_id) = fixture(0).await;
        let this = state(&db);
        db.insert_marketplace_node_health(&a_result(node_id, false, 0))
            .await?;

        let got = admin_node_health(
            auth_for(AdminResource::MarketplaceNode),
            State(this),
            Path(node_id),
            Query(PageQuery::default()),
        )
        .await?;

        let row = &got.0.data[0];
        assert!(!row.passed);
        assert_eq!(row.failure.as_deref(), Some("could not log in"));
        assert!(row.provision_ms.is_none());
        Ok(())
    }

    /// Reading a node's probes needs permission on the node resource — the same
    /// check every other node endpoint makes, and the one that was granted to
    /// nobody until it was noticed.
    #[tokio::test]
    async fn reading_probes_needs_permission() -> Result<(), ApiError> {
        let (db, node_id) = fixture(0).await;
        let this = state(&db);

        let denied = admin_node_health(
            auth_for(AdminResource::MarketplaceOperator),
            State(this),
            Path(node_id),
            Query(PageQuery::default()),
        )
        .await;

        assert!(denied.is_err(), "operator permissions must not read nodes");
        Ok(())
    }

    /// An unknown node is a 404 rather than an empty series, which would read
    /// as "this node has never been probed".
    #[tokio::test]
    async fn an_unknown_node_is_not_an_empty_series() {
        let (db, _) = fixture(0).await;
        let this = state(&db);

        assert!(
            admin_node_health(
                auth_for(AdminResource::MarketplaceNode),
                State(this),
                Path(9_999),
                Query(PageQuery::default()),
            )
            .await
            .is_err()
        );
    }
}
