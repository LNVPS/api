//! Operator-facing marketplace API: register your hardware, list your nodes.
//!
//! Registration is authenticated as the **operator's** account. It returns a
//! node token, shown once, which the operator installs on the machine; the node
//! authenticates as itself from then on.
//!
//! That split is deliberate. A marketplace node is somebody else's machine in
//! somebody else's building, and the account credential controls billing,
//! payouts and every other node the operator owns. Registering from the
//! operator's own machine means the account credential never has to live on the
//! hardware, and a node's token can be revoked on its own — bumping
//! `token_version` takes out that node and nothing else.

use axum::extract::{Path, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use chrono::Utc;
use lnvps_api_common::{
    ApiData, ApiError, ApiResult, NODE_TOKEN_TTL_SECS, Nip98Auth, NodeAuth, WorkJob,
    issue_node_token, session_auth_enabled,
};
use lnvps_db::{
    IntervalType, MarketplaceNode, MarketplaceNodeStatus, MarketplaceOperator,
    MarketplaceTrustTier, Subscription, SubscriptionLineItem, SubscriptionType,
};

use crate::api::RouterState;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/marketplace/nodes",
            get(v1_list_nodes).post(v1_register_node),
        )
        .route("/api/v1/marketplace/nodes/{id}", patch(v1_update_node))
        .route(
            "/api/v1/marketplace/nodes/{id}/token",
            post(v1_rotate_node_token),
        )
        .route(
            "/api/v1/marketplace/nodes/{id}/fee",
            post(v1_start_node_fee),
        )
        .route("/api/v1/marketplace/operator", get(v1_get_operator))
        // Node-facing: authenticated by the node's own token, not a user.
        .route("/api/v1/node/self", get(v1_node_self))
        .route(
            "/api/v1/node/tunnel",
            get(v1_node_get_tunnel).post(v1_node_request_tunnel),
        )
        .route("/api/v1/node/dataplane", get(v1_node_dataplane))
        .route("/api/v1/node/libvirt", post(v1_node_libvirt_cert))
}

/// A node as its operator sees it.
#[derive(Serialize)]
pub struct ApiMarketplaceNode {
    pub id: u64,
    /// Operator-chosen label. Not an identifier.
    pub name: String,
    /// SHA-256 of the certificate the node's control API serves, hex. LNVPS
    /// checks every call to the node against this value, so it must be updated
    /// when the node's certificate changes or the node becomes unreachable.
    pub tls_fingerprint: Option<String>,
    /// `pending`, `approved`, `suspended` or `draining`.
    pub status: String,
    /// `untrusted`, `verified` or `partner`.
    pub trust_tier: String,
    /// Last contact from the node, if it has ever connected.
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub created: chrono::DateTime<chrono::Utc>,
}

impl From<MarketplaceNode> for ApiMarketplaceNode {
    fn from(n: MarketplaceNode) -> Self {
        Self {
            id: n.id,
            name: n.name,
            tls_fingerprint: n.tls_fingerprint.map(hex::encode),
            status: n.status.to_string(),
            trust_tier: n.trust_tier.to_string(),
            last_seen: n.last_seen,
            created: n.created,
        }
    }
}

/// The operator's own enrolment.
#[derive(Serialize)]
pub struct ApiMarketplaceOperator {
    pub id: u64,
    /// Payout target; its meaning depends on `mode`.
    pub address: Option<String>,
    /// `lightning_address`, `nwc`, `account_credit` or `on_chain`.
    pub mode: String,
    /// Minimum accrued earnings (satoshis) before an automated payout runs.
    pub payout_threshold: Option<u64>,
    /// Revenue share override as a whole percentage. `null` means the company
    /// default applies.
    pub rate: Option<f32>,
    /// False when an admin has stopped new placements on this operator's nodes.
    pub enabled: bool,
    pub created: chrono::DateTime<chrono::Utc>,
}

impl From<MarketplaceOperator> for ApiMarketplaceOperator {
    fn from(o: MarketplaceOperator) -> Self {
        Self {
            id: o.id,
            address: o.address,
            mode: o.mode.to_string(),
            payout_threshold: o.payout_threshold,
            rate: o.rate,
            enabled: o.enabled,
            created: o.created,
        }
    }
}

/// Register a node.
#[derive(Deserialize)]
pub struct RegisterNodeRequest {
    /// Operator-chosen label, for your own use.
    pub name: String,
    /// SHA-256 of the node's TLS certificate, 64 hex characters, as printed by
    /// `lnvps-node fingerprint`.
    pub tls_fingerprint: String,
}

/// Update an already-registered node.
#[derive(Deserialize)]
pub struct UpdateNodeRequest {
    /// New label. Omitted leaves it unchanged.
    pub name: Option<String>,
    /// New certificate fingerprint, 64 hex characters.
    ///
    /// This is the certificate-rotation path. A node that regenerates its
    /// certificate — restored from backup, state directory lost — presents a
    /// fingerprint LNVPS does not have, every control call to it fails closed,
    /// and without this it would be unreachable for good.
    pub tls_fingerprint: Option<String>,
}

/// The certificate a node serves libvirt with.
#[derive(Deserialize)]
pub struct NodeLibvirtCertRequest {
    /// PEM, self-signed and CA-capable so it can be its own trust anchor.
    pub cert_pem: String,
}

/// A newly registered node, with the one and only copy of its token.
#[derive(Serialize)]
pub struct ApiRegisteredNode {
    #[serde(flatten)]
    pub node: ApiMarketplaceNode,
    /// The node's authentication token. **Shown once**: LNVPS keeps no copy, so
    /// a lost token is replaced by issuing a new one, which revokes this one.
    pub token: String,
}

/// Decode a 32-byte value from hex, rejecting anything else.
///
/// Both fields are fixed-width keys and digests; accepting a short or malformed
/// value would store something that can never match what the node presents,
/// and the failure would only show up later as an unreachable node.
fn parse_32_bytes(value: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| ApiError::bad_request(format!("{field} is not valid hex")))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(format!(
            "{field} must be 32 bytes (64 hex characters), got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Register hardware and issue its token.
async fn v1_register_node(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<RegisterNodeRequest>,
) -> ApiResult<ApiRegisteredNode> {
    let (node, token) = register_node(&this.db, &auth.pubkey(), &req).await?;
    ApiData::ok(ApiRegisteredNode {
        node: node.into(),
        token,
    })
}

/// The registration itself, separated from the extractors so it can be tested
/// against a database rather than only through a running server.
pub(crate) async fn register_node(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    caller: &[u8; 32],
    req: &RegisterNodeRequest,
) -> Result<(MarketplaceNode, String), ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("Node name cannot be empty"));
    }
    let fingerprint = parse_32_bytes(&req.tls_fingerprint, "tls_fingerprint")?;

    // Registration hands back a token, so a deployment that cannot issue one
    // must say so here rather than register a node that can never authenticate.
    if !session_auth_enabled() {
        return Err(ApiError::with_status(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Node tokens are unavailable because this deployment has no session secret \
             configured. Set it and restart before registering nodes.",
        ));
    }

    let uid = db.upsert_user(caller).await?;

    // Enrolment is implicit: an account registering hardware is an operator.
    // Payout configuration comes later, and a node cannot earn before it is
    // approved anyway.
    let operator = match db.get_marketplace_operator_by_user(uid).await {
        Ok(o) => o,
        Err(_) => {
            let id = db
                .insert_marketplace_operator(&MarketplaceOperator {
                    user_id: uid,
                    // `enabled` is what an admin clears to stop placement
                    // across an operator's whole fleet, so an enrolment that
                    // started disabled would look like one that had been
                    // stopped — and the insert binds this field rather than
                    // taking the column default.
                    enabled: true,
                    ..Default::default()
                })
                .await?;
            db.get_marketplace_operator(id).await?
        }
    };

    // A certificate is meant to identify one machine. The usual cause of a
    // collision is a state directory copied along with a cloned machine image,
    // which is worth saying plainly rather than surfacing a unique-index
    // violation as an internal error.
    if db
        .get_marketplace_node_by_tls_fingerprint(&fingerprint)
        .await
        .is_ok()
    {
        return Err(ApiError::bad_request(
            "Another node already uses that TLS certificate. If this machine was cloned from \
             another node, delete the tls directory in its state directory and restart it to \
             generate its own certificate, then register it again.",
        ));
    }

    let id = db
        .insert_marketplace_node(&MarketplaceNode {
            operator_id: operator.id,
            name: name.to_string(),
            tls_fingerprint: Some(fingerprint),
            // Nothing is placed on a node until an admin approves it.
            status: MarketplaceNodeStatus::Pending,
            trust_tier: MarketplaceTrustTier::Untrusted,
            ..Default::default()
        })
        .await?;

    let node = db.get_marketplace_node(id).await?;
    let token =
        issue_node_token(node.id, node.token_version, NODE_TOKEN_TTL_SECS).map_err(|e| {
            ApiError::with_status(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not issue a node token: {e}"),
            )
        })?;
    Ok((node, token))
}

/// Update a node you own — rename it, or re-pin a rotated certificate.
async fn v1_update_node(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(node_id): Path<u64>,
    Json(req): Json<UpdateNodeRequest>,
) -> ApiResult<ApiMarketplaceNode> {
    let node = owned_node(&this.db, &auth.pubkey(), node_id).await?;

    let name = match req.name.as_deref().map(str::trim) {
        Some("") => return Err(ApiError::bad_request("Node name cannot be empty")),
        Some(n) => n.to_string(),
        None => node.name.clone(),
    };
    let fingerprint = match &req.tls_fingerprint {
        Some(f) => {
            let parsed = parse_32_bytes(f, "tls_fingerprint")?;
            // Another node holding this certificate is the cloned-state-directory
            // case again; rebinding it here would quietly point LNVPS at the
            // wrong machine.
            if let Ok(other) = this
                .db
                .get_marketplace_node_by_tls_fingerprint(&parsed)
                .await
                && other.id != node.id
            {
                return Err(ApiError::bad_request(
                    "Another node already uses that TLS certificate.",
                ));
            }
            Some(parsed)
        }
        None => node.tls_fingerprint.clone(),
    };

    let updated = MarketplaceNode {
        name,
        tls_fingerprint: fingerprint,
        ..node
    };
    this.db.update_marketplace_node(&updated).await?;
    ApiData::ok(this.db.get_marketplace_node(updated.id).await?.into())
}

/// Issue a fresh token for a node, revoking the previous one.
///
/// This is the only way to replace a token — LNVPS keeps no copy of the one it
/// handed out, so a lost or leaked token is dealt with by taking a new one.
async fn v1_rotate_node_token(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(node_id): Path<u64>,
) -> ApiResult<ApiRegisteredNode> {
    let node = owned_node(&this.db, &auth.pubkey(), node_id).await?;

    // Bumping the version is what invalidates the old token. It must be stored
    // before the new one is handed out, or a failure here would leave the
    // caller holding a token the node will reject.
    let bumped = MarketplaceNode {
        token_version: node.token_version.wrapping_add(1),
        ..node
    };
    this.db.update_marketplace_node(&bumped).await?;

    let node = this.db.get_marketplace_node(bumped.id).await?;
    let token =
        issue_node_token(node.id, node.token_version, NODE_TOKEN_TTL_SECS).map_err(|e| {
            ApiError::with_status(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not issue a node token: {e}"),
            )
        })?;
    ApiData::ok(ApiRegisteredNode {
        node: node.into(),
        token,
    })
}

/// Fetch a node, refusing one that belongs to somebody else.
///
/// Answers "not found" rather than "forbidden" so the endpoint does not confirm
/// the existence of other operators' nodes to anyone who guesses an id.
pub(crate) async fn owned_node(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    caller: &[u8; 32],
    node_id: u64,
) -> Result<MarketplaceNode, ApiError> {
    let uid = db.upsert_user(caller).await?;
    let operator = db
        .get_marketplace_operator_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Node not found"))?;
    let node = db
        .get_marketplace_node(node_id)
        .await
        .map_err(|_| ApiError::not_found("Node not found"))?;
    if node.operator_id != operator.id {
        return Err(ApiError::not_found("Node not found"));
    }
    Ok(node)
}

/// Start paying a node's one-off listing fee.
#[derive(Deserialize)]
pub struct StartNodeFeeRequest {
    /// The region the operator wants this node listed in.
    ///
    /// The fee's company and currency come from the region, exactly as an IP
    /// range's come from its IP space — a node belongs to no region when it is
    /// registered, so there is nothing else to derive them from. It also tells
    /// the admin where the operator intends the hardware to live; approval can
    /// still place it elsewhere.
    pub region_id: u64,
}

/// The fee subscription for a node.
#[derive(Serialize, Debug)]
pub struct ApiNodeFee {
    /// Subscription to pay. Pay it through the normal subscription renewal
    /// endpoint — there is no separate payment rail for fees.
    pub subscription_id: u64,
    /// Amount due, in `currency`.
    pub amount: u64,
    pub currency: String,
    /// Whether the fee has already been paid.
    pub is_paid: bool,
}

/// Create (or return) the subscription covering a node's listing fee.
///
/// Idempotent on purpose: an operator who calls this twice must not end up with
/// two fee subscriptions for one node, one of which they never pay and which
/// then sits unpaid forever. The second call returns the first.
async fn v1_start_node_fee(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<StartNodeFeeRequest>,
) -> ApiResult<ApiNodeFee> {
    ApiData::ok(start_node_fee(&this.db, &auth.pubkey(), id, &req).await?)
}

/// The body of [`v1_start_node_fee`], without the extractors, so it can be
/// tested against a database rather than a live HTTP stack.
pub(crate) async fn start_node_fee(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    caller: &[u8; 32],
    id: u64,
    req: &StartNodeFeeRequest,
) -> Result<ApiNodeFee, ApiError> {
    let mut node = owned_node(db, caller, id).await?;

    // Already started: hand back the existing subscription rather than making
    // a second one.
    if let Some(line_item_id) = node.subscription_line_item_id {
        let line_item = db.get_subscription_line_item(line_item_id).await?;
        let sub = db.get_subscription(line_item.subscription_id).await?;
        return Ok(ApiNodeFee {
            subscription_id: sub.id,
            amount: line_item.setup_amount,
            currency: sub.currency,
            // `is_setup` is what payment sets, and a one-off fee never gets an
            // expiry to check instead.
            is_paid: sub.is_setup,
        });
    }

    let region = db.get_host_region(req.region_id).await?;
    let company = db.get_company(region.company_id).await?;
    if company.marketplace_node_fee == 0 {
        return Err(ApiError::new(
            "No listing fee is required for nodes in this region",
        ));
    }

    let subscription = Subscription {
        id: 0,
        user_id: db.upsert_user(caller).await?,
        company_id: region.company_id,
        name: format!("Marketplace node listing fee: {}", node.name),
        description: Some(format!(
            "One-off fee to list node '{}' in {}",
            node.name, region.name
        )),
        created: Utc::now(),
        expires: None,
        is_active: false,
        is_setup: false,
        currency: company.base_currency.clone(),
        interval_amount: 1,
        interval_type: IntervalType::Month,
        setup_fee: company.marketplace_node_fee,
        // Nothing recurring to renew.
        auto_renewal_enabled: false,
        external_id: None,
    };

    // amount = 0 with a setup_amount is what marks this a one-off: it is the
    // shape `subscription_payment_paid` recognises to leave `expires` NULL.
    let line_item = SubscriptionLineItem {
        id: 0,
        subscription_id: 0,
        subscription_type: SubscriptionType::MarketplaceNodeFee,
        name: format!("Node listing fee: {}", node.name),
        description: None,
        amount: 0,
        setup_amount: company.marketplace_node_fee,
        configuration: None,
    };

    let (subscription_id, line_item_ids) = db
        .insert_subscription_with_line_items(&subscription, vec![line_item])
        .await?;
    let line_item_id = *line_item_ids
        .first()
        .ok_or_else(|| ApiError::new("Failed to create fee line item"))?;

    node.subscription_line_item_id = Some(line_item_id);
    db.update_marketplace_node(&node).await?;

    Ok(ApiNodeFee {
        subscription_id,
        amount: company.marketplace_node_fee,
        currency: company.base_currency,
        is_paid: false,
    })
}

/// List the caller's own nodes.
async fn v1_list_nodes(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiMarketplaceNode>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let operator = match this.db.get_marketplace_operator_by_user(uid).await {
        Ok(o) => o,
        // Not enrolled is not an error: it is an operator with no nodes.
        Err(_) => return ApiData::ok(vec![]),
    };
    let nodes = this.db.list_marketplace_nodes(operator.id).await?;
    ApiData::ok(nodes.into_iter().map(Into::into).collect())
}

/// A node asking for its data plane.
#[derive(Deserialize)]
pub struct RequestTunnelRequest {
    /// The node's WireGuard **public** key, 64 hex characters.
    ///
    /// Generated on the node. The private half never leaves the operator's
    /// machine, which is why this is presented rather than issued.
    pub public_key: String,
}

/// Everything a node needs to bring its tunnel up.
#[derive(Serialize, Debug)]
pub struct ApiNodeTunnel {
    /// The node's own inner addresses, as CIDR (`10.0.0.1/31`). Configure these
    /// on the WireGuard interface.
    pub address4: Option<String>,
    pub address6: Option<String>,
    /// The route server's addresses on the same links — the node's default
    /// gateway for guest traffic.
    pub gateway4: Option<String>,
    pub gateway6: Option<String>,
    /// The route server's WireGuard public key, hex.
    pub server_public_key: String,
    /// `host:port` to dial.
    pub endpoint: String,
    /// Persistent keepalive in seconds, when the pool sets one. A node behind
    /// NAT needs it or the route server cannot reach it between handshakes.
    pub keepalive: Option<u16>,
    /// MTU to use inside the tunnel. Not 1500: WireGuard's overhead comes off
    /// it, and guessing wrong hangs large transfers rather than failing
    /// outright.
    pub mtu: u16,
}

impl From<crate::provisioner::NodeTunnel> for ApiNodeTunnel {
    fn from(t: crate::provisioner::NodeTunnel) -> Self {
        Self {
            address4: t.tunnel.address4.clone(),
            address6: t.tunnel.address6.clone(),
            gateway4: t.gateway4(),
            gateway6: t.gateway6(),
            server_public_key: hex::encode(&t.pool.public_key),
            endpoint: t.pool.endpoint(),
            keepalive: t.tunnel.keepalive,
            mtu: t.pool.mtu,
        }
    }
}

/// Ask for a data plane, presenting the node's public key.
///
/// Idempotent: a node that retries gets the allocation it already has. A node
/// that presents a **new** key has regenerated its keypair and is re-pinned in
/// place — the addresses do not move, and refusing would leave a machine that
/// can never be reached again.
async fn v1_node_request_tunnel(
    auth: NodeAuth,
    State(this): State<RouterState>,
    Json(req): Json<RequestTunnelRequest>,
) -> ApiResult<ApiNodeTunnel> {
    let key = parse_32_bytes(&req.public_key, "public_key")?;
    let allocation = crate::provisioner::allocate_node_tunnel(&this.db, &auth.node, &key)
        .await
        .map_err(|e| ApiError::new(e.to_string()))?;

    // Realise the peer on the route server. Queued rather than awaited: the
    // node has what it needs to configure its own end either way, and making
    // the answer wait on an SSH round trip to a route server would fail the
    // request for something the node cannot fix. A failure to queue is logged
    // and left to the periodic reconcile, which pushes the same peer.
    if let Err(e) = this
        .work_sender
        .send(WorkJob::SyncNodeTunnel {
            tunnel_id: allocation.tunnel.id,
        })
        .await
    {
        log::error!(
            "Allocated tunnel {} for node {} but could not queue its peer push: {e}",
            allocation.tunnel.id,
            auth.node.id
        );
    }
    ApiData::ok(allocation.into())
}

/// Read back the node's data plane, which is how it re-reads its configuration
/// after a restart without asking for a new allocation.
async fn v1_node_get_tunnel(
    auth: NodeAuth,
    State(this): State<RouterState>,
) -> ApiResult<ApiNodeTunnel> {
    let allocation = crate::provisioner::get_node_tunnel(&this.db, &auth.node)
        .await
        .map_err(|e| ApiError::new(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("This node has no tunnel allocated yet"))?;
    ApiData::ok(allocation.into())
}

/// Everything the node's data plane should look like, in one document.
#[derive(Serialize, Debug)]
pub struct ApiNodeDataPlane {
    pub tunnel: ApiNodeTunnel,
    /// Gateway addresses this node must answer for on the bridge. They belong
    /// to the ranges the guests were addressed from, and the guests believe
    /// they are on-link.
    pub gateways: Vec<String>,
    /// The guests placed here. Also the anti-spoof list: an address that is not
    /// in it is not this node's to send from.
    pub guests: Vec<ApiNodeGuest>,
    /// How the node should set up the libvirtd LNVPS drives. `null` when LNVPS
    /// has no client identity configured, which is a deployment that can enrol
    /// and network nodes but not place VMs on them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub libvirt: Option<ApiNodeLibvirt>,
}

/// What a node needs to serve libvirt to LNVPS and nobody else.
#[derive(Serialize, Debug)]
pub struct ApiNodeLibvirt {
    /// PEM of the CA that signed LNVPS's client certificate. Delivered here
    /// rather than compiled into the node package, so rotating it reaches the
    /// fleet on the next poll instead of stranding every deployed node.
    pub ca_pem: String,
    /// The only client DN the node may accept. A certificate signed by the same
    /// CA for anything else is still refused.
    pub allowed_dn: String,
    /// The address libvirtd must bind — the node's own tunnel address, and not
    /// the machine's other interfaces, which are the operator's LAN and uplink.
    pub listen: String,
}

#[derive(Serialize, Debug)]
pub struct ApiNodeGuest {
    /// Host prefix (`203.0.113.5/32`), so v4 and v6 read the same way.
    pub address: String,
    /// The gateway this guest was configured with.
    pub gateway: String,
    /// The guest's MAC, when recorded.
    pub mac: Option<String>,
}

impl From<crate::provisioner::NodeDataPlane> for ApiNodeDataPlane {
    fn from(d: crate::provisioner::NodeDataPlane) -> Self {
        Self {
            gateways: d.gateways(),
            guests: d
                .guests
                .iter()
                .map(|g| ApiNodeGuest {
                    address: g.address.clone(),
                    gateway: g.gateway.clone(),
                    mac: g.mac.clone(),
                })
                .collect(),
            tunnel: d.tunnel.into(),
            // Filled by the handler, which is the only place that can see both
            // the node's address and LNVPS's own credentials.
            libvirt: None,
        }
    }
}

/// The node's whole desired data plane.
///
/// One call rather than three, because the node applies these together or not
/// at all: a bridge with no tunnel carries nothing, and a tunnel with no guest
/// routes carries nothing back.
/// What a node is told about serving libvirt, if LNVPS can drive it at all.
///
/// `None` when no client identity is configured: such a deployment can enrol
/// and network nodes but not place VMs on them. Telling the node to open an
/// unauthenticated listener instead would put hypervisor control on an address
/// its own guests can reach.
fn node_libvirt(
    settings: &crate::settings::Settings,
    listen: Option<&str>,
) -> Option<ApiNodeLibvirt> {
    let cfg = settings.provisioner.marketplace.as_ref()?;
    let listen = listen?;
    // The document carries addresses as CIDR; libvirtd binds an address.
    let listen = listen.split('/').next()?.to_string();
    let ca_pem = std::fs::read_to_string(&cfg.ca_cert)
        .map_err(|e| {
            // A missing CA is a deployment fault, not a node fault: log it and
            // send nothing, so the node keeps its existing configuration rather
            // than being told to trust an empty file.
            log::error!(
                "marketplace libvirt CA {} unreadable: {e}",
                cfg.ca_cert.display()
            );
        })
        .ok()?;

    Some(ApiNodeLibvirt {
        ca_pem,
        allowed_dn: lnvps_api_common::node_control::LIBVIRT_CLIENT_DN.to_string(),
        listen,
    })
}

/// Register the certificate LNVPS should trust when driving this node's
/// libvirtd.
///
/// Sent by the node once it has a tunnel address to name in the certificate.
/// The whole certificate rather than a fingerprint, because libvirt's client
/// verifies a chain against a CA file and a hash gives it nothing to read.
///
/// Rotation is the same call: a node restored from backup, or one whose tunnel
/// address moved, regenerates its identity and presents the new certificate.
/// Without that path it would be unreachable for good.
async fn v1_node_libvirt_cert(
    auth: NodeAuth,
    State(this): State<RouterState>,
    Json(req): Json<NodeLibvirtCertRequest>,
) -> ApiResult<()> {
    let cert = req.cert_pem.trim();
    // Checked here rather than at connection time: a malformed certificate
    // stored now is a VM that fails to provision later, at which point the
    // failing thing is a long way from the thing that was wrong.
    if !cert.starts_with("-----BEGIN CERTIFICATE-----")
        || !cert.ends_with("-----END CERTIFICATE-----")
    {
        return Err(ApiError::bad_request(
            "cert_pem must be a single PEM certificate",
        ));
    }

    let updated = MarketplaceNode {
        libvirt_cert: Some(cert.to_string()),
        ..auth.node
    };
    this.db.update_marketplace_node(&updated).await?;

    // Written here as well as stored, because libvirt reads its trust material
    // from a directory rather than from us. Doing it on every registration —
    // which is every poll — is what lets a deployment that lost that directory
    // repair itself without anyone noticing.
    if let Some(cfg) = this.settings.provisioner.marketplace.as_ref() {
        lnvps_api_common::host::marketplace_pki::materialise(cfg, updated.id, cert)
            .map_err(|e| ApiError::new(format!("Storing the node certificate failed: {e}")))?;
    }
    ApiData::ok(())
}

async fn v1_node_dataplane(
    auth: NodeAuth,
    State(this): State<RouterState>,
) -> ApiResult<ApiNodeDataPlane> {
    let plane = crate::provisioner::node_dataplane(&this.db, &auth.node)
        .await
        .map_err(|e| ApiError::new(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("This node has no tunnel allocated yet"))?;

    // libvirtd binds the node's own inner address, preferring v4 only because
    // that is what an operator reading their journal will recognise; either
    // works, and a node with neither has no tunnel to serve on.
    let listen = plane
        .tunnel
        .tunnel
        .address4
        .clone()
        .or_else(|| plane.tunnel.tunnel.address6.clone());
    let mut out: ApiNodeDataPlane = plane.into();
    out.libvirt = node_libvirt(&this.settings, listen.as_deref());
    ApiData::ok(out)
}

/// What a node is told about itself.
///
/// The daemon uses this to confirm its token works and to see whether it has
/// been approved, without being able to see anything about other nodes or about
/// the operator's account.
async fn v1_node_self(auth: NodeAuth) -> ApiResult<ApiMarketplaceNode> {
    ApiData::ok(auth.node.into())
}

/// The caller's operator enrolment.
async fn v1_get_operator(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<ApiMarketplaceOperator> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let operator = this
        .db
        .get_marketplace_operator_by_user(uid)
        .await
        .map_err(|_| ApiError::not_found("Not enrolled as a marketplace operator"))?;
    ApiData::ok(operator.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_api_common::{init_session_secret, verify_node_token, verify_session_token};
    use std::sync::Arc;

    const FINGERPRINT_1: &str = "aaaa111111111111111111111111111111111111111111111111111111111111";
    const FINGERPRINT_2: &str = "bbbb222222222222222222222222222222222222222222222222222222222222";

    const OPERATOR: [u8; 32] = [9u8; 32];
    const SOMEONE_ELSE: [u8; 32] = [8u8; 32];

    fn db() -> Arc<dyn lnvps_db::LNVpsDb> {
        init_session_secret(b"test-secret-for-marketplace".to_vec());
        Arc::new(MockDb::default())
    }

    /// A database whose company charges `fee` to list a node, plus the id of a
    /// region to derive that company from.
    async fn db_with_fee(fee: u64) -> (Arc<dyn lnvps_db::LNVpsDb>, u64) {
        init_session_secret(b"test-secret-for-marketplace".to_vec());
        let mock = MockDb::default();
        mock.set_marketplace_node_fee(1, fee).await;
        let db: Arc<dyn lnvps_db::LNVpsDb> = Arc::new(mock);
        let region_id = db.get_host_region(1).await.expect("mock region 1").id;
        (db, region_id)
    }

    fn request(name: &str, fingerprint: &str) -> RegisterNodeRequest {
        RegisterNodeRequest {
            name: name.to_string(),
            tls_fingerprint: fingerprint.to_string(),
        }
    }

    #[tokio::test]
    async fn paying_a_fee_creates_a_one_off_subscription_for_that_node() {
        let (db, region_id) = db_with_fee(5000).await;
        let (node, _) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        let fee = start_node_fee(&db, &OPERATOR, node.id, &StartNodeFeeRequest { region_id })
            .await
            .unwrap();
        assert_eq!(fee.amount, 5000);
        assert_eq!(fee.currency, "EUR");
        assert!(!fee.is_paid);

        // The shape matters: amount 0 with a setup fee is what makes
        // `subscription_payment_paid` treat this as a one-off and leave
        // `expires` NULL. A recurring line item here would start dunning the
        // operator for a fee they paid once.
        let items = db
            .list_subscription_line_items(fee.subscription_id)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].amount, 0, "listing fee must not bill recurring");
        assert_eq!(items[0].setup_amount, 5000);
        assert_eq!(
            items[0].subscription_type,
            SubscriptionType::MarketplaceNodeFee
        );

        let sub = db.get_subscription(fee.subscription_id).await.unwrap();
        assert_eq!(sub.expires, None);
        assert!(
            !sub.auto_renewal_enabled,
            "a one-off fee must not auto-renew"
        );

        // The node now points at the line item that bills it.
        let reloaded = db.get_marketplace_node(node.id).await.unwrap();
        assert_eq!(reloaded.subscription_line_item_id, Some(items[0].id));
        assert_eq!(
            db.get_marketplace_node_by_line_item(items[0].id)
                .await
                .unwrap()
                .id,
            node.id
        );
    }

    /// An operator who retries must not end up with two fee subscriptions, one
    /// of which they never pay and which then sits unpaid forever.
    #[tokio::test]
    async fn starting_a_fee_twice_returns_the_same_subscription() {
        let (db, region_id) = db_with_fee(5000).await;
        let (node, _) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        let first = start_node_fee(&db, &OPERATOR, node.id, &StartNodeFeeRequest { region_id })
            .await
            .unwrap();
        let second = start_node_fee(&db, &OPERATOR, node.id, &StartNodeFeeRequest { region_id })
            .await
            .unwrap();
        assert_eq!(first.subscription_id, second.subscription_id);
    }

    /// Each node is charged separately — paying once must not license a fleet.
    #[tokio::test]
    async fn each_node_needs_its_own_fee() {
        let (db, region_id) = db_with_fee(5000).await;
        let (a, _) = register_node(&db, &OPERATOR, &request("a", FINGERPRINT_1))
            .await
            .unwrap();
        let (b, _) = register_node(&db, &OPERATOR, &request("b", FINGERPRINT_2))
            .await
            .unwrap();

        let fee_a = start_node_fee(&db, &OPERATOR, a.id, &StartNodeFeeRequest { region_id })
            .await
            .unwrap();
        let fee_b = start_node_fee(&db, &OPERATOR, b.id, &StartNodeFeeRequest { region_id })
            .await
            .unwrap();
        assert_ne!(
            fee_a.subscription_id, fee_b.subscription_id,
            "two nodes shared one listing fee"
        );
    }

    /// Node ids must not be probeable through the fee endpoint either.
    #[tokio::test]
    async fn another_operators_node_cannot_be_paid_for() {
        let (db, region_id) = db_with_fee(5000).await;
        let (node, _) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        let err = start_node_fee(
            &db,
            &SOMEONE_ELSE,
            node.id,
            &StartNodeFeeRequest { region_id },
        )
        .await
        .expect_err("paid for another operator's node");
        assert!(format!("{err:?}").contains("not found"), "got: {err:?}");
    }

    /// A company that charges nothing must not create a zero-amount invoice
    /// that can never be paid and would block approval forever.
    #[tokio::test]
    async fn no_fee_configured_means_nothing_to_pay() {
        let (db, region_id) = db_with_fee(0).await;
        let (node, _) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        assert!(
            start_node_fee(&db, &OPERATOR, node.id, &StartNodeFeeRequest { region_id })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn registering_enrols_the_caller_and_leaves_the_node_pending() {
        let db = db();
        let (node, token) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        assert_eq!(node.name, "rack 1");
        assert_eq!(
            node.tls_fingerprint,
            Some(hex::decode(FINGERPRINT_1).unwrap())
        );
        assert_eq!(
            node.status,
            MarketplaceNodeStatus::Pending,
            "a node must not be placeable before an admin approves it"
        );

        // The token authenticates this node and no other.
        let claims = verify_node_token(&token).unwrap();
        assert_eq!(claims.nid, node.id);
        assert_eq!(claims.ver, node.token_version);

        let uid = db.upsert_user(&OPERATOR).await.unwrap();
        let operator = db.get_marketplace_operator_by_user(uid).await.unwrap();
        assert_eq!(node.operator_id, operator.id);
    }

    /// A node token must not be a way into its operator's account. The node is
    /// on hardware LNVPS does not control, so this is the boundary that keeps a
    /// compromised machine from becoming a compromised account.
    #[tokio::test]
    async fn a_node_token_is_not_an_account_credential() {
        let db = db();
        let (_, token) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        verify_session_token(&token)
            .expect_err("a node token authenticated as its operator's account");
    }

    /// Rotation is the only way to replace a token, since LNVPS keeps no copy
    /// of the one it issued.
    #[tokio::test]
    async fn rotating_a_token_revokes_the_previous_one() {
        let db = db();
        let (node, first) = register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .unwrap();

        // Bump the version the way the rotate handler does.
        let bumped = lnvps_db::MarketplaceNode {
            token_version: node.token_version + 1,
            ..node.clone()
        };
        db.update_marketplace_node(&bumped).await.unwrap();
        let after = db.get_marketplace_node(node.id).await.unwrap();

        // The signature on the old token is still valid — revocation has to be
        // the version check, because a signed token cannot be withdrawn.
        let old_claims = verify_node_token(&first).unwrap();
        assert_ne!(
            old_claims.ver, after.token_version,
            "the old token still matches the node's current version, so it was not revoked"
        );
    }

    /// Registration hands back a token. A deployment that cannot issue one must
    /// say so, not register a node that could never authenticate.
    #[tokio::test]
    async fn registration_refuses_when_tokens_cannot_be_issued() {
        // This cannot be tested by unsetting the process-wide secret (it is set
        // once for the process), so it checks the condition the guard reads.
        assert!(
            lnvps_api_common::session_auth_enabled(),
            "test setup: the secret should be installed by db()"
        );
        let db = db();
        register_node(&db, &OPERATOR, &request("rack 1", FINGERPRINT_1))
            .await
            .expect("registration should succeed while tokens can be issued");
    }

    /// Two nodes sharing a certificate means either can answer for the other,
    /// which is exactly what pinning exists to prevent.
    #[tokio::test]
    async fn two_nodes_cannot_share_a_fingerprint() {
        let db = db();
        register_node(&db, &OPERATOR, &request("one", FINGERPRINT_1))
            .await
            .unwrap();

        let err = register_node(&db, &OPERATOR, &request("two", FINGERPRINT_1))
            .await
            .expect_err("two nodes were allowed to share a TLS fingerprint");

        // The usual cause is a cloned machine image carrying a copied state
        // directory, so the message must name that and say what to do — this
        // otherwise surfaces as an opaque internal error.
        let msg = format!("{err:?}");
        assert!(msg.contains("Another node already uses"), "{msg}");
        assert!(
            msg.contains("cloned"),
            "the message must name the likely cause: {msg}"
        );
        assert!(
            msg.contains("delete the tls directory"),
            "the message must say what to do: {msg}"
        );
    }

    /// The same collision across operators is the impersonation case: one
    /// operator's node answering for another's.
    #[tokio::test]
    async fn a_fingerprint_cannot_be_reused_by_a_different_operator() {
        let db = db();
        register_node(&db, &OPERATOR, &request("theirs", FINGERPRINT_1))
            .await
            .unwrap();

        let err = register_node(&db, &SOMEONE_ELSE, &request("mine", FINGERPRINT_1))
            .await
            .expect_err("one operator registered another operator's certificate");
        assert!(
            format!("{err:?}").contains("Another node already uses"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn one_operator_can_run_several_nodes() {
        let db = db();
        let (a, ta) = register_node(&db, &OPERATOR, &request("one", FINGERPRINT_1))
            .await
            .unwrap();
        let (b, tb) = register_node(&db, &OPERATOR, &request("two", FINGERPRINT_2))
            .await
            .unwrap();

        assert_ne!(a.id, b.id);
        assert_eq!(a.operator_id, b.operator_id);
        // Each node gets its own token, so one can be revoked without the other.
        assert_ne!(ta, tb);
        assert_eq!(verify_node_token(&ta).unwrap().nid, a.id);
        assert_eq!(verify_node_token(&tb).unwrap().nid, b.id);
    }

    /// Answering "not found" rather than "forbidden" avoids confirming that
    /// another operator's node exists to anyone who guesses an id.
    #[tokio::test]
    async fn another_operators_node_cannot_be_reached() {
        let db = db();
        let (node, _) = register_node(&db, &OPERATOR, &request("theirs", FINGERPRINT_1))
            .await
            .unwrap();
        // Give the other caller an operator record of their own.
        register_node(&db, &SOMEONE_ELSE, &request("mine", FINGERPRINT_2))
            .await
            .unwrap();

        let err = owned_node(&db, &SOMEONE_ELSE, node.id)
            .await
            .expect_err("one operator reached another operator's node");
        assert!(format!("{err:?}").contains("not found"), "{err:?}");
        assert!(
            !format!("{err:?}").to_lowercase().contains("forbidden"),
            "the error confirms the node exists: {err:?}"
        );
    }

    /// A malformed digest would be stored as something the node can never
    /// present, and would surface much later as an unreachable node.
    #[tokio::test]
    async fn malformed_fingerprints_are_refused_at_the_door() {
        let db = db();
        for (fingerprint, expect) in [
            ("zz", "tls_fingerprint is not valid hex"),
            ("1122", "tls_fingerprint must be 32 bytes"),
        ] {
            let err = register_node(&db, &OPERATOR, &request("n", fingerprint))
                .await
                .expect_err("malformed fingerprint accepted");
            assert!(format!("{err:?}").contains(expect), "got {err:?}");
        }
    }

    #[tokio::test]
    async fn a_node_needs_a_name() {
        let db = db();
        let err = register_node(&db, &OPERATOR, &request("   ", FINGERPRINT_1))
            .await
            .expect_err("an unnamed node was registered");
        assert!(
            format!("{err:?}").contains("name cannot be empty"),
            "{err:?}"
        );
    }

    /// Hex is case-insensitive; the stored bytes must not depend on which case
    /// the operator pasted.
    #[tokio::test]
    async fn fingerprints_are_stored_as_bytes_not_text() {
        let db = db();
        let (node, _) = register_node(&db, &OPERATOR, &request("n", &FINGERPRINT_1.to_uppercase()))
            .await
            .unwrap();

        assert_eq!(
            node.tls_fingerprint,
            Some(hex::decode(FINGERPRINT_1).unwrap())
        );
        assert!(
            db.get_marketplace_node_by_tls_fingerprint(&hex::decode(FINGERPRINT_1).unwrap())
                .await
                .is_ok(),
            "the node cannot be found by the lowercase form its daemon will send"
        );
    }

    /// What the daemon is handed has to be enough to configure WireGuard
    /// without a second call: its own addresses, the gateway to route through,
    /// the server key, where to dial, and the MTU.
    #[test]
    fn a_tunnel_response_carries_a_complete_wireguard_configuration() {
        let allocation = crate::provisioner::NodeTunnel {
            tunnel: lnvps_db::Tunnel {
                id: 1,
                address4: Some("10.66.0.2/32".to_string()),
                address6: Some("fd00:66::2/128".to_string()),
                keepalive: Some(25),
                ..Default::default()
            },
            pool: lnvps_db::TunnelPool {
                cidr4: Some("10.66.0.0/24".to_string()),
                cidr6: Some("fd00:66::/64".to_string()),
                public_key: vec![0x33; 32],
                listen_addr: "rs.example".to_string(),
                listen_port: 51820,
                mtu: 1420,
                ..Default::default()
            },
        };

        let api: ApiNodeTunnel = allocation.into();
        assert_eq!(api.address4.as_deref(), Some("10.66.0.2/32"));
        assert_eq!(api.address6.as_deref(), Some("fd00:66::2/128"));
        // The gateway is derived from the pool's block rather than stored, and
        // is the same one address for every node on the pool.
        assert_eq!(api.gateway4.as_deref(), Some("10.66.0.1"));
        assert_eq!(api.gateway6.as_deref(), Some("fd00:66::1"));
        assert_eq!(api.server_public_key, hex::encode([0x33; 32]));
        assert_eq!(api.endpoint, "rs.example:51820");
        assert_eq!(api.keepalive, Some(25));
        assert_eq!(
            api.mtu, 1420,
            "the daemon must be told the MTU: 1500 inside a tunnel hangs large transfers"
        );
    }

    /// A key that is not 32 bytes is not a WireGuard key. Storing it would fail
    /// every handshake later, with nothing to point at.
    #[test]
    fn a_malformed_wireguard_key_is_refused_at_the_door() {
        for (key, expect) in [
            ("zz", "public_key is not valid hex"),
            ("1122", "public_key must be 32 bytes"),
        ] {
            let err = parse_32_bytes(key, "public_key").expect_err("malformed key accepted");
            assert!(format!("{err:?}").contains(expect), "got {err:?}");
        }
    }
}
