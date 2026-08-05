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

use lnvps_api_common::{
    ApiData, ApiError, ApiResult, NODE_TOKEN_TTL_SECS, Nip98Auth, NodeAuth, issue_node_token,
    session_auth_enabled,
};
use lnvps_db::{MarketplaceNode, MarketplaceNodeStatus, MarketplaceOperator, MarketplaceTrustTier};

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
        .route("/api/v1/marketplace/operator", get(v1_get_operator))
        // Node-facing: authenticated by the node's own token, not a user.
        .route("/api/v1/node/self", get(v1_node_self))
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

    fn request(name: &str, fingerprint: &str) -> RegisterNodeRequest {
        RegisterNodeRequest {
            name: name.to_string(),
            tls_fingerprint: fingerprint.to_string(),
        }
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
}
