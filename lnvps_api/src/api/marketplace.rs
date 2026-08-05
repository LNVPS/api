//! Operator-facing marketplace API: register your hardware, list your nodes.
//!
//! Registration is authenticated as the **operator's** account, and carries the
//! node's own identity — its nostr public key and TLS fingerprint — in the
//! body. The node is not the caller.
//!
//! That split is deliberate. A marketplace node is somebody else's machine in
//! somebody else's building, and the account key is what controls billing,
//! payouts and every other node the operator owns. Registering from the
//! operator's own machine, with the node's identity pasted in, means the
//! account key never has to live on the hardware at all; the node afterwards
//! authenticates as itself with a key that can be revoked on its own.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use lnvps_api_common::{ApiData, ApiError, ApiResult, Nip98Auth};
use lnvps_db::{MarketplaceNode, MarketplaceNodeStatus, MarketplaceOperator, MarketplaceTrustTier};

use crate::api::RouterState;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/marketplace/nodes",
            get(v1_list_nodes).post(v1_register_node),
        )
        .route("/api/v1/marketplace/operator", get(v1_get_operator))
}

/// A node as its operator sees it.
#[derive(Serialize)]
pub struct ApiMarketplaceNode {
    pub id: u64,
    /// Operator-chosen label. Not an identifier.
    pub name: String,
    /// The node's own nostr public key, hex. This is what the daemon
    /// authenticates its heartbeats with.
    pub nostr_pubkey: Option<String>,
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
            nostr_pubkey: n.nostr_pubkey.map(hex::encode),
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

/// Register a node, or update the identity of one already registered.
#[derive(Deserialize)]
pub struct RegisterNodeRequest {
    /// Operator-chosen label, for your own use.
    pub name: String,
    /// The node's nostr public key, 64 hex characters, as printed by
    /// `lnvps-node identity`. Identifies the node from here on.
    pub nostr_pubkey: String,
    /// SHA-256 of the node's TLS certificate, 64 hex characters, as printed by
    /// `lnvps-node fingerprint`.
    pub tls_fingerprint: String,
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

/// Register hardware, or re-register it after its certificate changed.
///
/// Re-registration is not a convenience: a node that regenerates its
/// certificate — restored from backup, state directory lost — presents a
/// fingerprint LNVPS does not have, and every control call to it fails closed.
/// Without a way to update the pin, such a node would be permanently
/// unreachable and could only be replaced.
async fn v1_register_node(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<RegisterNodeRequest>,
) -> ApiResult<ApiMarketplaceNode> {
    ApiData::ok(register_node(&this.db, &auth.pubkey(), &req).await?.into())
}

/// The registration itself, separated from the extractors so it can be tested
/// against a database rather than only through a running server.
pub(crate) async fn register_node(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    caller: &[u8; 32],
    req: &RegisterNodeRequest,
) -> Result<MarketplaceNode, ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("Node name cannot be empty"));
    }
    let pubkey = parse_32_bytes(&req.nostr_pubkey, "nostr_pubkey")?;
    let fingerprint = parse_32_bytes(&req.tls_fingerprint, "tls_fingerprint")?;

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
    if let Ok(other) = db
        .get_marketplace_node_by_tls_fingerprint(&fingerprint)
        .await
        && other.nostr_pubkey.as_deref() != Some(pubkey.as_slice())
    {
        return Err(ApiError::bad_request(
            "Another node already uses that TLS certificate. If this machine was cloned from \
             another node, delete the tls directory in its state directory and restart it to \
             generate its own certificate, then register it again.",
        ));
    }

    // A node already using this key is the same machine re-registering.
    match db.get_marketplace_node_by_nostr_pubkey(&pubkey).await {
        Ok(existing) => {
            // Someone else's hardware. Rebinding it would hand over a machine
            // that may be running their customers' VMs, so this fails rather than
            // taking ownership.
            if existing.operator_id != operator.id {
                return Err(ApiError::forbidden(
                    "That node is registered to another operator",
                ));
            }
            let updated = MarketplaceNode {
                name: name.to_string(),
                tls_fingerprint: Some(fingerprint),
                ..existing
            };
            db.update_marketplace_node(&updated).await?;
            Ok(db.get_marketplace_node(updated.id).await?)
        }
        Err(_) => {
            let id = db
                .insert_marketplace_node(&MarketplaceNode {
                    operator_id: operator.id,
                    name: name.to_string(),
                    nostr_pubkey: Some(pubkey),
                    tls_fingerprint: Some(fingerprint),
                    // Nothing is placed on a node until an admin approves it.
                    status: MarketplaceNodeStatus::Pending,
                    trust_tier: MarketplaceTrustTier::Untrusted,
                    ..Default::default()
                })
                .await?;
            Ok(db.get_marketplace_node(id).await?)
        }
    }
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
    use std::sync::Arc;

    /// Two distinct 32-byte values, written out so a test that swaps them is
    /// obvious.
    const NODE_A_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NODE_B_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const FINGERPRINT_1: &str = "aaaa111111111111111111111111111111111111111111111111111111111111";
    const FINGERPRINT_2: &str = "bbbb222222222222222222222222222222222222222222222222222222222222";

    fn db() -> Arc<dyn lnvps_db::LNVpsDb> {
        Arc::new(MockDb::default())
    }

    fn request(name: &str, pubkey: &str, fingerprint: &str) -> RegisterNodeRequest {
        RegisterNodeRequest {
            name: name.to_string(),
            nostr_pubkey: pubkey.to_string(),
            tls_fingerprint: fingerprint.to_string(),
        }
    }

    #[tokio::test]
    async fn registering_enrols_the_caller_and_leaves_the_node_pending() {
        let db = db();
        let node = register_node(
            &db,
            &[9u8; 32],
            &request("rack 1", NODE_A_KEY, FINGERPRINT_1),
        )
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
        assert_eq!(node.trust_tier, MarketplaceTrustTier::Untrusted);

        // The caller was enrolled as an operator on the way through.
        let uid = db.upsert_user(&[9u8; 32]).await.unwrap();
        let operator = db.get_marketplace_operator_by_user(uid).await.unwrap();
        assert_eq!(node.operator_id, operator.id);
    }

    /// The certificate rotation path. Without it, a node that regenerates its
    /// certificate presents a fingerprint LNVPS does not have, every control
    /// call fails closed, and the machine is unreachable for good.
    #[tokio::test]
    async fn re_registering_updates_the_pinned_fingerprint() {
        let db = db();
        let first = register_node(
            &db,
            &[9u8; 32],
            &request("rack 1", NODE_A_KEY, FINGERPRINT_1),
        )
        .await
        .unwrap();

        let second = register_node(
            &db,
            &[9u8; 32],
            &request("rack 1 renamed", NODE_A_KEY, FINGERPRINT_2),
        )
        .await
        .unwrap();

        assert_eq!(
            second.id, first.id,
            "re-registration must not create a second node"
        );
        assert_eq!(
            second.tls_fingerprint,
            Some(hex::decode(FINGERPRINT_2).unwrap())
        );
        assert_eq!(second.name, "rack 1 renamed");
    }

    /// The security guard: re-registering somebody else's node would hand over
    /// a machine that may be running their customers' VMs.
    #[tokio::test]
    async fn a_node_cannot_be_taken_over_by_another_operator() {
        let db = db();
        register_node(
            &db,
            &[9u8; 32],
            &request("theirs", NODE_A_KEY, FINGERPRINT_1),
        )
        .await
        .unwrap();

        let err = register_node(
            &db,
            &[8u8; 32],
            &request("mine now", NODE_A_KEY, FINGERPRINT_2),
        )
        .await
        .expect_err("a node was taken over by another operator");
        assert!(
            format!("{err:?}").contains("another operator"),
            "unexpected error: {err:?}"
        );

        // And the original is untouched.
        let node = db
            .get_marketplace_node_by_nostr_pubkey(&hex::decode(NODE_A_KEY).unwrap())
            .await
            .unwrap();
        assert_eq!(node.name, "theirs");
        assert_eq!(
            node.tls_fingerprint,
            Some(hex::decode(FINGERPRINT_1).unwrap())
        );
    }

    /// Two nodes sharing a certificate means either can answer for the other,
    /// which is exactly what pinning exists to prevent.
    #[tokio::test]
    async fn two_nodes_cannot_share_a_fingerprint() {
        let db = db();
        register_node(&db, &[9u8; 32], &request("one", NODE_A_KEY, FINGERPRINT_1))
            .await
            .unwrap();

        let err = register_node(&db, &[9u8; 32], &request("two", NODE_B_KEY, FINGERPRINT_1))
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
        assert!(
            msg.contains("code: 400"),
            "a client error must not be reported as a 500: {msg}"
        );
    }

    /// The same collision across operators is the impersonation case: one
    /// operator's node answering for another's.
    #[tokio::test]
    async fn a_fingerprint_cannot_be_reused_by_a_different_operator() {
        let db = db();
        register_node(
            &db,
            &[9u8; 32],
            &request("theirs", NODE_A_KEY, FINGERPRINT_1),
        )
        .await
        .unwrap();

        let err = register_node(&db, &[8u8; 32], &request("mine", NODE_B_KEY, FINGERPRINT_1))
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
        let a = register_node(&db, &[9u8; 32], &request("one", NODE_A_KEY, FINGERPRINT_1))
            .await
            .unwrap();
        let b = register_node(&db, &[9u8; 32], &request("two", NODE_B_KEY, FINGERPRINT_2))
            .await
            .unwrap();

        assert_ne!(a.id, b.id);
        assert_eq!(a.operator_id, b.operator_id);
        assert_eq!(
            db.list_marketplace_nodes(a.operator_id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    /// A malformed key or digest would be stored as something the node can
    /// never present, and would surface much later as an unreachable node.
    #[tokio::test]
    async fn malformed_identities_are_refused_at_the_door() {
        let db = db();
        for (pubkey, fingerprint, expect) in [
            ("nothex", FINGERPRINT_1, "nostr_pubkey is not valid hex"),
            (NODE_A_KEY, "zz", "tls_fingerprint is not valid hex"),
            ("1122", FINGERPRINT_1, "nostr_pubkey must be 32 bytes"),
            (NODE_A_KEY, "1122", "tls_fingerprint must be 32 bytes"),
        ] {
            let err = register_node(&db, &[9u8; 32], &request("n", pubkey, fingerprint))
                .await
                .expect_err("malformed identity accepted");
            assert!(format!("{err:?}").contains(expect), "got {err:?}");
        }
    }

    #[tokio::test]
    async fn a_node_needs_a_name() {
        let db = db();
        let err = register_node(&db, &[9u8; 32], &request("   ", NODE_A_KEY, FINGERPRINT_1))
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
    async fn identities_are_stored_as_bytes_not_text() {
        let db = db();
        let node = register_node(
            &db,
            &[9u8; 32],
            &request(
                "n",
                &NODE_A_KEY.to_uppercase(),
                &FINGERPRINT_1.to_uppercase(),
            ),
        )
        .await
        .unwrap();

        assert_eq!(
            node.tls_fingerprint,
            Some(hex::decode(FINGERPRINT_1).unwrap())
        );
        // And it is found by the lowercase form the daemon will send.
        assert!(
            db.get_marketplace_node_by_nostr_pubkey(&hex::decode(NODE_A_KEY).unwrap())
                .await
                .is_ok()
        );
    }
}
