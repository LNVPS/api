//! Authentication for marketplace nodes.
//!
//! A node is not a user. It has no account, cannot be billed, and must not
//! reach any endpoint that authenticates a person — so it gets its own
//! extractor rather than being squeezed into [`crate::Nip98Auth`], and the two
//! token types are kept apart by an explicit `typ` claim.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use lnvps_db::MarketplaceNode;

use crate::session::verify_node_token;

/// A request proven to come from a specific marketplace node.
#[derive(Debug, Clone)]
pub struct NodeAuth {
    /// The node the token authenticates. Taken from the database, not from the
    /// token, so a handler cannot act on stale claims.
    pub node: MarketplaceNode,
}

impl<S> FromRequestParts<S> for NodeAuth
where
    S: Send + Sync,
    std::sync::Arc<dyn lnvps_db::LNVpsDb>: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        use axum::extract::FromRef;
        let db = std::sync::Arc::<dyn lnvps_db::LNVpsDb>::from_ref(state);
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        Box::pin(async move {
            let header = header.ok_or((
                StatusCode::UNAUTHORIZED,
                "Auth header not found".to_string(),
            ))?;
            let token = header.strip_prefix("Bearer ").ok_or((
                StatusCode::UNAUTHORIZED,
                "Node auth must use the Bearer scheme".to_string(),
            ))?;

            let claims = verify_node_token(token.trim())
                .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid node token: {e}")))?;

            let node = db.get_marketplace_node(claims.nid).await.map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid node token: unknown node".to_string(),
                )
            })?;

            // The token is a signed statement that cannot be withdrawn, so
            // revocation lives here: bumping the node's `token_version` makes
            // every token issued before the bump stop working, and only for
            // this node.
            if node.token_version != claims.ver {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "Invalid node token: token has been revoked".to_string(),
                ));
            }

            Ok(NodeAuth { node })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use crate::session::{NODE_TOKEN_TTL_SECS, init_session_secret, issue_node_token};
    use axum::extract::FromRef;
    use axum::http::Request;
    use lnvps_db::{LNVpsDb, MarketplaceNodeStatus, MarketplaceOperator, MarketplaceTrustTier};
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestState(Arc<dyn LNVpsDb>);

    impl FromRef<TestState> for Arc<dyn LNVpsDb> {
        fn from_ref(s: &TestState) -> Self {
            s.0.clone()
        }
    }

    /// A registered node and the state to authenticate against.
    async fn node_and_state() -> (MarketplaceNode, TestState) {
        init_session_secret(b"test-secret-for-node-auth".to_vec());
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let uid = db.upsert_user(&[3u8; 32]).await.unwrap();
        let op = db
            .insert_marketplace_operator(&MarketplaceOperator {
                user_id: uid,
                ..Default::default()
            })
            .await
            .unwrap();
        let id = db
            .insert_marketplace_node(&MarketplaceNode {
                operator_id: op,
                name: "n".into(),
                status: MarketplaceNodeStatus::Pending,
                trust_tier: MarketplaceTrustTier::Untrusted,
                ..Default::default()
            })
            .await
            .unwrap();
        let node = db.get_marketplace_node(id).await.unwrap();
        (node, TestState(db))
    }

    async fn authenticate(state: &TestState, header: Option<&str>) -> Result<NodeAuth, StatusCode> {
        let mut builder = Request::builder().uri("/api/v1/node/self");
        if let Some(h) = header {
            builder = builder.header("authorization", h);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        NodeAuth::from_request_parts(&mut parts, state)
            .await
            .map_err(|(code, _)| code)
    }

    #[tokio::test]
    async fn a_valid_token_authenticates_its_own_node() {
        let (node, state) = node_and_state().await;
        let token = issue_node_token(node.id, node.token_version, NODE_TOKEN_TTL_SECS).unwrap();

        let auth = authenticate(&state, Some(&format!("Bearer {token}")))
            .await
            .expect("a freshly issued token was rejected");
        assert_eq!(auth.node.id, node.id);
    }

    /// The reason `token_version` exists. A signed token cannot be withdrawn,
    /// so revocation has to be a check against current state on every request.
    #[tokio::test]
    async fn a_revoked_token_stops_working() {
        let (node, state) = node_and_state().await;
        let token = issue_node_token(node.id, node.token_version, NODE_TOKEN_TTL_SECS).unwrap();

        // Rotate: bump the node's version, as the rotate endpoint does.
        let db = Arc::<dyn LNVpsDb>::from_ref(&state);
        db.update_marketplace_node(&MarketplaceNode {
            token_version: node.token_version + 1,
            ..node.clone()
        })
        .await
        .unwrap();

        let code = authenticate(&state, Some(&format!("Bearer {token}")))
            .await
            .expect_err("a revoked token still authenticated");
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    /// A token for a node that no longer exists must not authenticate as
    /// whatever now holds that id.
    #[tokio::test]
    async fn a_token_for_a_deleted_node_is_refused() {
        let (node, state) = node_and_state().await;
        let token = issue_node_token(node.id, node.token_version, NODE_TOKEN_TTL_SECS).unwrap();

        Arc::<dyn LNVpsDb>::from_ref(&state)
            .delete_marketplace_node(node.id)
            .await
            .unwrap();

        let code = authenticate(&state, Some(&format!("Bearer {token}")))
            .await
            .expect_err("a token for a deleted node authenticated");
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn requests_without_a_usable_token_are_refused() {
        let (_, state) = node_and_state().await;
        for header in [
            None,
            Some("Nostr abc"),
            Some("Bearer not-a-token"),
            Some(""),
        ] {
            let code = authenticate(&state, header)
                .await
                .expect_err("authenticated without a valid node token");
            assert_eq!(code, StatusCode::UNAUTHORIZED, "header: {header:?}");
        }
    }
}
