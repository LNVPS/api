//! Authenticating a route server that configures itself.
//!
//! A machine running `lvd` asks LNVPS what its interfaces should be and applies
//! the answer. It authenticates with a static token rather than a signed one,
//! because there is nothing to mint: unlike a marketplace node, a route server
//! is LNVPS's own machine, provisioned by hand, and the credential is written
//! into its config file at the same time as everything else about it.
//!
//! The token is `router.token`, which is the meaning that column already
//! carries — the secret shared between LNVPS and this router — travelling in
//! the other direction. One secret per route server, so rotating it takes out
//! one machine rather than all of them, and rotating it is a column update.
//!
//! It is presented as `<router_id>.<secret>`. The id is in the token because
//! `router.token` is encrypted at rest with a per-row nonce, so there is no
//! query that finds a router by its secret; the id says which row to compare
//! against, and the secret is what actually authenticates.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use lnvps_db::{Router, RouterKind};

/// A route server, authenticated as itself.
pub struct RouteServerAuth {
    /// The router the token belongs to. Read from the database rather than
    /// carried in the token, so a handler cannot act on stale claims.
    pub router: Router,
}

/// Compare two secrets without leaking, through timing, how much of one was
/// right.
///
/// Written out rather than pulled from a crate: it is four lines, and the only
/// thing that matters is that it does not stop at the first difference.
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // Lengths are compared in the clear. A secret's length is not the secret,
    // and folding it into the loop would either leak it anyway or index out of
    // bounds.
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl<S> FromRequestParts<S> for RouteServerAuth
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
            let unauthorized = |m: &str| (StatusCode::UNAUTHORIZED, m.to_string());

            let header = header.ok_or_else(|| unauthorized("Auth header not found"))?;
            let token = header
                .strip_prefix("Bearer ")
                .ok_or_else(|| unauthorized("Route server auth must use the Bearer scheme"))?
                .trim();

            let (id, secret) = token
                .split_once('.')
                .ok_or_else(|| unauthorized("Route server token must be <router_id>.<secret>"))?;
            let id: u64 = id
                .parse()
                .map_err(|_| unauthorized("Route server token must be <router_id>.<secret>"))?;

            let router = db
                .get_router(id)
                .await
                .map_err(|_| unauthorized("Invalid route server token"))?;

            // Every failure below answers the same way. Which of them it was is
            // knowledge the caller has not yet earned, and telling a prober
            // that a router exists but is disabled is telling them something.
            if !secret_eq(router.token.as_str(), secret) {
                return Err(unauthorized("Invalid route server token"));
            }
            // A route server is not asked what to be by any other backend: a
            // MikroTik's token is a management password, and honouring it here
            // would turn every router credential into a way to read the peer
            // set of the machines it has nothing to do with.
            if !matches!(router.kind, RouterKind::Lvd) {
                return Err(unauthorized("Invalid route server token"));
            }
            if !router.enabled {
                return Err(unauthorized("Invalid route server token"));
            }

            Ok(RouteServerAuth { router })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::secret_eq;

    #[test]
    fn a_secret_matches_only_itself() {
        assert!(secret_eq("hunter2", "hunter2"));
        assert!(!secret_eq("hunter2", "hunter3"));
        // A prefix must not pass: the fold would be zero over the shared bytes,
        // so the length check is what refuses it.
        assert!(!secret_eq("hunter2", "hunter"));
        assert!(!secret_eq("hunter", "hunter2"));
        assert!(secret_eq("", ""));
    }
}
