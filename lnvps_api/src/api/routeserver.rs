//! What a route server should be, published for it to come and fetch.
//!
//! Every other router backend is configured by LNVPS reaching out and telling
//! it what to be. A VPN route server is not, because it runs wherever its
//! region is: behind somebody else's NAT, on a residential uplink, on a
//! provider that filters inbound. Dialling out to it would work everywhere it
//! was tested and fail on the one machine nobody thought about, and that
//! failure surfaces as a revoked device that keeps working. How quickly a
//! customer's key stops being honoured must not depend on the network the
//! machine happens to sit in.
//!
//! So the document is published and `lvd` fetches it. To get the speed of a
//! push without the reachability of one, the fetch can **wait**: a route server
//! sends the generation it last applied and the request is held until that
//! moves. A peer change lands in one round trip, over a connection the route
//! server opened, through any NAT, with no inbound port and no certificate for
//! LNVPS to pin.
//!
//! There is nothing in the document that says who a peer is. A peer is a public
//! key and the addresses it may use, and that is all: no account, no plan, no
//! device name. A seized route server yields the key-to-address map it must
//! have in kernel memory anyway, and nothing that was not already on the wire.

use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use lnvps_api_common::{ApiData, ApiError, ApiResult, JobFeedback, RouteServerAuth};
use std::sync::Arc;

use lnvps_db::{LNVpsDb, TunnelPool};

use crate::api::RouterState;

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/v1/routeserver/dataplane", get(v1_dataplane))
}

/// The longest a fetch may be held open.
///
/// Bounded well under the idle timeout of the middleboxes between a route
/// server and here: a connection silently dropped by a NAT is one the daemon
/// waits on until its own timeout fires, which is the delay this exists to
/// avoid. Twenty-five seconds also fits inside the 30s default of most reverse
/// proxies without being cut off mid-wait.
const MAX_WAIT_SECS: u64 = 25;

/// How often a held request re-reads the generation when nothing has woken it.
///
/// A backstop, not the mechanism. Redis pub/sub is fire-and-forget: a message
/// published while this instance was reconnecting is simply gone, and a route
/// server that waited on it alone would wait out its whole deadline for a
/// change that had already happened. Re-reading on a slow timer bounds that at
/// a few seconds instead.
///
/// It is also the whole mechanism when no Redis is configured, which is how the
/// API runs in development and in tests.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct DataplaneQuery {
    /// The highest generation this route server has already applied. The
    /// request is held until some interface passes it.
    pub generation: Option<u64>,
    /// Seconds to wait for a change before answering unchanged. Zero, or
    /// absent, answers immediately.
    pub wait: Option<u64>,
}

/// One WireGuard interface, as the route server should configure it.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DesiredInterface {
    /// The pool this interface realises. The interface is named from it, so the
    /// name is not carried: a stored name could be edited to point at an
    /// interface the pool does not own.
    pub pool_id: u64,
    /// The interface's private key, base64.
    ///
    /// LNVPS holds it because LNVPS generated it: a route server that made its
    /// own key could not be handed a peer set, since every client config
    /// naming the old public key would stop working the moment it rebooted.
    pub private_key: String,
    /// The UDP port to listen on.
    pub listen_port: u16,
    pub mtu: u16,
    /// The route server's own addresses on this interface, CIDR.
    pub addresses: Vec<String>,
    /// Prefixes routed down the interface. Empty for a VPN interface, whose
    /// peers are single addresses already covered by their own `allowed_ips`.
    pub routes: Vec<String>,
    pub peers: Vec<DesiredPeer>,
}

/// One peer. A key, and what it may send as.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DesiredPeer {
    /// Base64, as WireGuard states keys.
    pub public_key: String,
    /// The only source addresses this key may use, CIDR. This is the whole of
    /// what LNVPS tells a route server about a customer.
    pub allowed_ips: Vec<String>,
    /// Where to send to, for a peer that sits still. Absent for a device, which
    /// is a laptop on a train and is found by where it last spoke from.
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DesiredDataPlane {
    /// The highest generation in this document. A route server sends it back on
    /// its next fetch, and holds a request open until it moves.
    pub generation: u64,
    /// Every interface this route server terminates. The full set, not a delta:
    /// an interface that has been unlinked is gone from here, and a route server
    /// that only ever heard about additions would keep serving it.
    pub interfaces: Vec<DesiredInterface>,
}

/// Fetch the desired data plane, optionally waiting for it to change.
async fn v1_dataplane(
    auth: RouteServerAuth,
    State(this): State<RouterState>,
    Query(params): Query<DataplaneQuery>,
) -> ApiResult<DesiredDataPlane> {
    let router_id = auth.router.id;
    let known = params.generation.unwrap_or(0);
    let wait = params.wait.unwrap_or(0).min(MAX_WAIT_SECS);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);

    // Subscribed before the first read, not after: a bump landing in between
    // would be announced to nobody, and this request would then wait out its
    // whole deadline for a change that had already happened.
    let mut changes = subscribe_to_changes(&this, router_id).await;

    let pools = loop {
        let pools = route_server_pools(&this.db, router_id).await?;
        let now = tokio::time::Instant::now();
        if current_generation(&pools) != known || now >= deadline {
            break pools;
        }
        // Whichever comes first. The message is only ever a hint that it is
        // worth looking again -- what it says is never trusted, because the
        // database is what the route server is actually being told.
        let backstop = POLL_INTERVAL.min(deadline - now);
        match changes.as_mut() {
            Some(stream) => {
                let _ = tokio::time::timeout(backstop, stream.next()).await;
            }
            None => tokio::time::sleep(backstop).await,
        }
    };

    // The document is built once the answer is known to have changed, rather
    // than on every poll: reading a generation is one query, and building a
    // peer set is one per interface plus every device on the service.
    let mut interfaces = Vec::with_capacity(pools.len());
    for pool in &pools {
        interfaces.push(desired_interface(&this.db, pool).await?);
    }

    ApiData::ok(DesiredDataPlane {
        generation: current_generation(&pools),
        interfaces,
    })
}

/// Listen for any of this route server's interfaces being announced as moved.
///
/// One subscription per interface rather than a single channel for the router,
/// because a pool announces itself and does not know which machine is asking.
/// The payload is discarded: it says which generation was published, but a
/// message is not proof and the database is re-read regardless. All it does is
/// save the wait.
///
/// `None` when there is no Redis, or when subscribing fails. Both fall back to
/// re-reading on the backstop timer, which is slower and still correct -- a
/// route server that is late is better than one that is refused.
async fn subscribe_to_changes<'a>(
    this: &'a RouterState,
    router_id: u64,
) -> Option<BoxStream<'a, ()>> {
    let feedback = this.feedback.as_ref()?;
    let pools = route_server_pools(&this.db, router_id).await.ok()?;

    let mut streams = Vec::with_capacity(pools.len());
    for pool in pools {
        let channel = JobFeedback::channel_name(&JobFeedback::tunnel_pool_job_id(pool.id));
        match feedback.subscribe(&channel).await {
            Ok(stream) => streams.push(stream),
            Err(e) => {
                log::warn!("Could not subscribe to {channel}, falling back to polling: {e}");
                return None;
            }
        }
    }
    Some(futures::stream::select_all(streams).map(|_| ()).boxed())
}

/// The interfaces a route server terminates.
///
/// Disabled pools are excluded rather than sent with a flag: a route server has
/// no use for an interface it must not bring up, and sending one is sending a
/// private key to a machine that has no reason to hold it.
async fn route_server_pools(
    db: &Arc<dyn LNVpsDb>,
    router_id: u64,
) -> Result<Vec<TunnelPool>, ApiError> {
    Ok(db
        .list_tunnel_pools(None)
        .await?
        .into_iter()
        .filter(|p| p.router_id == router_id && p.enabled)
        .collect())
}

/// The generation of the whole document: the highest of any interface in it.
///
/// One number rather than one per interface, because a route server applies the
/// document as a unit. Taking the highest means a change to any interface moves
/// it, and removing an interface cannot lower it, so a document can never look
/// older than one already applied.
fn current_generation(pools: &[TunnelPool]) -> u64 {
    pools.iter().map(|p| p.generation).max().unwrap_or(0)
}

async fn desired_interface(
    db: &Arc<dyn LNVpsDb>,
    pool: &TunnelPool,
) -> Result<DesiredInterface, ApiError> {
    // The same planner the pushed backends use. Not a second description of
    // what an interface should be: one that drifted from the other would be
    // wrong on exactly the pools nobody was watching.
    let plan = crate::provisioner::wg::TunnelProvisioner::new(db.clone())
        .plan(pool)
        .await?;

    Ok(DesiredInterface {
        pool_id: pool.id,
        private_key: pool.private_key.as_str().to_string(),
        listen_port: pool.listen_port,
        mtu: pool.mtu,
        addresses: plan.addresses,
        routes: plan.routes,
        peers: plan
            .peers
            .into_iter()
            .map(|p| DesiredPeer {
                public_key: p.public_key,
                allowed_ips: p.allowed_ips,
                endpoint: p.endpoint,
                persistent_keepalive: p.persistent_keepalive,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests;
