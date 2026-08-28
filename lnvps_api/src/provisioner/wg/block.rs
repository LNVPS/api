//! Something a peer address can be carved out of.
//!
//! Two rows hold blocks: a [`TunnelPool`], whose peers are the point-to-point
//! links carved from its own `cidr4`/`cidr6`, and a `VpnService`, whose peers
//! are devices addressed from one block shared by every region. They differ in
//! four things — which columns hold the block, what is already taken out of it,
//! where in it to place a new address, and what to call the row in an error —
//! and in nothing else.
//!
//! So those four are the trait, and carving is written once as a default
//! method. A caller says `pool.carve(&db)` or `service.carve(&db)` and neither
//! the pool nor the service needs a function of its own in a consumer module.

use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use lnvps_db::{LNVpsDb, Tunnel, TunnelPool};

use crate::provisioner::wg::address::{Placement, carve_peer};

#[async_trait]
pub trait PeerBlock: Send + Sync {
    /// The IPv4 and IPv6 blocks, either of which may be absent.
    fn blocks(&self) -> (Option<&str>, Option<&str>);

    /// How this row is named in an error, so an admin knows what to edit.
    fn describe(&self) -> String;

    /// Where in the block a new address is taken from.
    fn placement(&self) -> Placement;

    /// Addresses already carved out of this block.
    async fn taken(&self, db: &Arc<dyn LNVpsDb>) -> Result<Vec<IpNetwork>>;

    /// Carve the next free peer address out of each block this row has.
    async fn carve(&self, db: &Arc<dyn LNVpsDb>) -> Result<(Option<String>, Option<String>)> {
        let (cidr4, cidr6) = self.blocks();
        // The invariant `ck_tunnel_pool_has_a_block` used to hold, moved here
        // when a VPN pool stopped needing a block of its own. It cannot live in
        // the schema any more, because whether a row is allowed to have no
        // block depends on another table. Failing loudly beats returning a peer
        // with no addresses, which looks configured and carries nothing.
        if cidr4.is_none() && cidr6.is_none() {
            bail!(
                "{} has no address block, so there is nothing to carve a peer from",
                self.describe()
            );
        }
        let taken = self.taken(db).await?;
        carve_peer(cidr4, cidr6, &taken, &self.describe(), self.placement())
    }
}

/// Every address already carved, as the allocator wants them.
///
/// Unparseable values are dropped rather than failing the allocation: a
/// malformed stored address is a row to fix, not a reason to refuse every
/// subsequent customer, and it cannot collide with anything the allocator
/// produces because the allocator only produces parseable ones.
pub(crate) fn taken_addresses(tunnels: &[Tunnel]) -> Vec<IpNetwork> {
    tunnels
        .iter()
        .flat_map(|t| [t.address4.as_deref(), t.address6.as_deref()])
        .flatten()
        .filter_map(|a| a.parse::<IpNetwork>().ok())
        .collect()
}

/// A pool's peers are the links carved from its own block.
///
/// Sequential placement: a pool holds a handful of nodes, and an operator
/// debugging one benefits from addresses they can reason about. The argument
/// for scattering customer addresses does not apply.
#[async_trait]
impl PeerBlock for TunnelPool {
    fn blocks(&self) -> (Option<&str>, Option<&str>) {
        (self.cidr4.as_deref(), self.cidr6.as_deref())
    }

    fn describe(&self) -> String {
        format!("Tunnel pool {}", self.id)
    }

    fn placement(&self) -> Placement {
        Placement::Sequential
    }

    async fn taken(&self, db: &Arc<dyn LNVpsDb>) -> Result<Vec<IpNetwork>> {
        Ok(taken_addresses(&db.list_tunnels_in_pool(self.id).await?))
    }
}
