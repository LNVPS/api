//! A marketplace node's data plane.
//!
//! A node's guests use LNVPS addresses, so their traffic has to reach an LNVPS
//! route server before it reaches the internet. That is a WireGuard tunnel: the
//! node dials out, the route server terminates it, and the guest prefixes are
//! routed down it.
//!
//! Everything here is marketplace vocabulary — nodes, hosts, guests, probes,
//! the bridge the operator's daemon puts VMs on. None of it belongs in the
//! generic WireGuard code, which meets this module only at `tunnel` and
//! `tunnel_route`.
//!
//! LNVPS decides the inner addresses and which route server terminates them;
//! the node decides its own key and presents only the public half.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use ipnetwork::IpNetwork;
use lnvps_db::{LNVpsDb, MarketplaceNode, RouterTunnelKind, Tunnel, TunnelPool};

use crate::provisioner::wg::address::{bare_address, host_address, server_address};
use crate::provisioner::wg::block::PeerBlock;

/// A node's tunnel and the pool it came from.
///
/// The pool is returned alongside because everything the node needs to bring
/// the tunnel up — the server's key, the endpoint to dial, the MTU — lives
/// there, and looking it up again from the tunnel is an avoidable round trip.
#[derive(Debug, Clone)]
pub struct NodeTunnel {
    pub tunnel: Tunnel,
    pub pool: TunnelPool,
}

impl NodeTunnel {
    /// The route server's address, which every node on the pool shares.
    ///
    /// Derived from the pool's block rather than stored, and one address for
    /// the whole pool rather than one per node: WireGuard is layer 3 and
    /// point-to-point, with no ARP and no on-link requirement, so a per-node
    /// link address bought nothing and cost the route server one address per
    /// node on a single interface.
    pub fn gateway4(&self) -> Option<String> {
        server_address(self.pool.cidr4.as_deref()).map(|a| bare_address(&a))
    }

    /// The route server's IPv6 address on the pool.
    pub fn gateway6(&self) -> Option<String> {
        server_address(self.pool.cidr6.as_deref()).map(|a| bare_address(&a))
    }
}

/// The bridge a marketplace node puts its guests on.
///
/// A constant on both sides rather than a field in the data-plane document.
/// Sending it would imply LNVPS could choose a different one, which it cannot:
/// the daemon has to know the name before it has ever spoken to LNVPS (it
/// reports on that bridge, and an operator debugging a node asks about it
/// offline), so a document that named a *different* bridge would leave the node
/// holding two answers. The e2e harness asserts the two constants agree.
pub const NODE_BRIDGE: &str = "br-lnvps";

/// The whole desired data plane for one node, in one document.
///
/// Fetched and applied together because it only makes sense together: a bridge
/// with no tunnel carries nothing, a tunnel with no guest routes carries
/// nothing back, and a document that can be half-fetched is a data plane that
/// can be half-applied.
#[derive(Debug, Clone)]
pub struct NodeDataPlane {
    pub tunnel: NodeTunnel,
    /// The guests placed on this node.
    pub guests: Vec<GuestAddress>,
}

/// One address assigned to a guest on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAddress {
    /// The guest's address as a host prefix (`203.0.113.5/32`).
    pub address: String,
    /// The gateway the guest is configured with.
    ///
    /// It belongs to the range, not to this node, and the guest believes it is
    /// on-link — so the node has to answer for it on the bridge. Sent per
    /// address rather than per node because one node can hold guests from
    /// several ranges.
    pub gateway: String,
    /// The guest's MAC, when one is recorded. Lets the node bind an address to
    /// a port rather than trusting whatever claims it.
    pub mac: Option<String>,
}

impl NodeDataPlane {
    /// The gateway addresses this node has to answer for, deduplicated.
    pub fn gateways(&self) -> Vec<String> {
        let mut out: Vec<String> = self.guests.iter().map(|g| g.gateway.clone()).collect();
        out.sort();
        out.dedup();
        out
    }
}

/// A marketplace node's data plane.
///
/// Holds the database once rather than taking it as an argument to every
/// function, the same shape as [`crate::provisioner::wg::TunnelProvisioner`]
/// and [`lnvps_api_common::NetworkProvisioner`].
pub struct MarketplaceTunnels {
    db: Arc<dyn LNVpsDb>,
}

impl MarketplaceTunnels {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// Fetch a node's existing data plane, if it has one.
    pub async fn get_tunnel(&self, node: &MarketplaceNode) -> Result<Option<NodeTunnel>> {
        let Some(tunnel_id) = node.tunnel_id else {
            return Ok(None);
        };
        let tunnel = self.db.get_tunnel(tunnel_id).await?;
        let pool_id = tunnel
            .pool_id
            .ok_or_else(|| anyhow!("Tunnel {tunnel_id} was not allocated from a pool"))?;
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        Ok(Some(NodeTunnel { tunnel, pool }))
    }

    /// Allocate (or return) the data plane for `node`, keyed to `peer_pubkey`.
    ///
    /// Idempotent: a node that asks twice gets the allocation it already has. A
    /// node presenting a *different* key has regenerated its keypair — restored
    /// from backup, state directory lost — and the key is re-pinned rather than
    /// refused, for the same reason its TLS certificate can be: the alternative is
    /// a machine that can never be reached again. The addresses do not move, so
    /// nothing downstream has to be re-plumbed.
    pub async fn allocate(&self, node: &MarketplaceNode, peer_pubkey: &[u8]) -> Result<NodeTunnel> {
        if peer_pubkey.len() != 32 {
            bail!(
                "A WireGuard public key is 32 bytes, got {}",
                peer_pubkey.len()
            );
        }

        // Placement, addresses and payouts all hang off approval. A pending node
        // asking for a tunnel is asking to be treated as approved.
        if !node.status.accepts_placement() {
            bail!(
                "Node {} is {} and has no data plane; it must be approved first",
                node.id,
                node.status
            );
        }

        if let Some(existing) = self.get_tunnel(node).await? {
            if existing.tunnel.peer_pubkey.as_deref() == Some(peer_pubkey) {
                return Ok(existing);
            }
            let rotated = Tunnel {
                peer_pubkey: Some(peer_pubkey.to_vec()),
                ..existing.tunnel
            };
            self.db.update_tunnel(&rotated).await?;
            return Ok(NodeTunnel {
                tunnel: self.db.get_tunnel(rotated.id).await?,
                pool: existing.pool,
            });
        }

        // The region lives on the backing host, which approval created. A node
        // without one has not been approved, and there is nowhere to put it.
        let host = self
            .db
            .get_marketplace_node_host(node.id)
            .await?
            .ok_or_else(|| anyhow!("Node {} has no backing host to take a region from", node.id))?;

        let operator = self.db.get_marketplace_operator(node.operator_id).await?;

        let pools: Vec<TunnelPool> = self
            .db
            .list_tunnel_pools(Some(host.region_id))
            .await?
            .into_iter()
            .filter(|p| p.enabled)
            .collect();
        if pools.is_empty() {
            bail!(
                "No enabled tunnel pool serves region {}, so this node's guests would have no way \
                 out. Configure a pool on a route server for that region.",
                host.region_id
            );
        }

        // Pools are tried in order and the first with room wins, rather than
        // balancing across them: a second pool in a region exists because the first
        // filled up or is being migrated away from, and spreading nodes over both
        // would leave neither drainable.
        let mut last_error = None;
        for pool in pools {
            match pool.carve(&self.db).await {
                Ok((address4, address6)) => {
                    let tunnel_id = self
                        .db
                        .insert_tunnel(&Tunnel {
                            id: 0,
                            kind: RouterTunnelKind::Wireguard,
                            // The operator's account owns the allocation. A tunnel
                            // with no owner is one nobody can be billed for or have
                            // revoked with their account.
                            user_id: operator.user_id,
                            router_id: Some(pool.router_id),
                            pool_id: Some(pool.id),
                            name: peer_name(node),
                            peer_pubkey: Some(peer_pubkey.to_vec()),
                            // Nodes dial out from behind NAT, so the endpoint is
                            // learned from the handshake rather than configured.
                            peer_endpoint: None,
                            address4,
                            address6,
                            keepalive: pool.keepalive,
                            enabled: true,
                            created: chrono::Utc::now(),
                        })
                        .await?;

                    let linked = MarketplaceNode {
                        tunnel_id: Some(tunnel_id),
                        ..node.clone()
                    };
                    self.db.update_marketplace_node(&linked).await?;

                    let tunnel = self.db.get_tunnel(tunnel_id).await?;
                    let allocation = NodeTunnel { tunnel, pool };

                    // The host's control endpoint is the node's inner address: the
                    // node's control API is only reachable through the tunnel, and
                    // is bound to that address on the node itself. Until now the
                    // host has had a blank `ip`, which every caller must treat as a
                    // hard error rather than dialling something else.
                    let control_address = allocation.control_address()?;
                    let mut host = host;
                    host.ip = control_address;
                    self.db.update_host(&host).await?;

                    return Ok(allocation);
                }
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("No tunnel pool had a free link")))
    }

    /// Assemble the desired data plane for `node`.
    pub async fn dataplane(&self, node: &MarketplaceNode) -> Result<Option<NodeDataPlane>> {
        let Some(tunnel) = self.get_tunnel(node).await? else {
            return Ok(None);
        };
        let mut guests = self.guests(node).await?;
        // The probe's address, in the node's filter whether or not one is running.
        //
        // Sent always rather than when a probe exists, because a probe is created
        // and destroyed between two of the node's polls: a document that named it
        // only while it ran would give a probe that fails because the node had not
        // fetched the document yet, and a node that tears the address down while
        // LNVPS is still logged into it.
        //
        // It costs one address in an anti-spoof list. What it buys is that the
        // check LNVPS makes on an operator's machine never depends on timing.
        if let Some(address) = super::probe_address(&tunnel.tunnel) {
            guests.push(GuestAddress {
                address,
                // The node's own address for probes, which it answers for on the
                // bridge. Deliberately not the route server's: the node holds its
                // guests' gateways itself, so sharing that address with the route
                // server means the guest's replies are delivered to the node and
                // the route server never sees them.
                gateway: super::probe_gateway(&tunnel.tunnel)
                    .and_then(|g| g.split('/').next().map(str::to_string))
                    .unwrap_or_default(),
                mac: Some(super::probe_mac(node.id)),
            });
        }
        guests.sort_by(|a, b| a.address.cmp(&b.address));

        Ok(Some(NodeDataPlane { guests, tunnel }))
    }

    /// The guests placed on `node`, with what each needs to be reachable.
    pub async fn guests(&self, node: &MarketplaceNode) -> Result<Vec<GuestAddress>> {
        let Some(host) = self.db.get_marketplace_node_host(node.id).await? else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        for vm in self.db.list_vms_on_host(host.id).await? {
            if vm.deleted {
                continue;
            }
            for ip in self.db.list_vm_ip_assignments(vm.id).await? {
                if ip.deleted {
                    continue;
                }
                let Some(address) = host_address(Some(&ip.ip)) else {
                    continue;
                };
                // The range is what says which gateway the guest was handed; a
                // node inventing one would answer for an address the guest never
                // uses. Normalised to a bare address because a stored gateway may
                // carry the range's prefix, and the node holds it as a host
                // address on the bridge either way.
                let range = self.db.get_ip_range(ip.ip_range_id).await?;
                let gateway = lnvps_api_common::parse_gateway(&range.gateway)
                    .map(|g| g.ip().to_string())
                    .unwrap_or(range.gateway);
                out.push(GuestAddress {
                    address,
                    gateway,
                    mac: Some(vm.mac_address.clone()).filter(|m| !m.is_empty()),
                });
            }
        }
        out.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(out)
    }

    /// Recompute what is routed behind every marketplace node peer in `pool`.
    ///
    /// The planner reads `tunnel_route` and asks no questions; this is where the
    /// answers come from for a node. Run before a reconcile rather than written at
    /// each point a guest address changes: a missed write would black-hole a
    /// customer's VM until somebody noticed, while a recompute is corrected on the
    /// next pass, in the same way the rest of the reconcile is.
    ///
    /// A pool terminating a VPN service has no tunnels of its own — a device's peer
    /// has a NULL `pool_id` — so this is a no-op there without needing to ask what
    /// kind of pool it is.
    pub async fn refresh_routes(&self, pool: &TunnelPool) -> Result<()> {
        for tunnel in self.db.list_tunnels_in_pool(pool.id).await? {
            let mut prefixes = self.guest_addresses(&tunnel).await?;
            // The node's probe address, always — a probe is created and destroyed
            // between polls, and reconfiguring the route server for the few minutes
            // one exists would mean a probe that fails because the routing had not
            // caught up. It costs one host route on a peer that already has one.
            prefixes.extend(super::probe_address(&tunnel));
            self.db.replace_tunnel_routes(tunnel.id, &prefixes).await?;
        }
        Ok(())
    }

    /// The public addresses assigned to the guests running on `tunnel`'s node.
    ///
    /// Empty for a tunnel that is not a marketplace node's, or a node with no
    /// guests yet — a node is realised before it has customers, and the peer exists
    /// so it can be given some.
    async fn guest_addresses(&self, tunnel: &Tunnel) -> Result<Vec<String>> {
        let Some(node) = self.db.get_marketplace_node_by_tunnel(tunnel.id).await? else {
            return Ok(vec![]);
        };
        let Some(host) = self.db.get_marketplace_node_host(node.id).await? else {
            return Ok(vec![]);
        };

        let mut out = Vec::new();
        for vm in self.db.list_vms_on_host(host.id).await? {
            if vm.deleted {
                continue;
            }
            for ip in self.db.list_vm_ip_assignments(vm.id).await? {
                // A freed assignment must stop being routed here immediately: the
                // address goes back in the pool and may already be somebody
                // else's.
                if ip.deleted {
                    continue;
                }
                if let Some(addr) = host_address(Some(&ip.ip)) {
                    out.push(addr);
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// The peer name configured on the route server. Derived from the node id so it
/// is stable across renames and unique across the fleet — an operator's label
/// is neither.
fn peer_name(node: &MarketplaceNode) -> String {
    format!("mkt-node-{}", node.id)
}

#[cfg(test)]
mod tests;

impl NodeTunnel {
    /// The address LNVPS dials the node's control API on.
    ///
    /// IPv4 when the pool has one, otherwise IPv6 in bracketed form so it can
    /// be used where a host:port is expected.
    pub fn control_address(&self) -> Result<String> {
        if let Some(addr4) = self.tunnel.address4.as_deref() {
            let net: IpNetwork = addr4.parse()?;
            return Ok(net.ip().to_string());
        }
        if let Some(addr6) = self.tunnel.address6.as_deref() {
            let net: IpNetwork = addr6.parse()?;
            return Ok(format!("[{}]", net.ip()));
        }
        bail!("Tunnel {} has no inner address", self.tunnel.id)
    }
}
