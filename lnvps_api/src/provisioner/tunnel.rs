//! Allocating a marketplace node's data plane.
//!
//! A node's guests use LNVPS addresses, so their traffic has to reach an LNVPS
//! route server before it reaches the internet. That is a WireGuard tunnel: the
//! node dials out, the route server terminates it, and the guest prefixes are
//! routed down it.
//!
//! This module hands out the two things LNVPS decides — the inner point-to-point
//! addresses and which route server terminates them — and records the one thing
//! the node decides: its public key. The private half never leaves the
//! operator's machine, which is why the key arrives here rather than being
//! generated for them.
//!
//! Realising the peer on the route server is increment 4b. An allocation is
//! paperwork, not a working tunnel, so the backing host stays disabled.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use ipnetwork::IpNetwork;
use lnvps_db::{LNVpsDb, MarketplaceNode, RouterTunnelKind, Tunnel, TunnelPool};

use crate::provisioner::allocate_subnet;
use crate::router::WireguardPeer;

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

/// The route server's own address in `cidr`, as CIDR carrying the block's
/// prefix (`10.66.0.1/16`).
///
/// The first usable address of the block, so it is fixed for the life of the
/// pool: it is handed to every node as their gateway, and a value that moved
/// when the block was edited would strand all of them at once.
///
/// Carries the block's prefix rather than a host prefix so the route server
/// treats the whole pool as on-link — that is what makes one address serve
/// every node.
pub fn server_address(cidr: Option<&str>) -> Option<String> {
    let net: IpNetwork = cidr?.parse().ok()?;
    let first = next_address(&net)?;
    Some(format!("{first}/{}", net.prefix()))
}

/// The address one above the network address of `net`.
fn next_address(net: &IpNetwork) -> Option<std::net::IpAddr> {
    Some(match net {
        IpNetwork::V4(v4) => {
            std::net::Ipv4Addr::from(u32::from(v4.network()).checked_add(1)?).into()
        }
        IpNetwork::V6(v6) => {
            std::net::Ipv6Addr::from(u128::from(v6.network()).checked_add(1)?).into()
        }
    })
}

/// `10.66.0.1/16` -> `10.66.0.1`.
fn bare_address(cidr: &str) -> String {
    cidr.split_once('/').map_or(cidr, |(a, _)| a).to_string()
}

/// A node holds a single address, not a link.
///
/// WireGuard needs no gateway on the node's side (`ip route add default dev
/// wg0` is enough on a point-to-point layer 3 interface), so a /31 spent two
/// addresses to describe something that needs one — and forced the route server
/// to carry an address per node.
const NODE_PREFIX_V4: u8 = 32;
const NODE_PREFIX_V6: u8 = 128;

/// Fetch a node's existing data plane, if it has one.
pub async fn get_node_tunnel(
    db: &Arc<dyn LNVpsDb>,
    node: &MarketplaceNode,
) -> Result<Option<NodeTunnel>> {
    let Some(tunnel_id) = node.tunnel_id else {
        return Ok(None);
    };
    let tunnel = db.get_tunnel(tunnel_id).await?;
    let pool_id = tunnel
        .pool_id
        .ok_or_else(|| anyhow!("Tunnel {tunnel_id} was not allocated from a pool"))?;
    let pool = db.get_tunnel_pool(pool_id).await?;
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
pub async fn allocate_node_tunnel(
    db: &Arc<dyn LNVpsDb>,
    node: &MarketplaceNode,
    peer_pubkey: &[u8],
) -> Result<NodeTunnel> {
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

    if let Some(existing) = get_node_tunnel(db, node).await? {
        if existing.tunnel.peer_pubkey.as_deref() == Some(peer_pubkey) {
            return Ok(existing);
        }
        let rotated = Tunnel {
            peer_pubkey: Some(peer_pubkey.to_vec()),
            ..existing.tunnel
        };
        db.update_tunnel(&rotated).await?;
        return Ok(NodeTunnel {
            tunnel: db.get_tunnel(rotated.id).await?,
            pool: existing.pool,
        });
    }

    // The region lives on the backing host, which approval created. A node
    // without one has not been approved, and there is nowhere to put it.
    let host = db
        .get_marketplace_node_host(node.id)
        .await?
        .ok_or_else(|| anyhow!("Node {} has no backing host to take a region from", node.id))?;

    let operator = db.get_marketplace_operator(node.operator_id).await?;

    let pools: Vec<TunnelPool> = db
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
        match carve_link(db, &pool).await {
            Ok((address4, address6)) => {
                let tunnel_id = db
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
                db.update_marketplace_node(&linked).await?;

                let tunnel = db.get_tunnel(tunnel_id).await?;
                let allocation = NodeTunnel { tunnel, pool };

                // The host's control endpoint is the node's inner address: the
                // node's control API is only reachable through the tunnel, and
                // is bound to that address on the node itself. Until now the
                // host has had a blank `ip`, which every caller must treat as a
                // hard error rather than dialling something else.
                let control_address = allocation.control_address()?;
                let mut host = host;
                host.ip = control_address;
                db.update_host(&host).await?;

                return Ok(allocation);
            }
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("No tunnel pool had a free link")))
}

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

/// The peer name configured on the route server. Derived from the node id so it
/// is stable across renames and unique across the fleet — an operator's label
/// is neither.
fn peer_name(node: &MarketplaceNode) -> String {
    format!("mkt-node-{}", node.id)
}

/// Carve the next free link out of `pool`, returning `(address4, address6)` in
/// the peer's own form (`10.0.0.2/32`).
///
/// A pool with both blocks must supply both halves: a node given only one
/// family would silently be single-stack, which is the kind of thing that is
/// discovered by a customer rather than by us.
async fn carve_link(
    db: &Arc<dyn LNVpsDb>,
    pool: &TunnelPool,
) -> Result<(Option<String>, Option<String>)> {
    let taken: Vec<IpNetwork> = db
        .list_tunnels_in_pool(pool.id)
        .await?
        .iter()
        .flat_map(|t| [t.address4.clone(), t.address6.clone()])
        .flatten()
        .filter_map(|a| a.parse::<IpNetwork>().ok())
        .collect();

    let address4 = match pool.cidr4.as_deref() {
        Some(cidr) => Some(carve_one(cidr, NODE_PREFIX_V4, &taken, pool)?),
        None => None,
    };
    let address6 = match pool.cidr6.as_deref() {
        Some(cidr) => Some(carve_one(cidr, NODE_PREFIX_V6, &taken, pool)?),
        None => None,
    };
    Ok((address4, address6))
}

/// Addresses in `cidr` that are not the pool's to hand out.
///
/// The route server holds the whole block on-link, so the addresses that block
/// reserves are reserved here too: its network address, the route server's own
/// address immediately after it, and — on IPv4 — its broadcast address.
/// Handing any of them to a node would produce an address the route server
/// itself will not forward to.
pub fn reserved_addresses(cidr: &str) -> Vec<IpNetwork> {
    let Ok(net) = cidr.parse::<IpNetwork>() else {
        return vec![];
    };
    let mut out = vec![IpNetwork::from(net.network())];
    if let Some(server) = server_address(Some(cidr))
        && let Ok(addr) = bare_address(&server).parse::<IpNetwork>()
    {
        out.push(addr);
    }
    if let IpNetwork::V4(v4) = net {
        out.push(IpNetwork::from(std::net::IpAddr::from(v4.broadcast())));
    }
    out
}

fn carve_one(cidr: &str, prefix: u8, taken: &[IpNetwork], pool: &TunnelPool) -> Result<String> {
    let block: IpNetwork = cidr.parse().map_err(|e| {
        anyhow!(
            "Tunnel pool {} has an unparseable block {cidr}: {e}",
            pool.id
        )
    })?;
    let mut taken = taken.to_vec();
    taken.extend(reserved_addresses(cidr));
    let addr = allocate_subnet(&block, prefix, &taken).ok_or_else(|| {
        anyhow!(
            "Tunnel pool {} has no free /{prefix} left in {cidr}",
            pool.id
        )
    })?;
    Ok(addr.to_string())
}

/// What one pool's interface should have configured on its route server.
///
/// Computed in one pass over the pool's tunnels because the three parts are
/// answers to the same question and must agree: an address without its peer is
/// a link to nowhere, a peer without its route drops the guest traffic it was
/// created to carry, and a route to a peer that is not there is a black hole.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PoolPlan {
    /// Addresses on the interface — the route server's side of each link.
    pub addresses: Vec<String>,
    /// One peer per realisable tunnel.
    pub peers: Vec<WireguardPeer>,
    /// Guest prefixes routed down the interface.
    pub routes: Vec<String>,
}

/// Work out what `pool`'s interface should look like.
///
/// A tunnel that cannot be realised — disabled, or with no key presented yet —
/// contributes nothing at all, not an empty peer: half-configuring it would
/// give the node a link with no way to authenticate over it.
pub async fn plan_pool(db: &Arc<dyn LNVpsDb>, pool: &TunnelPool) -> Result<PoolPlan> {
    let mut plan = PoolPlan::default();

    // One address for the whole pool, carrying the block's prefix so every
    // node in it is on-link. A per-node address would put one address on this
    // interface for every node on the route server — thousands, on a /16 — to
    // describe links that WireGuard, being layer 3 and point-to-point, does
    // not need described.
    plan.addresses.extend(
        [
            server_address(pool.cidr4.as_deref()),
            server_address(pool.cidr6.as_deref()),
        ]
        .into_iter()
        .flatten(),
    );

    // The pool's own blocks are routed down the interface as well. An address
    // on a point-to-point interface does not give the kernel a route to the
    // rest of its prefix, so without this the route server holds
    // `10.66.0.1/16` and still answers "network is unreachable" for every node
    // in it. Found by the end-to-end harness rather than by reading the code.
    plan.routes.extend(
        [pool.cidr4.as_deref(), pool.cidr6.as_deref()]
            .into_iter()
            .flatten()
            .map(str::to_string),
    );

    for tunnel in db.list_tunnels_in_pool(pool.id).await? {
        if !tunnel.enabled {
            continue;
        }
        let Some(key) = tunnel.peer_pubkey.as_deref() else {
            continue;
        };

        // AllowedIPs is both the routing table for this peer and the
        // anti-spoof boundary: WireGuard drops an inbound packet whose source
        // is not listed, so a node cannot claim another node's guest address.
        let mut allowed_ips: Vec<String> = [
            host_address(tunnel.address4.as_deref()),
            host_address(tunnel.address6.as_deref()),
        ]
        .into_iter()
        .flatten()
        .collect();

        let mut guests = guest_addresses(db, &tunnel).await?;
        // The node's probe address, always — a probe is created and destroyed
        // between polls, and reconfiguring the route server for the few minutes
        // one exists would mean a probe that fails because the routing had not
        // caught up. It costs one host route on a peer that already has one.
        guests.extend(super::probe_address(&tunnel));
        allowed_ips.extend(guests.iter().cloned());
        plan.routes.extend(guests);

        plan.peers.push(WireguardPeer {
            public_key: lnvps_api_common::wireguard_key_to_base64(key),
            // Nodes dial out from behind NAT; the endpoint is learned from the
            // handshake. Configuring a stale one would stop the peer from
            // being reachable after the node's address changes.
            endpoint: tunnel.peer_endpoint.clone(),
            allowed_ips,
            persistent_keepalive: tunnel.keepalive,
        });
    }
    Ok(plan)
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

/// Assemble the desired data plane for `node`.
pub async fn node_dataplane(
    db: &Arc<dyn LNVpsDb>,
    node: &MarketplaceNode,
) -> Result<Option<NodeDataPlane>> {
    let Some(tunnel) = get_node_tunnel(db, node).await? else {
        return Ok(None);
    };
    let mut guests = node_guests(db, node).await?;
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
            // Its gateway is the route server, which is where everything on
            // this node's tunnel goes.
            gateway: tunnel
                .gateway6()
                .and_then(|g| g.split('/').next().map(str::to_string))
                .unwrap_or_default(),
            mac: Some(super::probe_mac(node.id)),
        });
    }
    guests.sort_by(|a, b| a.address.cmp(&b.address));

    Ok(Some(NodeDataPlane { guests, tunnel }))
}

/// The guests placed on `node`, with what each needs to be reachable.
pub async fn node_guests(
    db: &Arc<dyn LNVpsDb>,
    node: &MarketplaceNode,
) -> Result<Vec<GuestAddress>> {
    let Some(host) = db.get_marketplace_node_host(node.id).await? else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for vm in db.list_vms_on_host(host.id).await? {
        if vm.deleted {
            continue;
        }
        for ip in db.list_vm_ip_assignments(vm.id).await? {
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
            let range = db.get_ip_range(ip.ip_range_id).await?;
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

/// The public addresses assigned to the guests running on `tunnel`'s node.
///
/// Empty for a tunnel that is not a marketplace node's, or a node with no
/// guests yet — a node is realised before it has customers, and the peer exists
/// so it can be given some.
async fn guest_addresses(db: &Arc<dyn LNVpsDb>, tunnel: &Tunnel) -> Result<Vec<String>> {
    let Some(node) = db.get_marketplace_node_by_tunnel(tunnel.id).await? else {
        return Ok(vec![]);
    };
    let Some(host) = db.get_marketplace_node_host(node.id).await? else {
        return Ok(vec![]);
    };

    let mut out = Vec::new();
    for vm in db.list_vms_on_host(host.id).await? {
        if vm.deleted {
            continue;
        }
        for ip in db.list_vm_ip_assignments(vm.id).await? {
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

/// A single address as a host prefix (`/32` or `/128`).
///
/// Accepts either a bare address or one already carrying a prefix, because
/// tunnel addresses are stored as CIDR and guest assignments as bare addresses.
fn host_address(addr: Option<&str>) -> Option<String> {
    let addr = addr?;
    let ip: std::net::IpAddr = match addr.split_once('/') {
        Some((a, _)) => a.parse().ok()?,
        None => addr.parse().ok()?,
    };
    Some(match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}/32"),
        std::net::IpAddr::V6(v6) => format!("{v6}/128"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{
        MarketplaceNodeStatus, MarketplaceOperator, Router, RouterKind, TunnelPool, VmHost,
        VmHostKind,
    };

    const NODE_KEY: [u8; 32] = [0x11; 32];
    const OTHER_KEY: [u8; 32] = [0x22; 32];

    /// An approved node with a backing host in region 1, plus a pool serving it.
    ///
    /// The concrete `MockDb` is handed back alongside the trait object because
    /// routers have no insert on the non-admin trait, and a pool needs one.
    async fn fixture() -> (Arc<dyn LNVpsDb>, MockDb, MarketplaceNode, u64) {
        let mock = MockDb::default();
        let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
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
                tls_fingerprint: Some(vec![0xab; 32]),
                status: MarketplaceNodeStatus::Approved,
                ..Default::default()
            })
            .await
            .unwrap();
        db.create_host(&VmHost {
            kind: VmHostKind::MarketplaceNode,
            region_id: 1,
            name: "node-host".to_string(),
            ip: String::new(),
            enabled: false,
            marketplace_node_id: Some(node_id),
            ..Default::default()
        })
        .await
        .unwrap();

        let pool_id = pool(&db, &mock, "10.66.0.0/24", Some("fd00:66::/64"), "wg-mkt0").await;
        let node = db.get_marketplace_node(node_id).await.unwrap();
        (db, mock, node, pool_id)
    }

    /// Insert a route server. `router` has no insert on the customer-facing DB
    /// trait (it is admin-only), so the mock's map is written directly.
    async fn add_router(mock: &MockDb, name: &str) -> u64 {
        let mut routers = mock.router.lock().await;
        let id = routers.keys().max().copied().unwrap_or(0) + 1;
        routers.insert(
            id,
            Router {
                id,
                name: name.to_string(),
                enabled: true,
                kind: RouterKind::MockRouter,
                url: "mock://rs".to_string(),
                token: "t".into(),
            },
        );
        id
    }

    async fn pool(
        db: &Arc<dyn LNVpsDb>,
        mock: &MockDb,
        cidr4: &str,
        cidr6: Option<&str>,
        interface: &str,
    ) -> u64 {
        let router_id = add_router(mock, &format!("rs-{interface}")).await;
        db.insert_tunnel_pool(&TunnelPool {
            router_id,
            region_id: 1,
            name: format!("pool-{interface}"),
            listen_addr: "rs.example".to_string(),
            listen_port: 51820,
            private_key: lnvps_api_common::generate_wireguard_keypair()
                .unwrap()
                .private_key
                .into(),
            public_key: vec![0x33; 32],
            cidr4: Some(cidr4.to_string()),
            cidr6: cidr6.map(str::to_string),
            keepalive: Some(25),
            mtu: 1420,
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// The first allocation takes one address of each family — the first the
    /// block has left, after its own network address and the route server's.
    #[tokio::test]
    async fn allocating_takes_the_first_free_address_in_both_families() {
        let (db, _mock, node, pool_id) = fixture().await;

        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        assert_eq!(allocation.tunnel.address4.as_deref(), Some("10.66.0.2/32"));
        assert_eq!(
            allocation.tunnel.address6.as_deref(),
            Some("fd00:66::2/128")
        );
        // One gateway for the whole pool, not one per node: the route server
        // holds a single address and every node in the block is on-link to it.
        assert_eq!(allocation.gateway4().as_deref(), Some("10.66.0.1"));
        assert_eq!(allocation.gateway6().as_deref(), Some("fd00:66::1"));
        assert_eq!(allocation.tunnel.pool_id, Some(pool_id));
        assert_eq!(allocation.tunnel.kind, RouterTunnelKind::Wireguard);
        assert_eq!(
            allocation.tunnel.peer_pubkey.as_deref(),
            Some(&NODE_KEY[..])
        );
        assert_eq!(allocation.tunnel.keepalive, Some(25));

        // The node now points at its data plane...
        let node = db.get_marketplace_node(node.id).await.unwrap();
        assert_eq!(node.tunnel_id, Some(allocation.tunnel.id));

        // ...and the host has a control endpoint at last, but is still off:
        // an allocation is paperwork, not a working tunnel.
        let host = db
            .get_marketplace_node_host(node.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host.ip, "10.66.0.2");
        assert!(!host.enabled);
    }

    /// Two nodes must never share an address; the second takes the next one.
    #[tokio::test]
    async fn a_second_node_gets_the_next_address() {
        let (db, _mock, first, _) = fixture().await;
        allocate_node_tunnel(&db, &first, &NODE_KEY).await.unwrap();

        let second_id = db
            .insert_marketplace_node(&MarketplaceNode {
                operator_id: first.operator_id,
                name: "rack 2".to_string(),
                tls_fingerprint: Some(vec![0xcd; 32]),
                status: MarketplaceNodeStatus::Approved,
                ..Default::default()
            })
            .await
            .unwrap();
        db.create_host(&VmHost {
            kind: VmHostKind::MarketplaceNode,
            region_id: 1,
            name: "node-host-2".to_string(),
            enabled: false,
            marketplace_node_id: Some(second_id),
            ..Default::default()
        })
        .await
        .unwrap();
        let second = db.get_marketplace_node(second_id).await.unwrap();

        let allocation = allocate_node_tunnel(&db, &second, &OTHER_KEY)
            .await
            .unwrap();
        assert_eq!(allocation.tunnel.address4.as_deref(), Some("10.66.0.3/32"));
        assert_eq!(
            allocation.tunnel.address6.as_deref(),
            Some("fd00:66::3/128")
        );
    }

    /// A node that retries must not end up with two allocations, each holding
    /// addresses and one of them never realised.
    #[tokio::test]
    async fn asking_twice_returns_the_same_allocation() {
        let (db, _mock, node, _) = fixture().await;
        let first = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();

        let node = db.get_marketplace_node(node.id).await.unwrap();
        let second = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        assert_eq!(first.tunnel.id, second.tunnel.id);
        assert_eq!(db.list_tunnels().await.unwrap().len(), 1);
    }

    /// A node restored from backup presents a new key. Refusing it would leave
    /// a machine that can never be reached again; the addresses stay put, so
    /// nothing downstream moves.
    #[tokio::test]
    async fn a_regenerated_key_is_re_pinned_without_moving_the_addresses() {
        let (db, _mock, node, _) = fixture().await;
        let first = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();

        let node = db.get_marketplace_node(node.id).await.unwrap();
        let rotated = allocate_node_tunnel(&db, &node, &OTHER_KEY).await.unwrap();
        assert_eq!(rotated.tunnel.id, first.tunnel.id);
        assert_eq!(rotated.tunnel.address4, first.tunnel.address4);
        assert_eq!(
            rotated.tunnel.peer_pubkey.as_deref(),
            Some(&OTHER_KEY[..]),
            "the node's new key was not pinned, so its handshake would be refused"
        );
    }

    /// One key belongs to one machine: the uniqueness that makes a handshake
    /// resolve to an allocation.
    #[tokio::test]
    async fn two_nodes_cannot_share_a_key() {
        let (db, _mock, first, _) = fixture().await;
        allocate_node_tunnel(&db, &first, &NODE_KEY).await.unwrap();

        let second_id = db
            .insert_marketplace_node(&MarketplaceNode {
                operator_id: first.operator_id,
                name: "rack 2".to_string(),
                tls_fingerprint: Some(vec![0xcd; 32]),
                status: MarketplaceNodeStatus::Approved,
                ..Default::default()
            })
            .await
            .unwrap();
        db.create_host(&VmHost {
            kind: VmHostKind::MarketplaceNode,
            region_id: 1,
            name: "node-host-2".to_string(),
            marketplace_node_id: Some(second_id),
            ..Default::default()
        })
        .await
        .unwrap();
        let second = db.get_marketplace_node(second_id).await.unwrap();

        assert!(
            allocate_node_tunnel(&db, &second, &NODE_KEY).await.is_err(),
            "two nodes were allowed to share a WireGuard key"
        );
    }

    /// Placement, payouts and addresses all hang off approval.
    #[tokio::test]
    async fn a_node_that_is_not_approved_gets_no_data_plane() {
        let (db, _mock, node, _) = fixture().await;
        let pending = MarketplaceNode {
            status: MarketplaceNodeStatus::Pending,
            ..node
        };
        db.update_marketplace_node(&pending).await.unwrap();
        let pending = db.get_marketplace_node(pending.id).await.unwrap();

        let err = allocate_node_tunnel(&db, &pending, &NODE_KEY)
            .await
            .expect_err("a pending node was given a data plane");
        assert!(format!("{err}").contains("approved"), "{err}");
    }

    /// A key of the wrong length is not a WireGuard key; storing it would fail
    /// every handshake with nothing to point at.
    #[tokio::test]
    async fn a_malformed_key_is_refused() {
        let (db, _mock, node, _) = fixture().await;
        assert!(allocate_node_tunnel(&db, &node, &[1u8; 16]).await.is_err());
    }

    /// A region with no pool cannot carry guest traffic. Saying so beats
    /// allocating something that routes nowhere.
    #[tokio::test]
    async fn a_region_with_no_pool_is_reported_not_guessed() {
        let (db, _mock, node, pool_id) = fixture().await;
        db.delete_tunnel_pool(pool_id).await.unwrap();

        let err = allocate_node_tunnel(&db, &node, &NODE_KEY)
            .await
            .expect_err("a node was allocated a tunnel from nowhere");
        assert!(format!("{err}").contains("No enabled tunnel pool"), "{err}");
    }

    /// A disabled pool is being drained; new nodes must not land in it.
    #[tokio::test]
    async fn a_disabled_pool_takes_no_new_allocations() {
        let (db, _mock, node, pool_id) = fixture().await;
        let mut pool = db.get_tunnel_pool(pool_id).await.unwrap();
        pool.enabled = false;
        db.update_tunnel_pool(&pool).await.unwrap();

        assert!(allocate_node_tunnel(&db, &node, &NODE_KEY).await.is_err());
    }

    /// A full pool is not a silent failure: the next pool in the region takes
    /// the node, which is why a second pool is added in the first place.
    #[tokio::test]
    async fn a_full_pool_falls_through_to_the_next_one() {
        let (db, mock, node, first_pool) = fixture().await;
        // A /30 holds one placeable address once the network, route server and
        // broadcast addresses are reserved — and it is already taken.
        let mut tiny = db.get_tunnel_pool(first_pool).await.unwrap();
        tiny.cidr4 = Some("10.66.0.0/30".to_string());
        tiny.cidr6 = None;
        db.update_tunnel_pool(&tiny).await.unwrap();
        let user_id = db
            .get_marketplace_operator(node.operator_id)
            .await
            .unwrap()
            .user_id;
        db.insert_tunnel(&Tunnel {
            kind: RouterTunnelKind::Wireguard,
            user_id,
            router_id: Some(tiny.router_id),
            pool_id: Some(tiny.id),
            name: "squatter".to_string(),
            address4: Some("10.66.0.2/32".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let spare = pool(&db, &mock, "10.77.0.0/24", None, "wg-mkt1").await;
        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        assert_eq!(allocation.tunnel.pool_id, Some(spare));
        assert_eq!(allocation.tunnel.address4.as_deref(), Some("10.77.0.2/32"));
    }

    /// A pool on a different router than the tunnel claims is a peer
    /// configured on an interface that is not there. The database rejects it
    /// through the composite key; the mock mirrors that.
    #[tokio::test]
    async fn a_tunnel_cannot_claim_a_pool_on_another_router() {
        let (db, mock, node, pool_id) = fixture().await;
        let other_router = add_router(&mock, "elsewhere").await;
        let user_id = db
            .get_marketplace_operator(node.operator_id)
            .await
            .unwrap()
            .user_id;

        assert!(
            db.insert_tunnel(&Tunnel {
                kind: RouterTunnelKind::Wireguard,
                user_id,
                router_id: Some(other_router),
                pool_id: Some(pool_id),
                name: "drift".to_string(),
                ..Default::default()
            })
            .await
            .is_err(),
            "a tunnel pointed at a pool on a router it does not belong to"
        );
    }

    /// An IPv6-only pool still yields a reachable control address, in the
    /// bracketed form a host:port needs.
    #[tokio::test]
    async fn an_ipv6_only_pool_gives_a_bracketed_control_address() {
        let (db, _mock, node, pool_id) = fixture().await;
        let mut v6_only = db.get_tunnel_pool(pool_id).await.unwrap();
        v6_only.cidr4 = None;
        db.update_tunnel_pool(&v6_only).await.unwrap();

        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        assert_eq!(allocation.tunnel.address4, None);
        assert_eq!(allocation.control_address().unwrap(), "[fd00:66::2]");
        let host = db
            .get_marketplace_node_host(node.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host.ip, "[fd00:66::2]");
    }

    /// Reading back an allocation is how the node re-reads its configuration
    /// after a restart.
    #[tokio::test]
    async fn a_node_can_read_back_its_allocation() {
        let (db, _mock, node, _) = fixture().await;
        assert!(get_node_tunnel(&db, &node).await.unwrap().is_none());

        let allocated = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        let node = db.get_marketplace_node(node.id).await.unwrap();
        let read = get_node_tunnel(&db, &node).await.unwrap().unwrap();
        assert_eq!(read.tunnel.id, allocated.tunnel.id);
        assert_eq!(read.pool.endpoint(), "rs.example:51820");
        assert_eq!(read.pool.mtu, 1420);
    }

    /// The route server takes one address for the whole pool, and the block's
    /// own reserved addresses are not the pool's to hand out: giving a node the
    /// network or broadcast address of a block the route server holds on-link
    /// produces an address it will not forward to.
    #[test]
    fn the_block_keeps_its_reserved_addresses() {
        assert_eq!(
            server_address(Some("10.66.0.0/16")).as_deref(),
            Some("10.66.0.1/16")
        );
        assert_eq!(
            server_address(Some("fd00:66::/48")).as_deref(),
            Some("fd00:66::1/48")
        );

        let reserved: Vec<String> = reserved_addresses("10.66.0.0/16")
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert_eq!(reserved, ["10.66.0.0", "10.66.0.1", "10.66.255.255"]);

        // IPv6 has no broadcast address, but the subnet-router anycast address
        // is still not a node's.
        let reserved: Vec<String> = reserved_addresses("fd00:66::/64")
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        assert_eq!(reserved, ["fd00:66::", "fd00:66::1"]);

        // Nothing to reserve out of a block nobody can parse; the allocator
        // reports that against the pool.
        assert!(reserved_addresses("not-a-cidr").is_empty());
        assert_eq!(server_address(None), None);
    }

    /// A tunnel with no address is unreachable, and saying so beats handing
    /// back an empty host that something later dials.
    #[test]
    fn a_tunnel_with_no_address_has_no_control_endpoint() {
        let orphan = NodeTunnel {
            tunnel: lnvps_db::Tunnel {
                id: 7,
                ..Default::default()
            },
            pool: TunnelPool::default(),
        };
        assert!(orphan.control_address().is_err());
        assert_eq!(orphan.gateway4(), None);
        assert_eq!(orphan.gateway6(), None);
    }

    /// A pool whose block is unparseable must be reported against that pool,
    /// not swallowed as "no space".
    #[tokio::test]
    async fn an_unparseable_block_is_reported() {
        let (db, _mock, node, pool_id) = fixture().await;
        let mut broken = db.get_tunnel_pool(pool_id).await.unwrap();
        broken.cidr4 = Some("not-a-cidr".to_string());
        db.update_tunnel_pool(&broken).await.unwrap();

        let err = allocate_node_tunnel(&db, &node, &NODE_KEY)
            .await
            .expect_err("an unparseable block allocated an address");
        assert!(format!("{err}").contains("unparseable block"), "{err}");
    }

    /// A realised peer is the anti-spoof boundary: `AllowedIPs` is the node's
    /// own inner addresses plus exactly the guest addresses LNVPS assigned to
    /// it, so a node cannot source traffic as another node's customer.
    #[tokio::test]
    async fn a_peer_allows_the_node_its_own_addresses_and_its_guests() {
        let (db, mock, node, pool_id) = fixture().await;
        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        let host = db
            .get_marketplace_node_host(node.id)
            .await
            .unwrap()
            .unwrap();
        add_guest(&db, &mock, host.id, &["203.0.113.5", "2001:db8::5"]).await;

        let pool = db.get_tunnel_pool(pool_id).await.unwrap();
        let plan = plan_pool(&db, &pool).await.unwrap();

        assert_eq!(plan.peers.len(), 1);
        let peer = &plan.peers[0];
        assert_eq!(
            peer.public_key,
            lnvps_api_common::wireguard_key_to_base64(&NODE_KEY)
        );
        // The probe address is here too, and always: a probe exists for a few
        // minutes between two of the node's polls, and reconfiguring the route
        // server around that window would mean probes that fail because the
        // routing had not caught up yet.
        assert!(
            peer.allowed_ips.contains(&"fd00:66::8002/128".to_string()),
            "{:?}",
            peer.allowed_ips
        );
        assert_eq!(
            peer.allowed_ips,
            vec![
                "10.66.0.2/32".to_string(),
                "fd00:66::2/128".to_string(),
                "2001:db8::5/128".to_string(),
                "203.0.113.5/32".to_string(),
                "fd00:66::8002/128".to_string(),
            ]
        );
        assert_eq!(peer.persistent_keepalive, Some(25));

        // One address for the whole pool, carrying the block's prefix so every
        // node in it is on-link. A per-node address would put one address on
        // this interface for every node on the route server.
        assert_eq!(
            plan.addresses,
            vec!["10.66.0.1/24".to_string(), "fd00:66::1/64".to_string()]
        );
        // ...the pool's own blocks, because an address on a point-to-point
        // interface does not route the rest of its prefix, and every node in
        // the pool lives in it...
        assert!(
            plan.routes.contains(&"10.66.0.0/24".to_string()),
            "{plan:?}"
        );
        assert!(
            plan.routes.contains(&"fd00:66::/64".to_string()),
            "{plan:?}"
        );
        // ...and a route for each guest address, because AllowedIPs picks the
        // peer for a packet already headed down the tunnel, it does not put it
        // there.
        assert!(
            plan.routes.contains(&"2001:db8::5/128".to_string()),
            "{plan:?}"
        );
        assert!(
            plan.routes.contains(&"203.0.113.5/32".to_string()),
            "{plan:?}"
        );
        assert_eq!(allocation.tunnel.pool_id, Some(pool_id));
    }

    /// A freed address must stop being routed to the node at once: it goes
    /// straight back in the pool and may already be somebody else's.
    #[tokio::test]
    async fn a_released_guest_address_is_not_routed() {
        let (db, mock, node, pool_id) = fixture().await;
        allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        let host = db
            .get_marketplace_node_host(node.id)
            .await
            .unwrap()
            .unwrap();
        let vm_id = add_guest(&db, &mock, host.id, &["203.0.113.5"]).await;

        // Release the address, leaving the VM in place.
        {
            let mut ips = mock.ip_assignments.lock().await;
            for ip in ips.values_mut().filter(|i| i.vm_id == vm_id) {
                ip.deleted = true;
            }
        }
        let pool = db.get_tunnel_pool(pool_id).await.unwrap();
        let plan = plan_pool(&db, &pool).await.unwrap();
        assert!(!plan.routes.iter().any(|r| r.starts_with("203.0.113")));
        assert_eq!(
            plan.peers[0].allowed_ips.len(),
            3,
            "the node's own two addresses and its probe address, nothing else"
        );

        // A deleted VM takes its addressing with it for the same reason.
        {
            let mut ips = mock.ip_assignments.lock().await;
            for ip in ips.values_mut().filter(|i| i.vm_id == vm_id) {
                ip.deleted = false;
            }
            let mut vms = mock.vms.lock().await;
            if let Some(vm) = vms.get_mut(&vm_id) {
                vm.deleted = true;
            }
        }
        let plan = plan_pool(&db, &pool).await.unwrap();
        assert!(!plan.routes.iter().any(|r| r.starts_with("203.0.113")));
    }

    /// A tunnel that cannot be realised contributes nothing at all, rather than
    /// an empty peer: a link with no key is one the node cannot authenticate
    /// over, and an address on it would be a link to nowhere.
    #[tokio::test]
    async fn an_unrealisable_tunnel_is_left_out_entirely() {
        let (db, _mock, node, pool_id) = fixture().await;
        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        let pool = db.get_tunnel_pool(pool_id).await.unwrap();

        for broken in [
            Tunnel {
                enabled: false,
                ..allocation.tunnel.clone()
            },
            Tunnel {
                peer_pubkey: None,
                ..allocation.tunnel.clone()
            },
        ] {
            db.update_tunnel(&broken).await.unwrap();
            let plan = plan_pool(&db, &pool).await.unwrap();
            assert!(plan.peers.is_empty());
            // The pool's blocks are routed whether or not anything is placed
            // in it; the interface exists either way.
            assert_eq!(plan.routes.len(), 2);
            // The interface still holds the pool's address: it exists whether
            // or not anything has been placed in it yet.
            assert_eq!(plan.addresses.len(), 2);
        }
    }

    /// A tunnel that is not a node's — a customer VPN carved from the same
    /// pool later — is still a peer, just one with no guests behind it.
    #[tokio::test]
    async fn a_tunnel_with_no_node_behind_it_is_still_a_peer() {
        let (db, mock, _node, pool_id) = fixture().await;
        let user_id = db.upsert_user(&[9u8; 32]).await.unwrap();
        db.insert_tunnel(&Tunnel {
            kind: RouterTunnelKind::Wireguard,
            user_id,
            router_id: Some(db.get_tunnel_pool(pool_id).await.unwrap().router_id),
            pool_id: Some(pool_id),
            name: "vpn".to_string(),
            peer_pubkey: Some(OTHER_KEY.to_vec()),
            address4: Some("10.66.9.1/32".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let pool = db.get_tunnel_pool(pool_id).await.unwrap();
        let plan = plan_pool(&db, &pool).await.unwrap();
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].allowed_ips, vec!["10.66.9.1/32".to_string()]);
        // The pool's own blocks, and nothing a guest brought.
        assert_eq!(plan.routes.len(), 2);
        let _ = mock;
    }

    /// The document is what the node acts on, so it has to carry everything the
    /// node cannot work out for itself: the gateway a guest was configured with
    /// belongs to the range, not to the node, and a node inventing one would
    /// answer for an address no guest uses.
    #[tokio::test]
    async fn the_data_plane_document_describes_the_whole_node() {
        let (db, mock, node, _) = fixture().await;
        allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        let node = db.get_marketplace_node(node.id).await.unwrap();
        let host = db
            .get_marketplace_node_host(node.id)
            .await
            .unwrap()
            .unwrap();
        add_guest(&db, &mock, host.id, &["203.0.113.5", "2001:db8::5"]).await;

        let plane = node_dataplane(&db, &node).await.unwrap().unwrap();
        assert_eq!(
            plane.tunnel.tunnel.address4.as_deref(),
            Some("10.66.0.2/32")
        );
        assert_eq!(
            plane
                .guests
                .iter()
                .map(|g| g.address.as_str())
                .collect::<Vec<_>>(),
            // The customer's two addresses, and the node's probe address, which
            // is present whether or not a probe is running.
            ["2001:db8::5/128", "203.0.113.5/32", "fd00:66::8002/128"]
        );
        // Bare, even though the range stores it with a prefix: the node holds
        // it as a host address on the bridge.
        assert_eq!(plane.guests[0].gateway, "10.0.0.1");
        assert_eq!(plane.guests[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        // Deduplicated: two guests from one range give the node one address to
        // answer for, not two identical ones. The probe's gateway is the route
        // server, which the node answers for on the bridge the same way — a
        // probe VM is configured like any other guest, because a probe
        // configured specially proves nothing about a customer.
        assert_eq!(
            plane.gateways(),
            vec!["10.0.0.1".to_string(), "fd00:66::1".to_string()]
        );
    }

    /// A node with no tunnel has no data plane to describe — saying so beats
    /// returning a document with an empty tunnel that a node would apply.
    #[tokio::test]
    async fn a_node_without_a_tunnel_has_no_document() {
        let (db, _mock, node, _) = fixture().await;
        assert!(node_dataplane(&db, &node).await.unwrap().is_none());
    }

    /// A node with no guests yet is still configured: it is realised before it
    /// has customers, so it can be given some.
    #[tokio::test]
    async fn a_node_with_no_guests_still_has_a_document() {
        let (db, _mock, node, _) = fixture().await;
        allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        let node = db.get_marketplace_node(node.id).await.unwrap();

        let plane = node_dataplane(&db, &node).await.unwrap().unwrap();
        // Not empty: a node with no customers still carries its probe address,
        // so LNVPS can find out whether it could carry one.
        assert_eq!(plane.guests.len(), 1);
        assert_eq!(plane.guests[0].address, "fd00:66::8002/128");
        assert_eq!(
            plane.guests[0].mac.as_deref(),
            Some(&*super::super::probe_mac(node.id))
        );
    }

    /// Give `host` a VM holding `ips`. Written through the mock's maps because
    /// a VM needs a template, an image and a disk that this test does not care
    /// about.
    async fn add_guest(db: &Arc<dyn LNVpsDb>, mock: &MockDb, host_id: u64, ips: &[&str]) -> u64 {
        let vm_id = {
            let mut vms = mock.vms.lock().await;
            let id = vms.keys().max().copied().unwrap_or(0) + 1;
            vms.insert(
                id,
                lnvps_db::Vm {
                    id,
                    host_id,
                    mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                    ..Default::default()
                },
            );
            id
        };
        for ip in ips {
            db.insert_vm_ip_assignment(&lnvps_db::VmIpAssignment {
                vm_id,
                ip: ip.to_string(),
                ip_range_id: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        vm_id
    }
}
