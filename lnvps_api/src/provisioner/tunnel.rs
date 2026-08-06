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
    /// The route server's address on the inner link.
    ///
    /// Derived from the node's own address rather than stored: on a /31 (or
    /// /127) there are exactly two addresses, LNVPS takes the first and the
    /// node the second. A stored copy would be a second answer to a question
    /// that already has one.
    pub fn gateway4(&self) -> Option<String> {
        link_gateway(self.tunnel.address4.as_deref())
    }

    /// The route server's address on the inner IPv6 link.
    pub fn gateway6(&self) -> Option<String> {
        link_gateway(self.tunnel.address6.as_deref())
    }
}

/// The first address of the link `addr` sits on, as plain text.
fn link_gateway(addr: Option<&str>) -> Option<String> {
    let net: IpNetwork = addr?.parse().ok()?;
    Some(net.network().to_string())
}

/// The second address of `link`, which is the peer's side.
///
/// A /31 or /127 has no network or broadcast address to skip — that is the
/// point of using them for point-to-point links — so the peer's side is simply
/// the other of the two.
///
/// Setting the low bit rather than adding one is deliberate: on a link that
/// wide the network address always has it clear, so this cannot overflow and
/// there is no arithmetic failure case to invent an error for.
fn peer_address(link: &IpNetwork) -> String {
    match link {
        IpNetwork::V4(v4) => {
            let addr = std::net::Ipv4Addr::from(u32::from(v4.network()) | 1);
            format!("{}/{}", addr, v4.prefix())
        }
        IpNetwork::V6(v6) => {
            let addr = std::net::Ipv6Addr::from(u128::from(v6.network()) | 1);
            format!("{}/{}", addr, v6.prefix())
        }
    }
}

/// Point-to-point prefix lengths. A /31 (RFC 3021) and a /127 (RFC 6164) are
/// exactly two addresses, so a link costs nothing beyond the two ends.
const LINK_PREFIX_V4: u8 = 31;
const LINK_PREFIX_V6: u8 = 127;

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
/// the peer's own form (`10.0.0.1/31`).
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
        // A stored address is the peer's own (`10.0.0.1/31`); parsing keeps the
        // host bits, and the overlap check works off the network address, so
        // the whole link is excluded rather than just the one address.
        .filter_map(|a| a.parse::<IpNetwork>().ok())
        .collect();

    let address4 = match pool.cidr4.as_deref() {
        Some(cidr) => Some(carve_one(cidr, LINK_PREFIX_V4, &taken, pool)?),
        None => None,
    };
    let address6 = match pool.cidr6.as_deref() {
        Some(cidr) => Some(carve_one(cidr, LINK_PREFIX_V6, &taken, pool)?),
        None => None,
    };
    Ok((address4, address6))
}

fn carve_one(cidr: &str, prefix: u8, taken: &[IpNetwork], pool: &TunnelPool) -> Result<String> {
    let block: IpNetwork = cidr.parse().map_err(|e| {
        anyhow!(
            "Tunnel pool {} has an unparseable block {cidr}: {e}",
            pool.id
        )
    })?;
    let link = allocate_subnet(&block, prefix, taken).ok_or_else(|| {
        anyhow!(
            "Tunnel pool {} has no free /{prefix} left in {cidr}",
            pool.id
        )
    })?;
    Ok(peer_address(&link))
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
    for tunnel in db.list_tunnels_in_pool(pool.id).await? {
        if !tunnel.enabled {
            continue;
        }
        let Some(key) = tunnel.peer_pubkey.as_deref() else {
            continue;
        };

        // The route server needs an address on each link, or the node's default
        // route points at something that does not answer.
        plan.addresses.extend(
            [
                link_address(tunnel.address4.as_deref()),
                link_address(tunnel.address6.as_deref()),
            ]
            .into_iter()
            .flatten(),
        );

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

        let guests = guest_addresses(db, &tunnel).await?;
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

/// The route server's side of the link `addr` sits on, as CIDR.
fn link_address(addr: Option<&str>) -> Option<String> {
    let net: IpNetwork = addr?.parse().ok()?;
    Some(format!("{}/{}", net.network(), net.prefix()))
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

    /// The first allocation takes the first link, both families, and gives the
    /// node the second address of each — LNVPS keeps the first.
    #[tokio::test]
    async fn allocating_takes_the_first_free_link_in_both_families() {
        let (db, _mock, node, pool_id) = fixture().await;

        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        assert_eq!(allocation.tunnel.address4.as_deref(), Some("10.66.0.1/31"));
        assert_eq!(
            allocation.tunnel.address6.as_deref(),
            Some("fd00:66::1/127")
        );
        assert_eq!(allocation.gateway4().as_deref(), Some("10.66.0.0"));
        assert_eq!(allocation.gateway6().as_deref(), Some("fd00:66::"));
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
        assert_eq!(host.ip, "10.66.0.1");
        assert!(!host.enabled);
    }

    /// Two nodes must never share a link; the second takes the next one.
    #[tokio::test]
    async fn a_second_node_gets_the_next_link() {
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
        assert_eq!(allocation.tunnel.address4.as_deref(), Some("10.66.0.3/31"));
        assert_eq!(
            allocation.tunnel.address6.as_deref(),
            Some("fd00:66::3/127")
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
        // A /31 out of a /31 block: one link, and it is already taken.
        let mut tiny = db.get_tunnel_pool(first_pool).await.unwrap();
        tiny.cidr4 = Some("10.66.0.0/31".to_string());
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
            address4: Some("10.66.0.1/31".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let spare = pool(&db, &mock, "10.77.0.0/24", None, "wg-mkt1").await;
        let allocation = allocate_node_tunnel(&db, &node, &NODE_KEY).await.unwrap();
        assert_eq!(allocation.tunnel.pool_id, Some(spare));
        assert_eq!(allocation.tunnel.address4.as_deref(), Some("10.77.0.1/31"));
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
        assert_eq!(allocation.control_address().unwrap(), "[fd00:66::1]");
        let host = db
            .get_marketplace_node_host(node.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host.ip, "[fd00:66::1]");
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

    /// The last link in a block is still a link. Deriving the peer's side by
    /// setting the low bit is what makes that true without an overflow case.
    #[test]
    fn the_top_of_the_address_space_still_yields_a_peer_address() {
        assert_eq!(
            peer_address(&"255.255.255.254/31".parse().unwrap()),
            "255.255.255.255/31"
        );
        assert_eq!(
            peer_address(
                &"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"
                    .parse()
                    .unwrap()
            ),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127"
        );
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
        assert_eq!(
            peer.allowed_ips,
            vec![
                "10.66.0.1/32".to_string(),
                "fd00:66::1/128".to_string(),
                "2001:db8::5/128".to_string(),
                "203.0.113.5/32".to_string(),
            ]
        );
        assert_eq!(peer.persistent_keepalive, Some(25));

        // The route server needs an address on each link, or the node's
        // default route points at something that does not answer...
        assert_eq!(
            plan.addresses,
            vec!["10.66.0.0/31".to_string(), "fd00:66::/127".to_string()]
        );
        // ...and a route for each guest address, because AllowedIPs picks the
        // peer for a packet already headed down the tunnel, it does not put it
        // there.
        assert_eq!(
            plan.routes,
            vec!["2001:db8::5/128".to_string(), "203.0.113.5/32".to_string()]
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
        assert_eq!(plan.routes, Vec::<String>::new());
        assert_eq!(plan.peers[0].allowed_ips.len(), 2, "only the node's own");

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
        assert_eq!(plan.routes, Vec::<String>::new());
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
            assert_eq!(plan, PoolPlan::default());
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
            address4: Some("10.66.9.1/31".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let pool = db.get_tunnel_pool(pool_id).await.unwrap();
        let plan = plan_pool(&db, &pool).await.unwrap();
        assert_eq!(plan.peers.len(), 1);
        assert_eq!(plan.peers[0].allowed_ips, vec!["10.66.9.1/32".to_string()]);
        assert!(plan.routes.is_empty());
        let _ = mock;
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
                    ..Default::default()
                },
            );
            id
        };
        for ip in ips {
            db.insert_vm_ip_assignment(&lnvps_db::VmIpAssignment {
                vm_id,
                ip: ip.to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        vm_id
    }
}
