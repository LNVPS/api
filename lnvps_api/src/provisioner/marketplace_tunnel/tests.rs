//! Allocating and planning a marketplace node's data plane.

use super::*;
use crate::provisioner::wg::address::reserved_addresses;
use crate::provisioner::wg::plan::plan_interface;
use lnvps_api_common::MockDb;
use lnvps_db::{
    MarketplaceNodeStatus, MarketplaceOperator, Router, RouterKind, TunnelPool, VmHost, VmHostKind,
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
    // What is behind a node peer is recomputed before planning, exactly as
    // the worker does it: the planner itself knows nothing about guests.
    refresh_node_routes(&db, &pool).await.unwrap();
    let plan = plan_interface(&db, &pool).await.unwrap();

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
    refresh_node_routes(&db, &pool).await.unwrap();
    let plan = plan_interface(&db, &pool).await.unwrap();
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
    refresh_node_routes(&db, &pool).await.unwrap();
    let plan = plan_interface(&db, &pool).await.unwrap();
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
        refresh_node_routes(&db, &pool).await.unwrap();
        let plan = plan_interface(&db, &pool).await.unwrap();
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
    refresh_node_routes(&db, &pool).await.unwrap();
    let plan = plan_interface(&db, &pool).await.unwrap();
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
        vec!["10.0.0.1".to_string(), "fd00:66::c002".to_string()],
        "the probe's gateway is the node's own, not the route server's"
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
    // The node's own gateway for probes, not the route server's: the node
    // holds its guests' gateways itself, and sharing that address with the
    // route server means every reply is delivered to the node instead.
    assert_eq!(
        plane.guests[0].gateway, "fd00:66::c002",
        "the probe's gateway collides with the route server"
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
