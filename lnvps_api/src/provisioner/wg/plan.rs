//! What one WireGuard interface should look like.
//!
//! The "decide" half of decide-then-apply: this works out the desired state
//! from the database, and [`crate::provisioner::wg::apply`] compares it against
//! the route server and pushes the difference. Keeping them apart is what lets
//! the decision be tested without a router, and what lets the same decision
//! later be serialised to an agent instead of pushed over SSH.
//!
//! This module knows nothing about what a peer is for. Whatever is routed
//! behind one is read from `tunnel_route`, and whoever owns that peer's purpose
//! put it there.

use std::sync::Arc;

use anyhow::Result;
use lnvps_db::{LNVpsDb, TunnelPool};

use crate::provisioner::wg::address::{host_address, server_address};
use crate::router::WireguardPeer;

/// What one WireGuard interface should have configured on its route server.
///
/// Named for the interface rather than the pool because the pool no longer
/// decides it on its own: an interface terminating a VPN service is addressed
/// from the service's block.
///
/// Computed in one pass because the three parts are answers to the same
/// question and must agree: an address without its peer is
/// a link to nowhere, a peer without its route drops the guest traffic it was
/// created to carry, and a route to a peer that is not there is a black hole.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InterfacePlan {
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
pub async fn plan_interface(db: &Arc<dyn LNVpsDb>, pool: &TunnelPool) -> Result<InterfacePlan> {
    let mut plan = InterfacePlan::default();

    // Where this interface's peers are addressed from, and which peers they
    // are. A pool records neither, because it records nothing about what it is
    // for: an interface terminating a VPN service carries that service's
    // devices, addressed from the service's block so a device keeps one address
    // in every region, and any other pool carries the links carved from its own.
    let (cidr4, cidr6, tunnels) = match db.get_vpn_service_for_pool(pool.id).await? {
        Some(service) => (
            service.device_cidr4.clone(),
            service.device_cidr6.clone(),
            db.list_active_vpn_tunnels(service.id).await?,
        ),
        None => (
            pool.cidr4.clone(),
            pool.cidr6.clone(),
            db.list_tunnels_in_pool(pool.id).await?,
        ),
    };

    // One address for the whole block, carrying its prefix so every peer is
    // on-link. A per-peer address would put one address on this interface for
    // every peer on the route server to describe links that WireGuard, being
    // layer 3 and point-to-point, does not need described.
    plan.addresses.extend(
        [
            server_address(cidr4.as_deref()),
            server_address(cidr6.as_deref()),
        ]
        .into_iter()
        .flatten(),
    );

    // The block itself is routed down the interface as well. An address on a
    // point-to-point interface does not give the kernel a route to the rest of
    // its prefix, so without this the route server holds `10.66.0.1/16` and
    // still answers "network is unreachable" for every peer in it. Found by the
    // end-to-end harness rather than by reading the code.
    plan.routes.extend(
        [cidr4.as_deref(), cidr6.as_deref()]
            .into_iter()
            .flatten()
            .map(str::to_string),
    );

    // What is behind each peer, in one query rather than one per peer. The
    // planner does not know or care why anything is behind a peer: a
    // marketplace node has its guests here, a VPN device has nothing, and
    // whoever owns that meaning wrote these rows before the reconcile ran.
    let ids: Vec<u64> = tunnels.iter().map(|t| t.id).collect();
    let routes = db.list_tunnel_routes(&ids).await?;

    for tunnel in tunnels {
        if !tunnel.enabled {
            continue;
        }
        let Some(key) = tunnel.peer_pubkey.as_deref() else {
            continue;
        };

        // AllowedIPs is both the routing table for this peer and the
        // anti-spoof boundary: WireGuard drops an inbound packet whose source
        // is not listed, so one peer cannot claim another's address.
        let mut allowed_ips: Vec<String> = [
            host_address(tunnel.address4.as_deref()),
            host_address(tunnel.address6.as_deref()),
        ]
        .into_iter()
        .flatten()
        .collect();

        let behind: Vec<String> = routes
            .iter()
            .filter(|r| r.tunnel_id == tunnel.id)
            .map(|r| r.prefix.clone())
            .collect();
        allowed_ips.extend(behind.iter().cloned());
        // A route as well as an AllowedIPs entry: AllowedIPs picks the peer for
        // a packet already headed down the tunnel, it does not put it there.
        plan.routes.extend(behind);

        plan.peers.push(WireguardPeer {
            public_key: lnvps_api_common::wireguard_key_to_base64(key),
            // Peers dial out from behind NAT; the endpoint is learned from the
            // handshake. Configuring a stale one would stop the peer from being
            // reachable after its address changes.
            endpoint: tunnel.peer_endpoint.clone(),
            allowed_ips,
            persistent_keepalive: tunnel.keepalive,
        });
    }
    Ok(plan)
}
