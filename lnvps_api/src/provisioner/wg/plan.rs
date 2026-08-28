//! What one WireGuard interface should look like.
//!
//! The desired state of one interface, as a value. Working it out is
//! [`crate::provisioner::wg::TunnelProvisioner::plan`]; applying it is
//! `reconcile_peers` on the same type. Keeping the value separate from both is
//! what lets a plan be asserted in a test without a router, and what will let
//! the same plan be serialised to an agent instead of pushed over SSH.

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
