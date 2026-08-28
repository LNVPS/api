//! Making a route server match the plan.
//!
//! The "apply" half of decide-then-apply. [`crate::provisioner::wg::plan`]
//! works out what an interface should look like; this reads what it actually
//! looks like, reports the difference, and pushes it.
//!
//! Reading before writing is the whole point. A peer that has vanished from a
//! route server is drift to put back and report, not an allocation to forget:
//! forgetting it would hand a customer's addresses to somebody else while they
//! still believe the addresses are theirs.
//!
//! Nothing here knows what a peer is for. Whatever is routed behind one came
//! from `tunnel_route`, written by whoever owns that peer's purpose.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use lnvps_db::LNVpsDb;
use log::{info, warn};

use crate::provisioner::wg::address::{
    Placement, carve_peer, host_address, server_address, taken_addresses,
};
use crate::provisioner::wg::plan::InterfacePlan;
use crate::router::WireguardPeer;
use lnvps_db::TunnelPool;

/// What a tunnel pool's route server disagreed with the database about.
///
/// Kept as three lists rather than a count because they mean different things:
/// a peer that is *missing* was configured and is gone, a *changed* one is
/// carrying the wrong anti-spoof list, and an *unclaimed* one is a key on an
/// LNVPS interface that no allocation accounts for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelPeerDrift {
    /// Allocated peers the route server did not have
    pub missing: Vec<String>,
    /// Peers whose allowed IPs no longer matched their allocation
    pub changed: Vec<String>,
    /// Peers on the interface that no tunnel claims
    pub unclaimed: Vec<String>,
}

/// Whether two peers permit the same set of addresses.
///
/// Compared as a set: `wg` reports allowed IPs in its own order, and treating
/// that as a difference would rewrite a working peer's anti-spoof list on every
/// single reconcile.
fn same_allowed_ips(a: &crate::router::WireguardPeer, b: &crate::router::WireguardPeer) -> bool {
    let mut x: Vec<&String> = a.allowed_ips.iter().collect();
    let mut y: Vec<&String> = b.allowed_ips.iter().collect();
    x.sort();
    y.sort();
    x == y
}

impl TunnelPeerDrift {
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.changed.is_empty() && self.unclaimed.is_empty()
    }
}

impl std::fmt::Display for TunnelPeerDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} missing, {} changed, {} unclaimed",
            self.missing.len(),
            self.changed.len(),
            self.unclaimed.len()
        )
    }
}

/// Managing the WireGuard interfaces LNVPS terminates.
///
/// Holds the database once, like [`lnvps_api_common::NetworkProvisioner`],
/// rather than taking it as an argument to every function. The router for a
/// given pool is resolved per call, because which route server an interface
/// lives on is a property of the pool and not of this service.
///
/// Knows nothing about what a peer is for. Whatever is routed behind one is
/// read from `tunnel_route`, and whoever owns that peer's purpose put it
/// there.
pub struct TunnelProvisioner {
    db: Arc<dyn LNVpsDb>,
}

impl TunnelProvisioner {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// Enable/disable a tunnel on a router and refresh its cached state.
    pub async fn set_enabled(&self, router_id: u64, name: &str, enabled: bool) -> Result<()> {
        let router = crate::router::get_router(&self.db, router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;
        // The admin API addresses tunnels by name (the cache key), but the backend
        // toggles by its own id (interface name on Linux, `<kind>:<.id>` on
        // Mikrotik). Resolve the id from the live listing.
        let tunnels = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?;
        let target = tunnels
            .iter()
            .find(|t| t.name == name)
            .context("tunnel not found")?;
        let id = target.id.as_deref().unwrap_or(name);
        tr.set_tunnel_enabled(id, enabled)
            .await
            .map_err(|e| anyhow!("failed to toggle tunnel: {}", e))?;
        // Refresh the cached inventory so the admin API reflects the new state.
        // The tunnel `enabled` flag is discovery-authoritative (the interface
        // up/down state), so re-listing after the change is sufficient.
        if let Ok(tunnels) = tr.list_tunnels().await {
            for t in &tunnels {
                if let Err(e) = self.db.upsert_router_tunnel(&t.to_db(router_id)).await {
                    warn!("Failed to refresh tunnel cache: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Configure a tunnel pool's WireGuard interface on its route server.
    ///
    /// This is a **push**, not a reconcile: LNVPS generates and holds the
    /// interface's key material, so what the database says is what the
    /// interface should be. Without it a pool could only describe an interface
    /// somebody configured by hand, and bringing up a new route server would be
    /// a manual job with a database row bolted on afterwards.
    pub async fn sync_pool(&self, pool_id: u64) -> Result<()> {
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        let router = crate::router::get_router(&self.db, pool.router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", pool.router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;

        let private_key = pool.private_key.as_str().to_string();
        // The stored pair has to agree with itself before it is pushed: a
        // public key that is not this private key's would be handed to every
        // node and none of them could hand shake.
        let derived = lnvps_api_common::wireguard_public_key(&private_key)?;
        if derived != pool.public_key {
            bail!(
                "Tunnel pool {} has a public key that its private key does not produce; \
                 refusing to configure an interface nobody could connect to",
                pool.id
            );
        }

        // Named from the pool's id under a fixed prefix, so a managed
        // interface can never be confused with one the operator of the route
        // server configured themselves.
        let interface = pool.interface();

        let existing = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?
            .into_iter()
            .find(|t| t.name == interface);

        let desired = crate::router::ObservedInterface {
            id: existing.as_ref().and_then(|t| t.id.clone()),
            name: interface.clone(),
            // The address the data plane listens on. Recorded so the interface
            // and the endpoint peers are told to dial cannot disagree.
            local_addr: Some(pool.listen_addr.clone()),
            remote_addr: None,
            enabled: pool.enabled,
            config: crate::router::TunnelConfig::Wireguard(crate::router::WireguardConfig {
                listen_port: Some(pool.listen_port),
                private_key: Some(private_key),
                public_key: Some(lnvps_api_common::wireguard_key_to_base64(&pool.public_key)),
                // Peers are pushed per allocation, not here. Sending an empty
                // list would be read as "this interface has no peers".
                peers: vec![],
            }),
        };

        match &existing {
            None => {
                info!(
                    "Creating WireGuard interface {} on router {}",
                    interface, pool.router_id
                );
                tr.add_tunnel(&desired)
                    .await
                    .map_err(|e| anyhow!("failed to create tunnel interface: {}", e))?;
            }
            Some(current) => {
                // Re-applying recreates the interface on the Linux backend,
                // which drops every peer with it. So it is only done when the
                // interface is actually wrong — a node whose tunnel is working
                // must not be cut because a pool was renamed.
                let current_key = match &current.config {
                    crate::router::TunnelConfig::Wireguard(c) => c.public_key.clone(),
                    _ => None,
                };
                let current_port = match &current.config {
                    crate::router::TunnelConfig::Wireguard(c) => c.listen_port,
                    _ => None,
                };
                let want_key = lnvps_api_common::wireguard_key_to_base64(&pool.public_key);
                let key_drifted = current_key.as_deref() != Some(want_key.as_str());
                let port_drifted = current_port != Some(pool.listen_port);

                if key_drifted || port_drifted {
                    warn!(
                        "WireGuard interface {} on router {} has drifted (key_changed={}, \
                         port_changed={}); re-applying, which drops its peers until they are \
                         pushed again",
                        interface, pool.router_id, key_drifted, port_drifted
                    );
                    tr.update_tunnel(&desired)
                        .await
                        .map_err(|e| anyhow!("failed to update tunnel interface: {}", e))?;
                } else if current.enabled != pool.enabled {
                    let id = current.id.as_deref().unwrap_or(interface.as_str());
                    tr.set_tunnel_enabled(id, pool.enabled)
                        .await
                        .map_err(|e| anyhow!("failed to toggle tunnel interface: {}", e))?;
                }
            }
        }

        // Refresh the observed-state cache so the admin API stops showing the
        // interface as missing the moment it exists.
        if let Ok(tunnels) = tr.list_tunnels().await {
            for t in &tunnels {
                if let Err(e) = self.db.upsert_router_tunnel(&t.to_db(pool.router_id)).await {
                    warn!("Failed to refresh tunnel cache: {}", e);
                }
            }
        }

        // Whatever happened above, the interface now has to carry the peers
        // that were allocated from this pool. This matters most in the case the
        // push above just created or re-applied it: on Linux that is a fresh
        // interface with no peers at all, and every node on it is cut until
        // they are put back.
        self.reconcile_peers(pool.id).await?;
        Ok(())
    }

    /// Reconcile the peers, addresses and routes on a pool's interface against
    /// the tunnels allocated from it.
    ///
    /// The `tunnel` table is the desired state and the router is the observed
    /// one, exactly as with host state. A peer that has vanished from a route
    /// server is drift to put back and report, not an allocation to forget:
    /// forgetting it would hand the node's addresses to somebody else while the
    /// node still believes they are its own.
    ///
    /// Returns what had drifted, so a caller running this on a schedule can say
    /// whether anything was wrong rather than only that it ran.
    pub async fn reconcile_peers(&self, pool_id: u64) -> Result<TunnelPeerDrift> {
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        let router = crate::router::get_router(&self.db, pool.router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", pool.router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;
        let interface = pool.interface();

        let observed = tr
            .list_tunnels()
            .await
            .map_err(|e| anyhow!("failed to list tunnels: {}", e))?
            .into_iter()
            .find(|t| t.name == interface);
        // Peers are configured *on* an interface, so there is nothing to
        // reconcile against until it exists. Creating it here would duplicate
        // `sync_tunnel_pool` and hide the fact that it never ran.
        let Some(observed) = observed else {
            bail!(
                "Tunnel pool {pool_id}'s interface {interface} is not configured on router {}; \
                 run SyncTunnelPool first",
                pool.router_id
            );
        };
        let observed_peers = match &observed.config {
            crate::router::TunnelConfig::Wireguard(c) => c.peers.clone(),
            _ => bail!("Tunnel pool {pool_id}'s interface {interface} is not a WireGuard tunnel"),
        };

        // What is behind each node peer is recomputed from the guest
        // assignments before the plan is built, so the planner can read it
        // without knowing that marketplace nodes exist.
        crate::provisioner::MarketplaceTunnels::new(self.db.clone())
            .refresh_routes(&pool)
            .await?;
        let plan = self.plan(&pool).await?;
        let mut drift = TunnelPeerDrift::default();

        for want in &plan.peers {
            match observed_peers
                .iter()
                .find(|p| p.public_key == want.public_key)
            {
                // Allowed IPs are compared as a set: `wg` reports them in its
                // own order, and re-pushing on every reconcile because of that
                // would rewrite the anti-spoof list of a working peer forever.
                Some(have) if same_allowed_ips(have, want) => continue,
                Some(_) => drift.changed.push(want.public_key.clone()),
                None => drift.missing.push(want.public_key.clone()),
            }
            tr.set_tunnel_peer(&interface, want)
                .await
                .map_err(|e| anyhow!("failed to configure peer on {interface}: {}", e))?;
        }

        for have in &observed_peers {
            if plan.peers.iter().any(|p| p.public_key == have.public_key) {
                continue;
            }
            // LNVPS owns `wgln*` interfaces outright, so a peer no tunnel
            // claims is either a revoked allocation that was never cleaned up
            // or somebody else's key on our route server. Both are removed.
            drift.unclaimed.push(have.public_key.clone());
            tr.remove_tunnel_peer(&interface, &have.public_key)
                .await
                .map_err(|e| anyhow!("failed to remove peer from {interface}: {}", e))?;
        }

        tr.sync_tunnel_addresses(&interface, &plan.addresses)
            .await
            .map_err(|e| anyhow!("failed to configure addresses on {interface}: {}", e))?;
        tr.sync_tunnel_routes(&interface, &plan.routes)
            .await
            .map_err(|e| anyhow!("failed to configure routes on {interface}: {}", e))?;

        if !drift.is_empty() {
            warn!(
                "Tunnel pool {pool_id} on router {} had drifted: {drift}",
                pool.router_id
            );
        }
        Ok(drift)
    }

    /// Push one node's peer onto its route server.
    ///
    /// Used when a single allocation changes — a node asking for its tunnel, a
    /// guest getting an address — so it does not wait behind a reconcile of
    /// every other node on the same route server.
    pub async fn sync_peer(&self, tunnel_id: u64) -> Result<()> {
        let tunnel = self.db.get_tunnel(tunnel_id).await?;
        let pool_id = tunnel.pool_id.ok_or_else(|| {
            anyhow!("Tunnel {tunnel_id} was not allocated from a pool, so there is no interface")
        })?;
        let pool = self.db.get_tunnel_pool(pool_id).await?;
        let router = crate::router::get_router(&self.db, pool.router_id)
            .await
            .map_err(|e| anyhow!("failed to load router {}: {}", pool.router_id, e))?;
        let tr = router.tunnel().context("router does not support tunnels")?;
        let interface = pool.interface();

        // The peer's own share of the pool plan, rather than a second
        // calculation of what one tunnel needs: the addresses and routes are
        // per-interface, so one node's change is applied by re-stating the
        // whole interface's addressing, and only its own peer is pushed.
        crate::provisioner::MarketplaceTunnels::new(self.db.clone())
            .refresh_routes(&pool)
            .await?;
        let plan = self.plan(&pool).await?;
        let key = tunnel
            .peer_pubkey
            .as_deref()
            .map(lnvps_api_common::wireguard_key_to_base64);

        match key
            .as_ref()
            .and_then(|k| plan.peers.iter().find(|p| &p.public_key == k))
        {
            Some(peer) => tr
                .set_tunnel_peer(&interface, peer)
                .await
                .map_err(|e| anyhow!("failed to configure peer on {interface}: {}", e))?,
            // A tunnel that is disabled or has never presented a key has no
            // peer to push. Removing whatever is there under its key is the
            // same statement in the other direction.
            None => {
                if let Some(key) = &key {
                    tr.remove_tunnel_peer(&interface, key)
                        .await
                        .map_err(|e| anyhow!("failed to remove peer from {interface}: {}", e))?;
                }
            }
        }

        tr.sync_tunnel_addresses(&interface, &plan.addresses)
            .await
            .map_err(|e| anyhow!("failed to configure addresses on {interface}: {}", e))?;
        tr.sync_tunnel_routes(&interface, &plan.routes)
            .await
            .map_err(|e| anyhow!("failed to configure routes on {interface}: {}", e))?;
        Ok(())
    }
    /// Work out what `pool`'s interface should look like.
    ///
    /// A tunnel that cannot be realised — disabled, or with no key presented yet —
    /// contributes nothing at all, not an empty peer: half-configuring it would
    /// give the node a link with no way to authenticate over it.
    pub async fn plan(&self, pool: &TunnelPool) -> Result<InterfacePlan> {
        let mut plan = InterfacePlan::default();

        // Where this interface's peers are addressed from, and which peers they
        // are. A pool records neither, because it records nothing about what it is
        // for: an interface terminating a VPN service carries that service's
        // devices, addressed from the service's block so a device keeps one address
        // in every region, and any other pool carries the links carved from its own.
        // The block is the pool's, as it is for every interface. Only which
        // peers it carries differs: an interface terminating a VPN service
        // carries that service's devices, which are peers on every one of its
        // interfaces at once and so belong to no single pool.
        let tunnels = match self.db.get_vpn_service_for_pool(pool.id).await? {
            Some(service) => self.db.list_active_vpn_tunnels(service.id).await?,
            None => self.db.list_tunnels_in_pool(pool.id).await?,
        };
        let (cidr4, cidr6) = (pool.cidr4.clone(), pool.cidr6.clone());

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
        let routes = self.db.list_tunnel_routes(&ids).await?;

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

    /// Carve the next free peer address out of `pool`'s own block.
    ///
    /// Sequential placement: a pool holds a handful of nodes, and an operator
    /// debugging one benefits from addresses they can reason about. The
    /// argument for scattering customer addresses does not apply here.
    pub async fn carve_from_pool(
        &self,
        pool: &TunnelPool,
    ) -> Result<(Option<String>, Option<String>)> {
        let taken = taken_addresses(&self.db.list_tunnels_in_pool(pool.id).await?);
        carve_peer(
            pool.cidr4.as_deref(),
            pool.cidr6.as_deref(),
            &taken,
            &format!("Tunnel pool {}", pool.id),
            Placement::Sequential,
        )
    }
}
