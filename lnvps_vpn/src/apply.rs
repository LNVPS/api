//! Making the machine be what LNVPS asked for.
//!
//! Declarative and convergent: an interface that is already right is not
//! touched, and one that has drifted is corrected without being torn down.
//! That distinction matters more here than on a node. A route server carries
//! thousands of peers, and the kernel's only way to state a device's
//! configuration replaces its peer set with it — so an apply that rebuilt the
//! interface every time would reset every established session on it, turning
//! one customer registering a phone into a stampede of renegotiation.
//!
//! So peers are reconciled one at a time: added when new, rewritten when their
//! allowed IPs have moved, removed when they are no longer in the document, and
//! otherwise left entirely alone.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use lnvps_netlink::{NetOps, WgPeer};

use crate::client::{DesiredDataPlane, DesiredInterface};

/// What an apply did. Empty means the machine was already right, which is what
/// almost every apply should report.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub changes: Vec<String>,
}

impl Applied {
    fn note(&mut self, what: impl Into<String>) {
        self.changes.push(what.into());
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Apply the whole document.
///
/// Interfaces in the document are brought into line; interfaces this machine
/// has that the document does not mention are left alone. A route server is not
/// necessarily only a route server, and tearing down an interface because LNVPS
/// has not heard of it would mean a bug here could take out the operator's own
/// networking. LNVPS removes what it created, through the pool going away and
/// the interface being deleted deliberately.
pub async fn apply(ops: &dyn NetOps, desired: &DesiredDataPlane) -> Result<Applied> {
    let mut applied = Applied::default();
    for interface in &desired.interfaces {
        apply_interface(ops, interface, &mut applied)
            .await
            .with_context(|| format!("Cannot configure {}", interface.interface()))?;
    }
    Ok(applied)
}

async fn apply_interface(
    ops: &dyn NetOps,
    desired: &DesiredInterface,
    applied: &mut Applied,
) -> Result<()> {
    let name = desired.interface();

    if !ops.link_exists(&name).await? {
        ops.create_wireguard(&name).await?;
        applied.note(format!("created {name}"));
    }

    // The key and port are set only when they are wrong, because setting them
    // drops every peer. On the ordinary path this branch is not taken and the
    // interface's sessions are never disturbed.
    let observed = ops.wireguard_state(&name).await?.unwrap_or_default();
    let want_public = lnvps_netlink::wireguard_public_key_base64(&desired.private_key)
        .context("The private key LNVPS sent is not a WireGuard key")?;
    if observed.public_key.as_deref() != Some(want_public.as_str())
        || observed.listen_port != desired.listen_port
    {
        ops.configure_wireguard_interface(&name, &desired.private_key, desired.listen_port)
            .await?;
        applied.note(format!("keyed {name} on port {}", desired.listen_port));
    }

    let (up, mtu) = ops.link_state(&name).await?;
    if !up || mtu != Some(desired.mtu as u32) {
        ops.set_up(&name, desired.mtu as u32).await?;
        applied.note(format!("brought {name} up at mtu {}", desired.mtu));
    }

    sync_addresses(ops, &name, &desired.addresses, applied).await?;
    sync_routes(ops, &name, &desired.routes, &desired.addresses, applied).await?;
    sync_peers(ops, &name, desired, applied).await?;
    Ok(())
}

/// Make the interface's addresses exactly what was asked for.
///
/// A WireGuard interface with no address terminates nowhere: a peer's route
/// points at *some* address on this side, and it has to exist for anything to
/// answer.
async fn sync_addresses(
    ops: &dyn NetOps,
    name: &str,
    desired: &[String],
    applied: &mut Applied,
) -> Result<()> {
    let want = parse_all(desired).context("LNVPS sent an address that is not a CIDR")?;
    let have = ops.addresses(name).await?;

    for address in want.iter().filter(|a| !have.contains(a)) {
        ops.add_address(name, *address).await?;
        applied.note(format!("added {address} to {name}"));
    }
    for address in have.iter().filter(|a| !want.contains(a)) {
        // Link-local addresses are the kernel's, not ours: removing the one it
        // assigns to every interface would be a fight with it that we lose on
        // every apply.
        if is_link_local(address) {
            continue;
        }
        ops.del_address(name, *address).await?;
        applied.note(format!("removed {address} from {name}"));
    }
    Ok(())
}

/// Make the routes down the interface exactly what was asked for.
///
/// `AllowedIPs` decides which *peer* a packet already bound for the tunnel
/// belongs to; it does not put the packet on the tunnel. Without a route,
/// return traffic reaches the route server and is dropped as unroutable.
async fn sync_routes(
    ops: &dyn NetOps,
    name: &str,
    desired: &[String],
    addresses: &[String],
    applied: &mut Applied,
) -> Result<()> {
    let want = parse_all(desired).context("LNVPS sent a route that is not a CIDR")?;
    let have = ops.routes(name).await?;

    // Giving an interface `10.64.0.1/24` makes the kernel write a connected
    // route for `10.64.0.0/24` into the main table, and that route is the
    // kernel's, not ours. Deleting it would be a fight we lose on every apply:
    // it comes straight back with the address, and the delete fails with
    // ESRCH the moment two addresses in one block imply the same prefix.
    //
    // A node never hit this because its addresses are `/32` and `/128`, which
    // only produce entries in the *local* table. A route server is addressed
    // from the block itself, so this is new here.
    let implied: Vec<IpNetwork> = parse_all(addresses)
        .context("LNVPS sent an address that is not a CIDR")?
        .into_iter()
        .filter_map(|a| IpNetwork::new(a.network(), a.prefix()).ok())
        .collect();

    for route in want.iter().filter(|r| !have.contains(r)) {
        ops.add_route(*route, name).await?;
        applied.note(format!("routed {route} down {name}"));
    }
    for route in have
        .iter()
        .filter(|r| !want.contains(r) && !implied.contains(r))
    {
        ops.del_route(*route, name).await?;
        applied.note(format!("stopped routing {route} down {name}"));
    }
    Ok(())
}

/// Reconcile the peer set, one peer at a time.
async fn sync_peers(
    ops: &dyn NetOps,
    name: &str,
    desired: &DesiredInterface,
    applied: &mut Applied,
) -> Result<()> {
    let observed = ops.wireguard_state(name).await?.unwrap_or_default();
    let have: HashMap<&str, &lnvps_netlink::WgPeerState> = observed
        .peers
        .iter()
        .map(|p| (p.public_key.as_str(), p))
        .collect();

    let mut wanted = HashSet::new();
    for peer in &desired.peers {
        wanted.insert(peer.public_key.as_str());
        let allowed_ips = parse_all(&peer.allowed_ips).with_context(|| {
            format!(
                "Peer {} has allowed IPs that are not CIDRs",
                peer.public_key
            )
        })?;

        // Compared as sets: the kernel reports them in its own order, and
        // rewriting a peer because a list was shuffled would reset a session
        // for nothing.
        if let Some(current) = have.get(peer.public_key.as_str())
            && same_set(&current.allowed_ips, &allowed_ips)
        {
            continue;
        }

        ops.set_wireguard_peer(
            name,
            &WgPeer {
                public_key: peer.public_key.clone(),
                allowed_ips,
                endpoint: peer.endpoint.clone(),
                persistent_keepalive: peer.persistent_keepalive,
            },
        )
        .await?;
        applied.note(match have.contains_key(peer.public_key.as_str()) {
            true => format!("re-addressed peer {} on {name}", peer.public_key),
            false => format!("added peer {} to {name}", peer.public_key),
        });
    }

    // A peer the document no longer lists is a device that was revoked, or a
    // plan that lapsed. Leaving it configured is the one failure that matters:
    // it is a key that still works after LNVPS was told it should not.
    for stale in observed
        .peers
        .iter()
        .map(|p| p.public_key.as_str())
        .filter(|k| !wanted.contains(k))
    {
        ops.remove_wireguard_peer(name, stale).await?;
        applied.note(format!("removed peer {stale} from {name}"));
    }
    Ok(())
}

fn parse_all(values: &[String]) -> Result<Vec<IpNetwork>> {
    values
        .iter()
        .map(|v| {
            v.parse::<IpNetwork>()
                .with_context(|| format!("{v} is not a CIDR"))
        })
        .collect()
}

fn same_set(a: &[IpNetwork], b: &[IpNetwork]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.contains(x))
}

fn is_link_local(address: &IpNetwork) -> bool {
    match address.ip() {
        std::net::IpAddr::V4(v4) => v4.is_link_local() || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80 || v6.is_loopback(),
    }
}

#[cfg(test)]
pub mod tests;
