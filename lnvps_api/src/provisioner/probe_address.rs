//! Where a probe VM lives on the network.
//!
//! A probe is a VM LNVPS builds on an operator's node, logs into, measures and
//! destroys, to find out whether that machine can actually carry a customer.
//! Nothing about it is stored — no VM row, no IP assignment, no subscription —
//! because a probe that outlives the process which made it is *our* VM left
//! running on somebody else's hardware, and a table of them needs a reaper,
//! which is one more thing that can fail quietly.
//!
//! That decision creates the problem this module solves. A guest is only
//! reachable if its address is in three places the node did not choose: the
//! route server's routing table, the peer's `AllowedIPs`, and the node's own
//! packet filter. All three are built from the database — so an address that is
//! not in the database is an address the network drops.
//!
//! So the probe's address is **derived, not allocated**. Every node already has
//! an inner address from its pool; the probe takes a second one at a fixed
//! offset from it. Nothing has to be written down for both ends to agree, there
//! is no allocation to leak if the API dies mid-probe, and a node's probe
//! address is a pure function of a row that already exists.

use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::{IpNetwork, Ipv4Network};
use lnvps_db::{Tunnel, TunnelPool};

/// The MAC a probe VM's NIC gets.
///
/// Derived from the node id in the locally-administered range, so the address
/// binding in the node's filter has something stable to attach to and two
/// probes on two nodes cannot collide. `52:54:00` is QEMU's OUI, which is what
/// an operator looking at their own bridge will expect to see.
pub fn probe_mac(node_id: u64) -> String {
    let id = node_id.to_be_bytes();
    format!("52:54:01:{:02x}:{:02x}:{:02x}", id[5], id[6], id[7])
}

pub fn probe_address(tunnel: &Tunnel, pool: &TunnelPool) -> Option<String> {
    let block = pool_block4(pool)?;
    let bare = tunnel.address4.as_deref()?.split('/').next()?;
    let IpAddr::V4(node) = bare.parse().ok()? else {
        return None;
    };
    if !block.contains(node) {
        return None;
    }
    let size = block_size(&block);
    let offset = u64::from(u32::from(node) - u32::from(block.network()));
    if offset < 2 || offset > size / 2 - 2 {
        return None;
    }
    let probe = u64::from(u32::from(block.network())) + size - offset;
    Some(format!("{}/32", Ipv4Addr::from(u32::try_from(probe).ok()?)))
}

pub fn probe_range(pool: &TunnelPool) -> Option<Ipv4Network> {
    let block = pool_block4(pool)?;
    if block.prefix() > 29 {
        return None;
    }
    let start = u64::from(u32::from(block.network())) + block_size(&block) / 2;
    Ipv4Network::new(
        Ipv4Addr::from(u32::try_from(start).ok()?),
        block.prefix() + 1,
    )
    .ok()
}

pub fn probe_gateway(pool: &TunnelPool) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(u32::from(probe_range(pool)?.network()) + 1))
}

pub fn probe_reserved(pool: &TunnelPool) -> Vec<IpNetwork> {
    let Some(range) = probe_range(pool) else {
        return vec![];
    };
    let last_node = Ipv4Addr::from(u32::from(range.network()) - 1);
    vec![IpNetwork::V4(range), IpNetwork::from(IpAddr::V4(last_node))]
}

fn pool_block4(pool: &TunnelPool) -> Option<Ipv4Network> {
    match pool.cidr4.as_deref()?.parse::<IpNetwork>().ok()? {
        IpNetwork::V4(v4) => Ipv4Network::new(v4.network(), v4.prefix()).ok(),
        IpNetwork::V6(_) => None,
    }
}

fn block_size(block: &Ipv4Network) -> u64 {
    1u64 << (32 - u32::from(block.prefix()))
}

#[cfg(test)]
mod tests;
