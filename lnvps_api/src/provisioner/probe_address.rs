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
//!
//! It is **IPv6 only**. IPv4 is the scarce resource the marketplace exists to
//! stretch, spending one to check a machine is exactly backwards — and a node
//! that cannot carry a v6 guest cannot carry a dual-stack one either.

use std::net::{IpAddr, Ipv6Addr};

use lnvps_db::Tunnel;

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

/// The address a probe VM on this node gets, as a host prefix.
///
/// The node's own inner v6 address with its last group offset, which keeps the
/// probe inside the pool's block — already routed to this peer — while never
/// colliding with the node itself.
///
/// `None` when the tunnel has no v6 address: a pool without a v6 block cannot
/// carry a probe, and inventing a v4 one instead would spend the resource this
/// deliberately avoids.
pub fn probe_address(tunnel: &Tunnel) -> Option<String> {
    let addr = tunnel.address6.as_deref()?;
    let bare = addr.split('/').next()?;
    let IpAddr::V6(v6) = bare.parse::<IpAddr>().ok()? else {
        return None;
    };

    let mut groups = v6.segments();
    // The offset is large enough that it cannot land on another node's address
    // in any pool we would allocate: nodes are handed consecutive addresses
    // from the bottom of the block, and a pool with 32,768 nodes in it has
    // problems this collision is the least of.
    groups[7] = groups[7].checked_add(0x8000)?;
    Some(format!("{}/128", Ipv6Addr::from(groups)))
}

#[cfg(test)]
mod tests;
