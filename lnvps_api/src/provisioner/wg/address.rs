//! Addressing a WireGuard block.
//!
//! Pure arithmetic: which addresses a block reserves for itself, which one the
//! route server takes, and how the next free one is carved out. No database, no
//! router, and no opinion about what the peer being addressed is for.
//!
//! Two callers carve from a block — a marketplace pool handing a
//! point-to-point link to each node, and a VPN service handing one address to
//! each device — and they differ only in where the block comes from and what is
//! already taken.

use anyhow::{Result, anyhow, bail};
use ipnetwork::IpNetwork;
use lnvps_api_common::random_address;

use crate::provisioner::allocate_subnet;

/// A peer holds a single address, not a link.
///
/// WireGuard needs no gateway on the peer's side (`ip route add default dev
/// wg0` is enough on a point-to-point layer 3 interface), so a /31 spent two
/// addresses to describe something that needs one — and forced the route server
/// to carry an address per peer.
const PEER_PREFIX_V4: u8 = 32;
const PEER_PREFIX_V6: u8 = 128;

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
pub(crate) fn bare_address(cidr: &str) -> String {
    cidr.split_once('/').map_or(cidr, |(a, _)| a).to_string()
}

/// Where in a block a new peer's address is taken from.
///
/// The same choice [`lnvps_db::IpRangeAllocationMode`] offers for guest
/// addresses, and picked the same way: a random candidate tested against the
/// taken set, as `NetworkProvisioner::pick_ip_from_range` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// The lowest free slot. Predictable, which is what a pool holding a
    /// handful of nodes wants: an operator debugging one can reason about it.
    Sequential,
    /// A free slot chosen at random.
    ///
    /// For addresses handed to customers. A sequential address encodes roughly
    /// when it was issued and how many came before it, so anybody who sees one
    /// learns the size of the fleet and the age of the account behind it.
    Random,
}

/// Carve the next free peer address out of each block.
///
/// A block-holder with both families must supply both halves: a peer given only
/// one would silently be single-stack, which is the kind of thing that is
/// discovered by a customer rather than by us.
///
/// `owner` names whatever holds the blocks (`"Tunnel pool 3"`, `"VPN service
/// 1"`) so an error points at the row an admin has to fix. That, and where the
/// taken set was read from, is the only thing a marketplace link and a VPN
/// device disagree about — the arithmetic is the same, so it is written once.
pub(crate) fn carve_peer(
    cidr4: Option<&str>,
    cidr6: Option<&str>,
    taken: &[IpNetwork],
    owner: &str,
    placement: Placement,
) -> Result<(Option<String>, Option<String>)> {
    // The invariant `ck_tunnel_pool_has_a_block` used to hold, moved here when
    // a VPN pool stopped needing a block of its own. The schema cannot state it
    // any more, because whether a row may have no block depends on another
    // table. Failing beats returning a peer with no addresses, which looks
    // configured and carries nothing.
    if cidr4.is_none() && cidr6.is_none() {
        bail!("{owner} has no address block, so there is nothing to carve a peer from");
    }

    let address4 = match cidr4 {
        Some(cidr) => Some(carve_one(cidr, PEER_PREFIX_V4, taken, owner, placement)?),
        None => None,
    };
    let address6 = match cidr6 {
        Some(cidr) => Some(carve_one(cidr, PEER_PREFIX_V6, taken, owner, placement)?),
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

/// Random candidates tried before falling back to the deterministic scan.
///
/// A guest range probes until it succeeds, which is right there: it is checked
/// for fullness first, so a free address exists to be found. A peer block gets
/// no such check, and only the scan can tell a block with one address left from
/// one with none. Eight probes clear a block up to about 85% full at better
/// than even odds, and past that the scan is both cheap and the answer worth
/// having.
const RANDOM_PLACEMENT_ATTEMPTS: usize = 8;

fn carve_one(
    cidr: &str,
    prefix: u8,
    taken: &[IpNetwork],
    owner: &str,
    placement: Placement,
) -> Result<String> {
    let block: IpNetwork = cidr
        .parse()
        .map_err(|e| anyhow!("{owner} has an unparseable block {cidr}: {e}"))?;
    let mut taken = taken.to_vec();
    taken.extend(reserved_addresses(cidr));

    if placement == Placement::Random {
        let ips: std::collections::HashSet<std::net::IpAddr> =
            taken.iter().map(|n| n.ip()).collect();
        for _ in 0..RANDOM_PLACEMENT_ATTEMPTS {
            let Some(addr) = random_address(&block) else {
                break;
            };
            if !ips.contains(&addr)
                && let Ok(net) = IpNetwork::new(addr, prefix)
            {
                return Ok(net.to_string());
            }
        }
    }

    // Also where random placement lands once the block is crowded: only a full
    // scan can tell a block with one address left from one with none, and that
    // difference is what an admin needs to hear.
    let addr = allocate_subnet(&block, prefix, &taken)
        .ok_or_else(|| anyhow!("{owner} has no free /{prefix} left in {cidr}; widen the block"))?;
    Ok(addr.to_string())
}

/// A single address as a host prefix (`/32` or `/128`).
///
/// Accepts either a bare address or one already carrying a prefix, because
/// tunnel addresses are stored as CIDR and guest assignments as bare addresses.
pub(crate) fn host_address(addr: Option<&str>) -> Option<String> {
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

/// Every address already carved out of a block, as the allocator wants them.
///
/// Unparseable values are dropped rather than failing the allocation: a
/// malformed stored address is a row to fix, not a reason to refuse every
/// subsequent customer, and it cannot collide with anything the allocator
/// produces because the allocator only produces parseable ones.
pub(crate) fn taken_addresses(tunnels: &[lnvps_db::Tunnel]) -> Vec<IpNetwork> {
    tunnels
        .iter()
        .flat_map(|t| [t.address4.as_deref(), t.address6.as_deref()])
        .flatten()
        .filter_map(|a| a.parse::<IpNetwork>().ok())
        .collect()
}
