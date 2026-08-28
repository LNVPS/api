//! Applying the data plane LNVPS asked for.
//!
//! The daemon configures the machine itself rather than writing files for
//! something else to read. A marketplace node runs on hardware LNVPS does not
//! own: a data plane that depends on the operator having wired it up correctly
//! is one whose mistakes surface as a customer's VM having no network.
//!
//! Interfaces, addresses and routes are managed over **netlink**, not by
//! shelling out to `ip`. Netlink is the interface the kernel actually offers;
//! `ip` is a program that formats netlink messages and then formats the answer
//! back into text for us to parse. Going direct means no dependency on
//! iproute2's presence or version, no output parsing that changes between
//! releases, no arguments to quote, and errors that arrive as kernel error
//! codes instead of a line of English on stderr.
//!
//! Everything is stated declaratively and converges: a node that is already
//! right is not disturbed, and one that has drifted is corrected without being
//! torn down.
//!
//! The kernel calls sit behind [`NetOps`] so the orchestration can be tested
//! without root: what is worth asserting is *what the node decides to do*.
//! Whether the netlink implementation of those decisions really works on a
//! kernel is proven by the netns end-to-end harness, which runs both ends of a
//! real tunnel and pings across it.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::wgkey::{self, NodeKey};

// How to talk to the kernel is shared with `lvd`, the VPN route-server daemon,
// and re-exported here so a node reads as one thing: everything about this
// node's data plane is `net::`, whether the code lives in this crate or not.
pub use lnvps_netlink::{
    Kernel, NetOps, UnavailableKernel, WgObserved, WgSettings, read_sysctl, write_sysctl,
};

/// The tunnel interface the node terminates its data plane on.
///
/// `wgln0`, not `wg0`: the interface is created in the *machine's* namespace
/// before being moved into the data plane's, and an operator's own `wg0` — a
/// VPN, a mesh, anything — is a name we would collide with there. The `wgln`
/// prefix is the same one LNVPS uses for its route-server interfaces, so a
/// managed interface is recognisable as ours wherever it turns up.
pub const TUNNEL_INTERFACE: &str = "wgln0";

/// The bridge guests sit on.
///
/// A constant here rather than a field in the data-plane document, because the
/// daemon needs the name before it has ever spoken to LNVPS: `dataplane
/// observe` reports on it without a credential, and an operator debugging a
/// node asks about it offline. A document that could name a different bridge
/// would leave the node holding two answers to one question. LNVPS holds the
/// same constant, and the end-to-end harness asserts the two agree.
pub const GUEST_BRIDGE: &str = "br-lnvps";

/// The desired data plane, as LNVPS states it.
///
/// Mirrors `GET /api/v1/node/dataplane`. Fetched and applied as one document
/// because it only makes sense as one: a bridge with no tunnel carries nothing,
/// and a tunnel with no guest routes carries nothing back.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredDataPlane {
    pub tunnel: DesiredTunnel,
    /// Gateway addresses this node answers for on the bridge.
    #[serde(default)]
    pub gateways: Vec<String>,
    #[serde(default)]
    pub guests: Vec<DesiredGuest>,
    /// How to serve libvirt to LNVPS. Absent when LNVPS has no client identity
    /// configured, which is a deployment that networks nodes but places no VMs
    /// on them — so the node leaves libvirt alone rather than opening a
    /// listener nobody can authenticate to.
    #[serde(default)]
    pub libvirt: Option<DesiredLibvirt>,
}

/// What the node's libvirtd should be, as LNVPS states it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DesiredLibvirt {
    /// PEM of the CA that signed LNVPS's client certificate.
    pub ca_pem: String,
    /// The only client DN allowed to connect.
    pub allowed_dn: String,
    /// The address libvirtd binds: this node's own tunnel address, never the
    /// machine's other interfaces.
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredTunnel {
    pub address4: Option<String>,
    pub address6: Option<String>,
    pub gateway4: Option<String>,
    pub gateway6: Option<String>,
    /// The route server's key, hex.
    pub server_public_key: String,
    pub endpoint: String,
    pub keepalive: Option<u16>,
    pub mtu: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredGuest {
    pub address: String,
    pub gateway: String,
    pub mac: Option<String>,
}

/// What the machine currently looks like.
///
/// Reported to LNVPS over the control API, where it is the first thing the
/// health gate checks. Every field is read from the machine, never remembered
/// from what was applied — the point of observing is to catch the case where
/// the two disagree.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DataPlaneState {
    pub tunnel_up: bool,
    /// Seconds since the last handshake with the route server. `None` when
    /// there has never been one, which is the difference between "configured"
    /// and "working".
    pub last_handshake_secs: Option<u64>,
    pub tunnel_mtu: Option<u32>,
    pub bridge_up: bool,
    pub forwarding4: bool,
    pub forwarding6: bool,
    /// Guest addresses actually routed to the bridge.
    pub routed_guests: usize,
    /// The packet filter around those guests.
    #[serde(default)]
    pub firewall: crate::fw::FirewallState,
}

impl DataPlaneState {
    /// Whether this node can carry a customer.
    ///
    /// A handshake is required, not just an interface: WireGuard comes up happily
    /// with a peer that never answers, and a node in that state looks
    /// configured while being unreachable.
    ///
    /// The filter is required for a different reason: a node that forwards
    /// without one is a node where any guest can source any address and reach
    /// any neighbour. That is worse than a node that carries nobody, so it is
    /// counted as unhealthy rather than as a warning.
    pub fn healthy(&self) -> bool {
        self.tunnel_up
            && self.last_handshake_secs.is_some()
            && self.bridge_up
            && self.forwarding4
            && self.firewall.present
    }
}

/// Apply `desired` to this machine.
///
/// Returns a description of what was changed, so `dataplane apply` can show an
/// operator what happened and a test can assert it. An empty list means the
/// machine was already right, which is the normal case on every refresh after
/// the first.
pub async fn apply(
    ops: &dyn NetOps,
    fw: &dyn crate::fw::FirewallOps,
    desired: &DesiredDataPlane,
    key: &NodeKey,
) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    apply_tunnel(ops, desired, key, &mut changed).await?;
    apply_bridge(ops, desired, &mut changed).await?;

    // The filter before forwarding, every time. Between the two the machine
    // routes guest traffic with nothing checking it, and on a refresh that adds
    // a guest that window is exactly when the new guest starts sending.
    changed.extend(crate::fw::apply(fw, &crate::fw::Policy::from_desired(desired)?).await?);
    apply_forwarding(ops, &mut changed).await?;
    Ok(changed)
}

/// Bring up the tunnel interface and point the default route down it.
async fn apply_tunnel(
    ops: &dyn NetOps,
    desired: &DesiredDataPlane,
    key: &NodeKey,
    changed: &mut Vec<String>,
) -> Result<()> {
    if !ops.link_exists(TUNNEL_INTERFACE).await? {
        ops.create_wireguard(TUNNEL_INTERFACE).await?;
        changed.push(format!("created {TUNNEL_INTERFACE}"));
    }

    let peer_key = wgkey::parse_public_key(&desired.tunnel.server_public_key)?;
    let settings = WgSettings {
        private_key: key.private_base64(),
        peer_public_key: peer_key.clone(),
        endpoint: desired.tunnel.endpoint.clone(),
        keepalive: desired.tunnel.keepalive,
        // Everything goes up the tunnel: the node's guests use LNVPS addresses,
        // so there is no traffic of theirs that belongs anywhere else.
        allowed_ips: vec![
            "0.0.0.0/0".parse().expect("a constant CIDR"),
            "::/0".parse().expect("a constant CIDR"),
        ],
    };
    ops.configure_wireguard(TUNNEL_INTERFACE, &settings).await?;
    changed.push(format!("configured {TUNNEL_INTERFACE}"));

    // A peer that is not the route server has no business on this interface.
    // It would most likely be a stale key from a re-key, still able to send
    // traffic that the node treats as coming from LNVPS.
    if let Some(observed) = ops.wireguard_state(TUNNEL_INTERFACE).await? {
        for (stale, _) in observed.peers.iter().filter(|(k, _)| *k != peer_key) {
            ops.remove_wireguard_peer(TUNNEL_INTERFACE, stale).await?;
            changed.push(format!("removed stale peer {stale}"));
        }
    }

    let want = tunnel_addresses(desired)?;
    sync_addresses(ops, TUNNEL_INTERFACE, &want, changed).await?;

    // Not 1500: WireGuard's overhead comes off it, and guessing wrong hangs
    // large transfers rather than failing outright.
    ops.set_up(TUNNEL_INTERFACE, desired.tunnel.mtu as u32)
        .await?;

    // No gateway: the tunnel is point-to-point, so the interface names the next
    // hop by itself, and naming one would be a second copy of the route
    // server's address free to disagree with the peer's.
    let existing = ops.routes(TUNNEL_INTERFACE).await?;
    for default in default_routes(desired) {
        if !existing.contains(&default) {
            ops.add_route(default, TUNNEL_INTERFACE).await?;
            changed.push(format!("routed {default} via {TUNNEL_INTERFACE}"));
        }
    }
    Ok(())
}

/// Bring up the guest bridge and route each guest to it.
async fn apply_bridge(
    ops: &dyn NetOps,
    desired: &DesiredDataPlane,
    changed: &mut Vec<String>,
) -> Result<()> {
    if !ops.link_exists(GUEST_BRIDGE).await? {
        ops.create_bridge(GUEST_BRIDGE).await?;
        changed.push(format!("created {GUEST_BRIDGE}"));
    }
    // The bridge carries the same payload as the tunnel, so it takes the same
    // MTU: a guest that sends 1500 bytes into a 1420-byte tunnel produces a
    // connection that opens and then hangs on the first large transfer.
    ops.set_up(GUEST_BRIDGE, desired.tunnel.mtu as u32).await?;

    // The gateway belongs to the range, not to this node, and the guest
    // believes it is on-link. Held as a host address so the node answers for it
    // without claiming the rest of the range is local — the other addresses in
    // it live on other nodes, up the tunnel.
    let mut want = Vec::new();
    for gateway in &desired.gateways {
        want.push(host_prefix(gateway)?);
    }
    sync_addresses(ops, GUEST_BRIDGE, &want, changed).await?;

    // The guest thinks its neighbours are on-link and will ARP for them; proxy
    // ARP is what lets the node answer and pull that traffic up the tunnel
    // instead of it disappearing into a link that has no such address.
    for knob in [
        format!("net/ipv4/conf/{GUEST_BRIDGE}/proxy_arp"),
        format!("net/ipv6/conf/{GUEST_BRIDGE}/proxy_ndp"),
    ] {
        set_if_needed(ops, &knob, "1", changed).await?;
    }

    let mut guests: HashSet<IpNetwork> = HashSet::new();
    for guest in &desired.guests {
        guests.insert(host_prefix(&guest.address)?);
    }
    let existing: HashSet<IpNetwork> = ops.routes(GUEST_BRIDGE).await?.into_iter().collect();

    let mut to_add: Vec<&IpNetwork> = guests.difference(&existing).collect();
    to_add.sort();
    for address in to_add {
        ops.add_route(*address, GUEST_BRIDGE).await?;
        changed.push(format!("routed {address} to {GUEST_BRIDGE}"));
    }

    // A guest that has been deleted or moved must stop being routed here at
    // once: its address goes back in the pool and may already be somebody
    // else's. Routes the kernel maintains for the link itself are left alone —
    // deleting the IPv6 link-local prefix to tidy a list would take the
    // interface's own connectivity with it.
    //
    // The gateways this node answers for are left alone for the same reason.
    // Holding an address on an interface makes the kernel route it, and that
    // route is not ours to remove: with IPv6 the attempt fails outright with
    // "no such process", which stops the whole apply — a node with a v6 gateway
    // could not bring its data plane up at all.
    let own: HashSet<IpNetwork> = want.iter().copied().collect();
    let mut to_drop: Vec<&IpNetwork> = existing
        .difference(&guests)
        .filter(|r| !is_link_local(r) && !own.contains(r))
        .collect();
    to_drop.sort();
    for address in to_drop {
        ops.del_route(*address, GUEST_BRIDGE).await?;
        changed.push(format!("unrouted {address} from {GUEST_BRIDGE}"));
    }
    Ok(())
}

/// A node that does not forward is a node whose guests have no network at all.
async fn apply_forwarding(ops: &dyn NetOps, changed: &mut Vec<String>) -> Result<()> {
    for knob in ["net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"] {
        set_if_needed(ops, knob, "1", changed).await?;
    }
    Ok(())
}

/// Make the addresses on `name` exactly `want`.
async fn sync_addresses(
    ops: &dyn NetOps,
    name: &str,
    want: &[IpNetwork],
    changed: &mut Vec<String>,
) -> Result<()> {
    let existing = ops.addresses(name).await?;
    for address in want {
        if !existing.contains(address) {
            ops.add_address(name, *address).await?;
            changed.push(format!("added {address} to {name}"));
        }
    }
    for address in &existing {
        // A link-local address is the kernel's, not ours. Removing it would
        // remove the interface's ability to talk to itself, on every refresh.
        if is_link_local(address) || want.contains(address) {
            continue;
        }
        ops.del_address(name, *address).await?;
        changed.push(format!("removed {address} from {name}"));
    }
    Ok(())
}

/// Write a kernel knob only when it does not already say what it should.
///
/// A knob the kernel does not have is skipped rather than fatal: IPv6 can be
/// compiled out, and a node with no IPv6 guests is still a working node.
async fn set_if_needed(
    ops: &dyn NetOps,
    key: &str,
    value: &str,
    changed: &mut Vec<String>,
) -> Result<()> {
    match ops.sysctl(key).await? {
        Some(current) if current.trim() == value => Ok(()),
        Some(_) => {
            ops.set_sysctl(key, value).await?;
            changed.push(format!("set {key}={value}"));
            Ok(())
        }
        None => Ok(()),
    }
}

/// The addresses the tunnel interface should carry.
fn tunnel_addresses(desired: &DesiredDataPlane) -> Result<Vec<IpNetwork>> {
    [&desired.tunnel.address4, &desired.tunnel.address6]
        .into_iter()
        .flatten()
        .map(|a| {
            a.parse::<IpNetwork>()
                .with_context(|| format!("LNVPS sent {a}, which is not an address"))
        })
        .collect()
}

/// The default routes to install, one per family the tunnel has an address in.
///
/// A family with no address gets no default route: it would black-hole that
/// family's traffic rather than leaving the machine's own routing to handle it.
fn default_routes(desired: &DesiredDataPlane) -> Vec<IpNetwork> {
    let mut out = Vec::new();
    if desired.tunnel.address4.is_some() {
        out.push("0.0.0.0/0".parse().expect("a constant CIDR"));
    }
    if desired.tunnel.address6.is_some() {
        out.push("::/0".parse().expect("a constant CIDR"));
    }
    out
}

/// `203.0.113.1` -> `203.0.113.1/32`, and the v6 equivalent. A value that
/// already carries a prefix is taken as it is.
fn host_prefix(address: &str) -> Result<IpNetwork> {
    if address.contains('/') {
        return address
            .parse::<IpNetwork>()
            .with_context(|| format!("{address} is not a CIDR"));
    }
    let ip: IpAddr = address
        .parse()
        .with_context(|| format!("{address} is not an IP address"))?;
    Ok(IpNetwork::from(ip))
}

/// Addresses the kernel manages for itself.
fn is_link_local(address: &IpNetwork) -> bool {
    match address.ip() {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80 || v6.is_loopback(),
    }
}

/// Read back what the machine actually has.
pub async fn observe(ops: &dyn NetOps, fw: &dyn crate::fw::FirewallOps) -> Result<DataPlaneState> {
    let (tunnel_up, tunnel_mtu) = ops.link_state(TUNNEL_INTERFACE).await?;
    let (bridge_up, _) = ops.link_state(GUEST_BRIDGE).await?;
    let last_handshake_secs = ops
        .wireguard_state(TUNNEL_INTERFACE)
        .await?
        .and_then(|w| w.peers.into_iter().filter_map(|(_, age)| age).min());
    Ok(DataPlaneState {
        tunnel_up,
        tunnel_mtu,
        last_handshake_secs,
        bridge_up,
        forwarding4: enabled(ops, "net/ipv4/ip_forward").await?,
        forwarding6: enabled(ops, "net/ipv6/conf/all/forwarding").await?,
        routed_guests: ops.routes(GUEST_BRIDGE).await?.len(),
        firewall: crate::fw::observe(fw).await,
    })
}

async fn enabled(ops: &dyn NetOps, key: &str) -> Result<bool> {
    Ok(ops
        .sysctl(key)
        .await?
        .map(|v| v.trim() == "1")
        .unwrap_or(false))
}

#[cfg(test)]
pub mod tests;
