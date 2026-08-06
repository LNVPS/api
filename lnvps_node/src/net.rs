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
use std::path::Path;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::wgkey::{self, NodeKey};

/// The tunnel interface the node terminates its data plane on.
pub const TUNNEL_INTERFACE: &str = "wg0";

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

/// How a WireGuard interface should be configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgSettings {
    /// Base64, as WireGuard states keys.
    pub private_key: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub keepalive: Option<u16>,
    /// Everything, for a node: its guests use LNVPS addresses, so no traffic of
    /// theirs belongs anywhere else.
    pub allowed_ips: Vec<IpNetwork>,
}

/// What a WireGuard interface currently is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WgObserved {
    /// Peers keyed by public key, with seconds since each last handshake.
    pub peers: Vec<(String, Option<u64>)>,
}

/// The kernel operations the data plane needs.
///
/// A trait so the orchestration above it can be tested without root, and so the
/// end-to-end harness can drive the same code inside a network namespace.
#[async_trait]
pub trait NetOps: Send + Sync {
    /// Whether a link exists.
    async fn link_exists(&self, name: &str) -> Result<bool>;
    /// Create a WireGuard interface.
    async fn create_wireguard(&self, name: &str) -> Result<()>;
    /// Create a bridge.
    async fn create_bridge(&self, name: &str) -> Result<()>;
    /// Bring a link up with the given MTU.
    async fn set_up(&self, name: &str, mtu: u32) -> Result<()>;
    /// Whether a link is up, and its MTU.
    async fn link_state(&self, name: &str) -> Result<(bool, Option<u32>)>;

    async fn addresses(&self, name: &str) -> Result<Vec<IpNetwork>>;
    async fn add_address(&self, name: &str, address: IpNetwork) -> Result<()>;
    async fn del_address(&self, name: &str, address: IpNetwork) -> Result<()>;

    /// Destinations routed out of `name`.
    async fn routes(&self, name: &str) -> Result<Vec<IpNetwork>>;
    async fn add_route(&self, destination: IpNetwork, name: &str) -> Result<()>;
    async fn del_route(&self, destination: IpNetwork, name: &str) -> Result<()>;

    /// Configure the WireGuard interface: key, peer, allowed IPs.
    async fn configure_wireguard(&self, name: &str, settings: &WgSettings) -> Result<()>;
    /// Remove a peer by public key.
    async fn remove_wireguard_peer(&self, name: &str, public_key: &str) -> Result<()>;
    /// Read the interface back, or `None` when it does not exist.
    async fn wireguard_state(&self, name: &str) -> Result<Option<WgObserved>>;

    /// Read a kernel knob, or `None` when this kernel does not have it.
    async fn sysctl(&self, key: &str) -> Result<Option<String>>;
    async fn set_sysctl(&self, key: &str, value: &str) -> Result<()>;
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
}

impl DataPlaneState {
    /// Whether this node can carry a customer.
    ///
    /// A handshake is required, not just an interface: `wg0` comes up happily
    /// with a peer that never answers, and a node in that state looks
    /// configured while being unreachable.
    pub fn healthy(&self) -> bool {
        self.tunnel_up && self.last_handshake_secs.is_some() && self.bridge_up && self.forwarding4
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
    desired: &DesiredDataPlane,
    key: &NodeKey,
) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    apply_tunnel(ops, desired, key, &mut changed).await?;
    apply_bridge(ops, desired, &mut changed).await?;
    apply_forwarding(ops, &mut changed).await?;
    Ok(changed)
}

/// Bring up `wg0` and point the default route down it.
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
    let mut to_drop: Vec<&IpNetwork> = existing
        .difference(&guests)
        .filter(|r| !is_link_local(r))
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
pub async fn observe(ops: &dyn NetOps) -> Result<DataPlaneState> {
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
    })
}

async fn enabled(ops: &dyn NetOps, key: &str) -> Result<bool> {
    Ok(ops
        .sysctl(key)
        .await?
        .map(|v| v.trim() == "1")
        .unwrap_or(false))
}

/// Where the kernel exposes its knobs. A path rather than the `sysctl` binary:
/// one less program a node has to have installed, and a write that either
/// happens or reports why.
const PROC_SYS: &str = "/proc/sys";

/// Read a kernel knob from `/proc/sys`.
pub fn read_sysctl(root: &Path, key: &str) -> Result<Option<String>> {
    let path = root.join(key);
    match std::fs::read_to_string(&path) {
        Ok(value) => Ok(Some(value)),
        // Absent means this kernel does not have the knob — IPv6 can be
        // compiled out — which is a fact about the machine, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Cannot read {}", path.display())),
    }
}

/// Write a kernel knob to `/proc/sys`.
pub fn write_sysctl(root: &Path, key: &str, value: &str) -> Result<()> {
    let path = root.join(key);
    std::fs::write(&path, value).with_context(|| format!("Cannot set {}", path.display()))
}

pub use kernel::Kernel;

/// A machine whose network cannot be read.
///
/// Not a mock: it is what a node that has never been configured looks like from
/// outside, and reporting that truthfully is what lets the health gate say
/// "this node has no data plane" instead of timing out.
pub struct UnavailableKernel;

#[async_trait]
impl NetOps for UnavailableKernel {
    async fn link_exists(&self, _name: &str) -> Result<bool> {
        Ok(false)
    }
    async fn create_wireguard(&self, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn create_bridge(&self, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn set_up(&self, _name: &str, _mtu: u32) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn link_state(&self, _name: &str) -> Result<(bool, Option<u32>)> {
        Ok((false, None))
    }
    async fn addresses(&self, _name: &str) -> Result<Vec<IpNetwork>> {
        Ok(vec![])
    }
    async fn add_address(&self, _name: &str, _address: IpNetwork) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn del_address(&self, _name: &str, _address: IpNetwork) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn routes(&self, _name: &str) -> Result<Vec<IpNetwork>> {
        Ok(vec![])
    }
    async fn add_route(&self, _destination: IpNetwork, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn del_route(&self, _destination: IpNetwork, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn configure_wireguard(&self, _name: &str, _settings: &WgSettings) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn remove_wireguard_peer(&self, _name: &str, _public_key: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn wireguard_state(&self, _name: &str) -> Result<Option<WgObserved>> {
        Ok(None)
    }
    async fn sysctl(&self, _key: &str) -> Result<Option<String>> {
        Ok(None)
    }
    async fn set_sysctl(&self, _key: &str, _value: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
}

/// The real implementation: netlink for links, addresses and routes, the
/// kernel's WireGuard netlink interface for the tunnel, and `/proc/sys` for the
/// forwarding knobs.
mod kernel {
    use super::*;

    use defguard_wireguard_rs::key::Key;
    use defguard_wireguard_rs::net::IpAddrMask;
    use defguard_wireguard_rs::peer::Peer;
    use defguard_wireguard_rs::{
        InterfaceConfiguration, Kernel as WgKernel, WGApi, WireguardInterfaceApi,
    };
    use futures_util::TryStreamExt;
    use netlink_packet_route::address::AddressAttribute;
    use netlink_packet_route::link::LinkFlags;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader};
    use rtnetlink::{Handle, LinkBridge, LinkUnspec, RouteMessageBuilder, new_connection};

    /// Talks to the kernel, inside the data plane's own network namespace.
    ///
    /// The namespace is why this type exists at all: a marketplace node is
    /// often not only a marketplace node, and configuring routes, forwarding
    /// and proxy ARP in the machine's own namespace would be configuring the
    /// operator's network for them. See [`crate::netns`].
    pub struct Kernel {
        handle: Handle,
        namespace: crate::netns::Handle,
    }

    impl Kernel {
        /// Open a netlink connection inside the data plane namespace,
        /// creating the namespace if this is the first run.
        pub fn new() -> Result<Self> {
            Self::in_namespace(crate::netns::ensure_default()?)
        }

        /// Same, for an already-open namespace. Used by the end-to-end harness,
        /// which builds its own.
        pub fn in_namespace(namespace: crate::netns::Handle) -> Result<Self> {
            // The socket is opened *inside* the namespace: a netlink socket
            // belongs to the namespace it was created in, so everything sent
            // over this one lands there no matter which thread sends it.
            //
            // The runtime handle goes with it because the socket registers with
            // tokio's reactor as it is created, and the thread that enters the
            // namespace is a bare one — without this it panics with "there is
            // no reactor running", which is a confusing way to discover that a
            // namespace and a runtime are different kinds of context.
            let runtime = tokio::runtime::Handle::current();
            let (connection, handle, _) = namespace.enter(move || {
                let _guard = runtime.enter();
                new_connection().context("Cannot open a netlink socket")
            })?;
            tokio::spawn(connection);
            Ok(Self { handle, namespace })
        }

        /// The namespace this configures.
        pub fn namespace(&self) -> &crate::netns::Handle {
            &self.namespace
        }

        async fn index(&self, name: &str) -> Result<Option<u32>> {
            let mut links = self
                .handle
                .link()
                .get()
                .match_name(name.to_string())
                .execute();
            match links.try_next().await {
                Ok(Some(link)) => Ok(Some(link.header.index)),
                // "no such device" arrives as an error, and it is an answer
                // rather than a fault: the caller is asking whether to create it.
                Ok(None) | Err(_) => Ok(None),
            }
        }

        async fn require_index(&self, name: &str) -> Result<u32> {
            self.index(name)
                .await?
                .with_context(|| format!("Interface {name} does not exist"))
        }
    }

    #[async_trait]
    impl NetOps for Kernel {
        async fn link_exists(&self, name: &str) -> Result<bool> {
            Ok(self.index(name).await?.is_some())
        }

        async fn create_wireguard(&self, name: &str) -> Result<()> {
            // Deliberately created in the machine's own namespace and then
            // moved: a WireGuard interface keeps its UDP socket in the
            // namespace it was created in. Created inside, it could only reach
            // a route server through itself. This way the encrypted outer
            // traffic still leaves by the operator's uplink while everything
            // carried over the tunnel stays isolated.
            let mut api = WGApi::<WgKernel>::new(name.to_string())
                .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
            api.create_interface()
                .with_context(|| format!("Cannot create WireGuard interface {name}"))?;
            self.move_into_namespace(name).await
        }

        async fn create_bridge(&self, name: &str) -> Result<()> {
            // Created inside: nothing about a bridge needs the machine's own
            // namespace, and a guest port must never be attachable from there.
            self.handle
                .link()
                .add(LinkBridge::new(name).build())
                .execute()
                .await
                .with_context(|| format!("Cannot create bridge {name}"))
        }

        async fn set_up(&self, name: &str, mtu: u32) -> Result<()> {
            let index = self.require_index(name).await?;
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(index).up().mtu(mtu).build())
                .execute()
                .await
                .with_context(|| format!("Cannot bring {name} up with MTU {mtu}"))
        }

        async fn link_state(&self, name: &str) -> Result<(bool, Option<u32>)> {
            let mut links = self
                .handle
                .link()
                .get()
                .match_name(name.to_string())
                .execute();
            let Ok(Some(link)) = links.try_next().await else {
                return Ok((false, None));
            };
            let up = link.header.flags.contains(LinkFlags::Up);
            let mtu = link.attributes.iter().find_map(|a| {
                if let netlink_packet_route::link::LinkAttribute::Mtu(mtu) = a {
                    Some(*mtu)
                } else {
                    None
                }
            });
            Ok((up, mtu))
        }

        async fn addresses(&self, name: &str) -> Result<Vec<IpNetwork>> {
            let Some(index) = self.index(name).await? else {
                return Ok(vec![]);
            };
            let mut addresses = self
                .handle
                .address()
                .get()
                .set_link_index_filter(index)
                .execute();
            let mut out = Vec::new();
            while let Some(message) = addresses.try_next().await? {
                let prefix = message.header.prefix_len;
                for attribute in message.attributes {
                    if let AddressAttribute::Address(ip) = attribute
                        && let Ok(network) = IpNetwork::new(ip, prefix)
                    {
                        out.push(network);
                    }
                }
            }
            Ok(out)
        }

        async fn add_address(&self, name: &str, address: IpNetwork) -> Result<()> {
            let index = self.require_index(name).await?;
            self.handle
                .address()
                .add(index, address.ip(), address.prefix())
                .execute()
                .await
                .with_context(|| format!("Cannot add {address} to {name}"))
        }

        async fn del_address(&self, name: &str, address: IpNetwork) -> Result<()> {
            let index = self.require_index(name).await?;
            let mut addresses = self
                .handle
                .address()
                .get()
                .set_link_index_filter(index)
                .execute();
            while let Some(message) = addresses.try_next().await? {
                let matches = message.header.prefix_len == address.prefix()
                    && message
                        .attributes
                        .iter()
                        .any(|a| matches!(a, AddressAttribute::Address(ip) if *ip == address.ip()));
                if matches {
                    return self
                        .handle
                        .address()
                        .del(message)
                        .execute()
                        .await
                        .with_context(|| format!("Cannot remove {address} from {name}"));
                }
            }
            Ok(())
        }

        async fn routes(&self, name: &str) -> Result<Vec<IpNetwork>> {
            let Some(index) = self.index(name).await? else {
                return Ok(vec![]);
            };
            let mut out = Vec::new();
            // Both families asked for separately, because netlink dumps one
            // family at a time: a v6 guest would otherwise look unrouted on
            // every pass and be re-added forever.
            for builder in [
                RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
                RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
            ] {
                let mut routes = self.handle.route().get(builder).execute();
                while let Some(route) = routes.try_next().await? {
                    let on_this_link = route
                        .attributes
                        .iter()
                        .any(|a| matches!(a, RouteAttribute::Oif(oif) if *oif == index));
                    // Only the main table. Giving an interface an address makes
                    // the kernel write entries into the *local* table for it,
                    // and treating those as ours means trying to delete the
                    // bridge's own gateway on every sweep — which fails, and
                    // rightly so.
                    if !on_this_link || route.header.table != RouteHeader::RT_TABLE_MAIN {
                        continue;
                    }
                    let destination = route.attributes.iter().find_map(|a| match a {
                        RouteAttribute::Destination(RouteAddress::Inet(v4)) => {
                            Some(IpAddr::from(*v4))
                        }
                        RouteAttribute::Destination(RouteAddress::Inet6(v6)) => {
                            Some(IpAddr::from(*v6))
                        }
                        _ => None,
                    });
                    let prefix = route.header.destination_prefix_length;
                    let network = match destination {
                        Some(ip) => IpNetwork::new(ip, prefix).ok(),
                        // No destination at all is the default route.
                        None if route.header.address_family
                            == netlink_packet_route::AddressFamily::Inet =>
                        {
                            "0.0.0.0/0".parse().ok()
                        }
                        None => "::/0".parse().ok(),
                    };
                    if let Some(network) = network {
                        out.push(network);
                    }
                }
            }
            Ok(out)
        }

        async fn add_route(&self, destination: IpNetwork, name: &str) -> Result<()> {
            let index = self.require_index(name).await?;
            let message = match destination {
                IpNetwork::V4(v4) => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                    .destination_prefix(v4.ip(), v4.prefix())
                    .output_interface(index)
                    .build(),
                IpNetwork::V6(v6) => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                    .destination_prefix(v6.ip(), v6.prefix())
                    .output_interface(index)
                    .build(),
            };
            self.handle
                .route()
                .add(message)
                .replace()
                .execute()
                .await
                .with_context(|| format!("Cannot route {destination} via {name}"))
        }

        async fn del_route(&self, destination: IpNetwork, name: &str) -> Result<()> {
            let index = self.require_index(name).await?;
            let message = match destination {
                IpNetwork::V4(v4) => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                    .destination_prefix(v4.ip(), v4.prefix())
                    .output_interface(index)
                    .build(),
                IpNetwork::V6(v6) => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                    .destination_prefix(v6.ip(), v6.prefix())
                    .output_interface(index)
                    .build(),
            };
            self.handle
                .route()
                .del(message)
                .execute()
                .await
                .with_context(|| format!("Cannot remove the route for {destination} on {name}"))
        }

        async fn configure_wireguard(&self, name: &str, settings: &WgSettings) -> Result<()> {
            // Inside the namespace: the interface was moved there, and
            // WireGuard's netlink socket, like every other, belongs to the
            // namespace of the thread that opens it. Configuring from outside
            // reports "no such device" about an interface that plainly exists.
            let (name, settings) = (name.to_string(), settings.clone());
            self.namespace.enter(move || configure(&name, &settings))
        }

        async fn remove_wireguard_peer(&self, name: &str, public_key: &str) -> Result<()> {
            let (name, public_key) = (name.to_string(), public_key.to_string());
            self.namespace.enter(move || {
                let api = WGApi::<WgKernel>::new(name.clone())
                    .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
                let key = Key::from_str(&public_key).context("Not a WireGuard key")?;
                api.remove_peer(&key)
                    .with_context(|| format!("Cannot remove peer {public_key} from {name}"))
            })
        }

        async fn wireguard_state(&self, name: &str) -> Result<Option<WgObserved>> {
            if !self.link_exists(name).await? {
                return Ok(None);
            }
            let name = name.to_string();
            self.namespace
                .enter(move || observe_wireguard(&name))
                .map(Some)
        }

        async fn sysctl(&self, key: &str) -> Result<Option<String>> {
            // `/proc/sys/net` reflects the reading thread's namespace, so this
            // has to be read from inside — otherwise the node would report the
            // operator's forwarding setting as its own.
            let key = key.to_string();
            self.namespace
                .enter(move || read_sysctl(Path::new(PROC_SYS), &key))
        }

        async fn set_sysctl(&self, key: &str, value: &str) -> Result<()> {
            let (key, value) = (key.to_string(), value.to_string());
            self.namespace
                .enter(move || write_sysctl(Path::new(PROC_SYS), &key, &value))
        }
    }

    /// Configure a WireGuard interface. Runs on a thread already inside the
    /// data plane namespace.
    fn configure(name: &str, settings: &WgSettings) -> Result<()> {
        let api = WGApi::<WgKernel>::new(name.to_string())
            .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
        let peer = Peer {
            public_key: Key::from_str(&settings.peer_public_key)
                .context("The route server's key is not a WireGuard key")?,
            endpoint: Some(
                resolve(&settings.endpoint)
                    .with_context(|| format!("Cannot resolve endpoint {}", settings.endpoint))?,
            ),
            persistent_keepalive_interval: settings.keepalive,
            allowed_ips: settings
                .allowed_ips
                .iter()
                .map(|n| IpAddrMask::new(n.ip(), n.prefix()))
                .collect(),
            ..Default::default()
        };
        // Addresses and MTU are handled through netlink above rather than
        // here, so that one code path owns them for both interfaces.
        let config = InterfaceConfiguration {
            name: name.to_string(),
            prvkey: settings.private_key.clone(),
            addresses: vec![],
            port: 0,
            peers: vec![peer],
            mtu: None,
            fwmark: None,
        };
        api.configure_interface(&config)
            .with_context(|| format!("Cannot configure WireGuard interface {name}"))
    }

    /// Read a WireGuard interface back. Runs inside the namespace, as above.
    fn observe_wireguard(name: &str) -> Result<WgObserved> {
        let api = WGApi::<WgKernel>::new(name.to_string())
            .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
        let host = api
            .read_interface_data()
            .with_context(|| format!("Cannot read WireGuard interface {name}"))?;
        let now = std::time::SystemTime::now();
        Ok(WgObserved {
            peers: host
                .peers
                .values()
                .map(|p| {
                    let age = p
                        .last_handshake
                        // The zero time means "never", not 1970: reporting
                        // an age of half a century would look like a stale
                        // tunnel rather than one that has never worked.
                        .filter(|t| *t != std::time::UNIX_EPOCH)
                        .and_then(|t| now.duration_since(t).ok())
                        .map(|d| d.as_secs());
                    (p.public_key.to_string(), age)
                })
                .collect(),
        })
    }

    impl Kernel {
        /// Move an interface from the machine's namespace into the data
        /// plane's.
        ///
        /// Uses a second netlink socket, opened in the machine's own namespace,
        /// because the move is asked of the namespace the interface is *in*.
        async fn move_into_namespace(&self, name: &str) -> Result<()> {
            let (connection, handle, _) =
                new_connection().context("Cannot open a netlink socket")?;
            tokio::spawn(connection);

            let mut links = handle.link().get().match_name(name.to_string()).execute();
            let Ok(Some(link)) = links.try_next().await else {
                // Already inside: `create_wireguard` is the only caller, and a
                // retry after a partial failure finds it where it belongs.
                return Ok(());
            };
            handle
                .link()
                .set(
                    LinkUnspec::new_with_index(link.header.index)
                        .setns_by_fd(self.namespace.as_raw_fd())
                        .build(),
                )
                .execute()
                .await
                .with_context(|| format!("Cannot move {name} into the data plane namespace"))
        }
    }

    /// Resolve `host:port`, which is what a node is told to dial.
    ///
    /// Resolved here rather than passed through as text because the kernel
    /// takes an address: a name that does not resolve has to fail with that
    /// message, not as a rejected netlink attribute.
    fn resolve(endpoint: &str) -> Result<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        endpoint
            .to_socket_addrs()?
            .next()
            .with_context(|| format!("{endpoint} resolved to no addresses"))
    }

    trait KeyFromStr: Sized {
        fn from_str(value: &str) -> Result<Self>;
    }

    impl KeyFromStr for Key {
        /// WireGuard states keys in base64; the crate wants bytes.
        fn from_str(value: &str) -> Result<Self> {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(value.trim())
                .context("A WireGuard key must be base64")?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("A WireGuard key is 32 bytes, got {}", raw.len()))?;
            Ok(Key::new(bytes))
        }
    }
}

#[cfg(test)]
pub mod tests;
