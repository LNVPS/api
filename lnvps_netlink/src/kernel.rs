//! The real implementation: netlink for links, addresses and routes, the
//! kernel's WireGuard netlink interface for the tunnel, and `/proc/sys` for the
//! forwarding knobs.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use async_trait::async_trait;
use ipnetwork::IpNetwork;

use crate::netns;
use crate::ops::{NetOps, WgObserved, WgPeer, WgPeerState, WgSettings};
use crate::sysctl::{PROC_SYS, read_sysctl, write_sysctl};

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

/// Talks to the kernel, optionally inside a network namespace of its own.
///
/// The two daemons want opposite things here, and both are right.
///
/// A marketplace node is often not *only* a marketplace node: it is somebody
/// else's machine, running somebody else's workloads, and configuring routes,
/// forwarding and proxy ARP in its own namespace would be configuring the
/// operator's network for them. So it gets a namespace. See [`crate::netns`].
///
/// A VPN route server is a machine LNVPS runs for exactly this and nothing
/// else. Its interfaces, its routes and its forwarding *are* the host's, and
/// hiding them in a namespace would mean an operator debugging it could not see
/// them from a plain shell.
pub struct Kernel {
    handle: Handle,
    /// The namespace everything is configured in, or `None` for the machine's
    /// own.
    namespace: Option<netns::Handle>,
}

impl Kernel {
    /// Open a netlink connection inside the data plane namespace,
    /// creating the namespace if this is the first run.
    pub fn new() -> Result<Self> {
        Self::in_namespace(netns::ensure_default()?)
    }

    /// Configure the machine this is running on, with no namespace.
    ///
    /// For a daemon whose whole job is the host's network. Nothing is hidden,
    /// so `ip link` in a plain shell shows what the daemon built, which is what
    /// an operator will reach for first when it is not working.
    pub fn host() -> Result<Self> {
        let (connection, handle, _) = new_connection().context("Cannot open a netlink socket")?;
        tokio::spawn(connection);
        Ok(Self {
            handle,
            namespace: None,
        })
    }

    /// Run `f` where this kernel's interfaces live.
    ///
    /// A netlink socket, and `/proc/sys/net`, belong to the namespace of the
    /// thread that opened or read them. Without this, a namespaced kernel
    /// reports "no such device" about an interface that plainly exists, and
    /// reads the operator's forwarding setting as its own.
    ///
    /// Public because a daemon has its own things to do in the same place: a
    /// node reads the tunnel's addresses and binds its control listener there,
    /// and both would otherwise have to ask whether there is a namespace before
    /// they could ask the question they actually had.
    pub fn here<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + Send,
        T: Send,
    {
        match &self.namespace {
            Some(ns) => ns.enter(f),
            None => f(),
        }
    }

    /// Same, for an already-open namespace. Used by the end-to-end harness,
    /// which builds its own.
    pub fn in_namespace(namespace: netns::Handle) -> Result<Self> {
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
        Ok(Self {
            handle,
            namespace: Some(namespace),
        })
    }

    /// The namespace this configures, or `None` when it configures the machine
    /// itself.
    pub fn namespace(&self) -> Option<&netns::Handle> {
        self.namespace.as_ref()
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
                    RouteAttribute::Destination(RouteAddress::Inet(v4)) => Some(IpAddr::from(*v4)),
                    RouteAttribute::Destination(RouteAddress::Inet6(v6)) => Some(IpAddr::from(*v6)),
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
        self.here(move || configure(&name, &settings))
    }

    async fn remove_wireguard_peer(&self, name: &str, public_key: &str) -> Result<()> {
        let (name, public_key) = (name.to_string(), public_key.to_string());
        self.here(move || {
            let api = WGApi::<WgKernel>::new(name.clone())
                .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
            let key = Key::from_str(&public_key).context("Not a WireGuard key")?;
            api.remove_peer(&key)
                .with_context(|| format!("Cannot remove peer {public_key} from {name}"))
        })
    }

    async fn configure_wireguard_interface(
        &self,
        name: &str,
        private_key: &str,
        listen_port: u16,
    ) -> Result<()> {
        let (name, private_key) = (name.to_string(), private_key.to_string());
        self.here(move || {
            let api = WGApi::<WgKernel>::new(name.clone())
                .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
            // Addresses are left empty and managed over netlink, so that one
            // code path owns them. Note that this call flushes them, which is
            // the other reason it is only made when the key or port is wrong.
            let config = InterfaceConfiguration {
                name: name.clone(),
                prvkey: private_key,
                addresses: vec![],
                port: listen_port,
                peers: vec![],
                mtu: None,
                fwmark: None,
            };
            api.configure_interface(&config)
                .with_context(|| format!("Cannot configure WireGuard interface {name}"))
        })
    }

    async fn set_wireguard_peer(&self, name: &str, peer: &WgPeer) -> Result<()> {
        let (name, peer) = (name.to_string(), peer.clone());
        self.here(move || {
            let api = WGApi::<WgKernel>::new(name.clone())
                .with_context(|| format!("Cannot address WireGuard interface {name}"))?;
            let endpoint = match &peer.endpoint {
                Some(e) => {
                    Some(resolve(e).with_context(|| format!("Cannot resolve peer endpoint {e}"))?)
                }
                None => None,
            };
            let p = Peer {
                public_key: Key::from_str(&peer.public_key).context("Not a WireGuard key")?,
                endpoint,
                persistent_keepalive_interval: peer.persistent_keepalive,
                allowed_ips: peer
                    .allowed_ips
                    .iter()
                    .map(|n| IpAddrMask::new(n.ip(), n.prefix()))
                    .collect(),
                ..Default::default()
            };
            api.configure_peer(&p)
                .with_context(|| format!("Cannot configure peer {} on {name}", peer.public_key))
        })
    }

    async fn wireguard_state(&self, name: &str) -> Result<Option<WgObserved>> {
        if !self.link_exists(name).await? {
            return Ok(None);
        }
        let name = name.to_string();
        self.here(move || observe_wireguard(&name)).map(Some)
    }

    async fn sysctl(&self, key: &str) -> Result<Option<String>> {
        // `/proc/sys/net` reflects the reading thread's namespace, so this
        // has to be read from inside — otherwise the node would report the
        // operator's forwarding setting as its own.
        let key = key.to_string();
        self.here(move || read_sysctl(Path::new(PROC_SYS), &key))
    }

    async fn set_sysctl(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_string(), value.to_string());
        self.here(move || write_sysctl(Path::new(PROC_SYS), &key, &value))
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
        listen_port: host.listen_port,
        public_key: host
            .private_key
            .as_ref()
            .map(|k| k.public_key().to_string()),
        peers: host
            .peers
            .values()
            .map(|p| WgPeerState {
                public_key: p.public_key.to_string(),
                last_handshake_secs: p
                    .last_handshake
                    // The zero time means "never", not 1970: reporting
                    // an age of half a century would look like a stale
                    // tunnel rather than one that has never worked.
                    .filter(|t| *t != std::time::UNIX_EPOCH)
                    .and_then(|t| now.duration_since(t).ok())
                    .map(|d| d.as_secs()),
                allowed_ips: p
                    .allowed_ips
                    .iter()
                    .filter_map(|a| IpNetwork::new(a.address, a.cidr).ok())
                    .collect(),
                endpoint: p.endpoint.map(|e| e.to_string()),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
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
        // Nothing to move: this kernel's interfaces are the machine's, and
        // they are already where they belong.
        let Some(namespace) = &self.namespace else {
            return Ok(());
        };
        let (connection, handle, _) = new_connection().context("Cannot open a netlink socket")?;
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
                    .setns_by_fd(namespace.as_raw_fd())
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
