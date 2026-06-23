use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use lnvps_api_common::retry::OpResult;
use lnvps_db::{LNVpsDb, RouterKind, Vm, VmIpAssignment};
use std::sync::Arc;

/// Router defines a network device used to access the hosts
///
/// In our infrastructure we use this to add static ARP entries on the router
/// for every IP assignment, this way we don't need to have a ton of ARP requests on the
/// VM network because of people doing IP scanning
///
/// It also prevents people from re-assigning their IP to another in the range,
#[async_trait]
pub trait Router: Send + Sync {
    /// Generate mac address for a given IP address
    async fn generate_mac(&self, ip: &str, comment: &str) -> Result<Option<ArpEntry>>;
    async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>>;
    async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry>;
    async fn remove_arp_entry(&self, id: &str) -> OpResult<()>;
    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry>;

    /// Tunnel-management capability, if this router supports it.
    ///
    /// Returns `None` for routers that cannot manage GRE/VXLAN/WireGuard tunnels.
    fn tunnel(&self) -> Option<&dyn TunnelRouter> {
        None
    }

    /// BGP capability, if this router supports it.
    ///
    /// Returns `None` for routers that do not run BGP.
    fn bgp(&self) -> Option<&dyn BgpRouter> {
        None
    }
}

/// Optional capability for routers that run BGP (route servers / edge routers).
///
/// Note: BGP itself exposes no per-session byte counters — traffic accounting is
/// done at the tunnel/interface level (see [`TunnelRouter`]).
#[async_trait]
pub trait BgpRouter: Send + Sync {
    /// Detect configured BGP sessions and their state (issue task 2)
    async fn list_sessions(&self) -> OpResult<Vec<BgpSession>>;
    /// Detect which of the `candidates` prefixes (e.g. VM IP ranges) the router
    /// actually originates/announces (issue task 3).
    ///
    /// Scoped to a candidate set rather than enumerating the table so it stays
    /// bounded on routers carrying a full DFZ table (~1M+ routes). Passing an
    /// empty slice returns all locally-originated prefixes (which is inherently
    /// small — a router only originates its own ranges).
    ///
    /// The returned routes always have `next_hop == None`: an originated prefix
    /// is injected into BGP by a static route for which the router is itself the
    /// source, so there is no gateway to report.
    async fn originated_routes(&self, candidates: &[String]) -> OpResult<Vec<BgpRoute>>;
    /// Detect default route(s), if present (issue task 4 — route-server detection).
    ///
    /// Returns one entry per next-hop. A router using ECMP for its default route
    /// reports multiple next-hops, so the result is a `Vec` rather than a single
    /// route. An empty vec means no default route is installed.
    async fn default_routes(&self) -> OpResult<Vec<BgpRoute>>;
    /// Install or replace the static default route pointing at `next_hop`.
    ///
    /// The address family of the default (`0.0.0.0/0` vs `::/0`) is inferred from
    /// `next_hop`: an IPv6 next hop manages the IPv6 default, otherwise the IPv4
    /// default. Replaces any existing static default for that family.
    async fn set_default_route(&self, next_hop: &str) -> OpResult<()>;
    /// Remove the static default route(s). Idempotent — succeeds even when no
    /// default route is configured.
    async fn clear_default_route(&self) -> OpResult<()>;
    /// Discover BGP peers and classify upstream/downstream (issue task 5)
    async fn discover_peers(&self) -> OpResult<Vec<BgpPeer>>;
    /// Enable or disable a BGP session by its backend id (issue task 6)
    async fn set_session_enabled(&self, id: &str, enabled: bool) -> OpResult<()>;
}

/// Relationship of a BGP peer relative to this router
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BgpPeerDirection {
    /// The peer is a transit provider (we are its customer)
    Upstream,
    /// The peer is our customer (we provide transit)
    Downstream,
    /// Settlement-free / lateral peer
    Peer,
    /// Relationship could not be determined
    #[default]
    Unknown,
}

/// A detected BGP session
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpSession {
    /// Backend identifier used for toggling (protocol name on BIRD, `.id` on Mikrotik)
    pub id: String,
    /// Human-readable session/protocol name
    pub name: String,
    /// Neighbour address
    pub peer_ip: Option<String>,
    /// Neighbour AS number
    pub peer_asn: Option<u32>,
    /// Local AS number
    pub local_asn: Option<u32>,
    /// Session state (e.g. `Established`, `Active`, `Idle`)
    pub state: String,
    /// Number of prefixes received from the peer
    pub prefixes_received: Option<u64>,
    /// Number of prefixes sent to the peer
    pub prefixes_sent: Option<u64>,
    /// Whether the session is administratively enabled
    pub enabled: bool,
    /// Inferred peer relationship
    pub direction: BgpPeerDirection,
}

/// A discovered BGP peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPeer {
    /// Peer address
    pub peer_ip: Option<String>,
    /// Peer AS number
    pub asn: Option<u32>,
    /// Inferred relationship
    pub direction: BgpPeerDirection,
}

/// A route in the routing table
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpRoute {
    /// Destination prefix (CIDR)
    pub prefix: String,
    /// Next hop / gateway, if any.
    ///
    /// Always `None` for originated routes (see [`BgpRouter::originated_routes`]):
    /// a router *originates* a prefix into BGP via a static unicast/blackhole
    /// route to which it is itself the source, so there is no gateway. A next hop
    /// is only meaningful for routes the router *forwards* through (e.g. the
    /// default route).
    pub next_hop: Option<String>,
}

/// Optional capability for routers that can manage point-to-point/overlay tunnels
/// (GRE, VXLAN, WireGuard) and report per-tunnel traffic counters.
///
/// Per-tunnel byte counters are the canonical source of "per session" traffic for
/// route servers — BGP itself exposes no byte counters.
#[async_trait]
pub trait TunnelRouter: Send + Sync {
    /// List all tunnels currently configured on the router
    async fn list_tunnels(&self) -> OpResult<Vec<Tunnel>>;
    /// Create a new tunnel
    async fn add_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel>;
    /// Remove a tunnel by its backend id (interface name on Linux)
    async fn remove_tunnel(&self, id: &str) -> OpResult<()>;
    /// Update an existing tunnel
    async fn update_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel>;
    /// Enable or disable a tunnel by its backend id (interface name on Linux,
    /// `"<kind>:<.id>"` on Mikrotik).
    async fn set_tunnel_enabled(&self, id: &str, enabled: bool) -> OpResult<()>;
    /// Report per-tunnel rx/tx byte counters
    async fn tunnel_traffic(&self) -> OpResult<Vec<TunnelTraffic>>;
}

/// The kind of a tunnel interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelKind {
    Gre,
    Vxlan,
    Wireguard,
}

/// A tunnel interface (GRE, VXLAN or WireGuard)
#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
    /// Backend identifier (interface name on Linux, `.id` on Mikrotik)
    pub id: Option<String>,
    /// Interface name
    pub name: String,
    /// Local tunnel endpoint address
    pub local_addr: Option<String>,
    /// Remote tunnel endpoint address
    pub remote_addr: Option<String>,
    /// Whether the interface is administratively up
    pub enabled: bool,
    /// Kind-specific configuration
    pub config: TunnelConfig,
}

impl Tunnel {
    /// The kind of this tunnel, derived from its config
    pub fn kind(&self) -> TunnelKind {
        match self.config {
            TunnelConfig::Gre(_) => TunnelKind::Gre,
            TunnelConfig::Vxlan(_) => TunnelKind::Vxlan,
            TunnelConfig::Wireguard(_) => TunnelKind::Wireguard,
        }
    }
}

/// Kind-specific tunnel configuration
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelConfig {
    Gre(GreConfig),
    Vxlan(VxlanConfig),
    Wireguard(WireguardConfig),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GreConfig {
    /// GRE key (shared between local/remote tunnel ends)
    pub key: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VxlanConfig {
    /// VXLAN network identifier (VNI)
    pub vni: u32,
    /// UDP destination port (default 4789)
    pub dst_port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireguardConfig {
    /// UDP listen port
    pub listen_port: Option<u16>,
    /// Interface private key (PEM/base64); never returned when listing
    pub private_key: Option<String>,
    /// Interface public key
    pub public_key: Option<String>,
    /// Configured peers
    pub peers: Vec<WireguardPeer>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireguardPeer {
    /// Peer public key
    pub public_key: String,
    /// Peer endpoint (host:port)
    pub endpoint: Option<String>,
    /// Allowed IP ranges (CIDR)
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval in seconds
    pub persistent_keepalive: Option<u16>,
}

/// Per-tunnel traffic counters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelTraffic {
    /// Tunnel interface name
    pub name: String,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
}

impl From<TunnelKind> for lnvps_db::RouterTunnelKind {
    fn from(k: TunnelKind) -> Self {
        match k {
            TunnelKind::Gre => lnvps_db::RouterTunnelKind::Gre,
            TunnelKind::Vxlan => lnvps_db::RouterTunnelKind::Vxlan,
            TunnelKind::Wireguard => lnvps_db::RouterTunnelKind::Wireguard,
        }
    }
}

impl Tunnel {
    /// Build a cacheable DB row for this tunnel under the given router.
    pub fn to_db(&self, router_id: u64) -> lnvps_db::RouterTunnel {
        lnvps_db::RouterTunnel {
            id: 0,
            router_id,
            name: self.name.clone(),
            kind: self.kind().into(),
            local_addr: self.local_addr.clone(),
            remote_addr: self.remote_addr.clone(),
            enabled: self.enabled,
            last_seen: chrono::Utc::now(),
        }
    }
}

impl From<BgpPeerDirection> for lnvps_db::RouterBgpDirection {
    fn from(d: BgpPeerDirection) -> Self {
        match d {
            BgpPeerDirection::Upstream => lnvps_db::RouterBgpDirection::Upstream,
            BgpPeerDirection::Downstream => lnvps_db::RouterBgpDirection::Downstream,
            BgpPeerDirection::Peer => lnvps_db::RouterBgpDirection::Peer,
            BgpPeerDirection::Unknown => lnvps_db::RouterBgpDirection::Unknown,
        }
    }
}

impl BgpSession {
    /// Build a cacheable DB row for this session under the given router.
    pub fn to_db(&self, router_id: u64) -> lnvps_db::RouterBgpSession {
        lnvps_db::RouterBgpSession {
            id: 0,
            router_id,
            name: self.name.clone(),
            peer_ip: self.peer_ip.clone(),
            peer_asn: self.peer_asn,
            local_asn: self.local_asn,
            state: self.state.clone(),
            prefixes_received: self.prefixes_received,
            prefixes_sent: self.prefixes_sent,
            // Initial import value only: a protocol in "Down" state is treated as
            // administratively disabled. On subsequent refreshes the database
            // `enabled` flag is authoritative and is preserved by the upsert.
            enabled: !self.state.eq_ignore_ascii_case("down"),
            direction: self.direction.into(),
            last_seen: chrono::Utc::now(),
        }
    }
}

impl BgpRoute {
    /// Build a cacheable DB row for this route under the given router.
    pub fn to_db(&self, router_id: u64, is_default: bool) -> lnvps_db::RouterBgpRoute {
        lnvps_db::RouterBgpRoute {
            id: 0,
            router_id,
            prefix: self.prefix.clone(),
            next_hop: self.next_hop.clone(),
            is_default,
            last_seen: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub id: Option<String>,
    pub address: String,
    pub mac_address: String,
    pub interface: Option<String>,
    pub comment: Option<String>,
}

impl ArpEntry {
    pub fn new(vm: &Vm, ip: &VmIpAssignment, interface: Option<String>) -> Result<Self> {
        ensure!(
            vm.mac_address != "ff:ff:ff:ff:ff:ff",
            "MAC address is invalid because its blank"
        );
        Ok(Self {
            id: ip.arp_ref.clone(),
            address: ip.ip.clone(),
            mac_address: vm.mac_address.clone(),
            interface,
            comment: Some(format!("VM{}", vm.id)),
        })
    }
}

#[cfg(feature = "linux-ssh")]
mod linux_ssh;
#[cfg(feature = "mikrotik")]
mod mikrotik;
mod ovh;

#[cfg(feature = "linux-ssh")]
pub use linux_ssh::LinuxSshRouter;
#[cfg(feature = "mikrotik")]
pub use mikrotik::MikrotikRouter;
pub use ovh::OvhDedicatedServerVMacRouter;

pub async fn get_router(db: &Arc<dyn LNVpsDb>, router_id: u64) -> OpResult<Arc<dyn Router>> {
    let cfg = db.get_router(router_id).await?;
    match cfg.kind {
        RouterKind::Mikrotik => {
            let mut t_split = cfg.token.as_str().split(":");
            let (username, password) = (
                t_split.next().context("Invalid username:password")?,
                t_split.next().context("Invalid username:password")?,
            );
            Ok(Arc::new(MikrotikRouter::new(&cfg.url, username, password)))
        }
        RouterKind::OvhAdditionalIp => Ok(Arc::new(
            OvhDedicatedServerVMacRouter::new(&cfg.url, &cfg.name, cfg.token.as_str()).await?,
        )),
        #[cfg(feature = "linux-ssh")]
        RouterKind::LinuxSsh => Ok(Arc::new(LinuxSshRouter::new(&cfg.url, cfg.token.as_str())?)),
        #[cfg(not(feature = "linux-ssh"))]
        RouterKind::LinuxSsh => Err(lnvps_api_common::retry::OpError::Fatal(anyhow::anyhow!(
            "LinuxSsh router support is not enabled in this build"
        ))),
        RouterKind::MockRouter => {
            #[cfg(test)]
            return Ok(Arc::new(crate::mocks::MockRouter::new()));
            #[cfg(not(test))]
            {
                #[allow(unreachable_code)]
                panic!("Cant use mock router outside tests!")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::MockRouter;

    fn sample_tunnel(name: &str) -> Tunnel {
        Tunnel {
            id: None,
            name: name.to_string(),
            local_addr: Some("10.0.0.1".to_string()),
            remote_addr: Some("10.0.0.2".to_string()),
            enabled: false,
            config: TunnelConfig::Gre(GreConfig { key: Some(7) }),
        }
    }

    #[tokio::test]
    async fn test_mock_tunnel_lifecycle() -> anyhow::Result<()> {
        let r = MockRouter::new();
        r.clear().await;
        let tr = r.tunnel().expect("mock router supports tunnels");

        assert!(tr.list_tunnels().await.unwrap().is_empty());

        let added = tr.add_tunnel(&sample_tunnel("gre1")).await.unwrap();
        assert_eq!(added.id.as_deref(), Some("gre1"));
        assert!(added.enabled);
        assert_eq!(added.kind(), TunnelKind::Gre);

        // duplicate add fails
        assert!(tr.add_tunnel(&sample_tunnel("gre1")).await.is_err());

        let list = tr.list_tunnels().await.unwrap();
        assert_eq!(list.len(), 1);

        let traffic = tr.tunnel_traffic().await.unwrap();
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].name, "gre1");

        let mut upd = sample_tunnel("gre1");
        upd.remote_addr = Some("10.0.0.9".to_string());
        let updated = tr.update_tunnel(&upd).await.unwrap();
        assert_eq!(updated.remote_addr.as_deref(), Some("10.0.0.9"));

        tr.remove_tunnel("gre1").await.unwrap();
        assert!(tr.list_tunnels().await.unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_mock_bgp() -> anyhow::Result<()> {
        let r = MockRouter::new();
        r.clear().await;
        r.add_session(BgpSession {
            id: "s1".to_string(),
            name: "upstream1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: Some(10),
            prefixes_sent: Some(2),
            enabled: true,
            direction: BgpPeerDirection::Upstream,
        })
        .await;
        let bgp = r.bgp().expect("mock router supports bgp");

        let sessions = bgp.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].peer_asn, Some(64512));

        let peers = bgp.discover_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].direction, BgpPeerDirection::Upstream);

        // empty candidates => all originated; scoped candidates => filtered subset
        assert!(!bgp.originated_routes(&[]).await.unwrap().is_empty());
        assert_eq!(
            bgp.originated_routes(&["203.0.113.0/24".to_string()])
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            bgp.originated_routes(&["10.0.0.0/8".to_string()])
                .await
                .unwrap()
                .is_empty()
        );
        assert!(!bgp.default_routes().await.unwrap().is_empty());

        bgp.set_session_enabled("s1", false).await.unwrap();
        let sessions = bgp.list_sessions().await.unwrap();
        assert!(!sessions[0].enabled);
        Ok(())
    }

    /// Regression: a "Down" BGP state is cached as administratively disabled,
    /// so disabling a session (which drives BIRD to state "Down") is reflected
    /// in the database on the next discovery refresh.
    #[test]
    fn test_to_db_state_down_is_disabled() {
        let base = BgpSession {
            id: "s1".to_string(),
            name: "peer1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: Some(10),
            prefixes_sent: Some(2),
            enabled: true,
            direction: BgpPeerDirection::Upstream,
        };
        assert!(base.to_db(1).enabled);

        let down = BgpSession {
            state: "Down".to_string(),
            ..base.clone()
        };
        assert!(!down.to_db(1).enabled);

        // case-insensitive
        let down_lc = BgpSession {
            state: "down".to_string(),
            ..base
        };
        assert!(!down_lc.to_db(1).enabled);
    }

    #[test]
    fn test_bgp_route_to_db() {
        let route = BgpRoute {
            prefix: "192.0.2.0/24".to_string(),
            next_hop: Some("192.0.2.1".to_string()),
        };
        let originated = route.to_db(7, false);
        assert_eq!(originated.router_id, 7);
        assert_eq!(originated.prefix, "192.0.2.0/24");
        assert_eq!(originated.next_hop.as_deref(), Some("192.0.2.1"));
        assert!(!originated.is_default);

        let default = BgpRoute {
            prefix: "0.0.0.0/0".to_string(),
            next_hop: None,
        }
        .to_db(7, true);
        assert!(default.is_default);
    }
}
