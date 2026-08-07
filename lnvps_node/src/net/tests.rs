//! Tests for the orchestration: what the node *decides* to do to a machine.
//!
//! The kernel sits behind [`NetOps`], so these run without root and assert the
//! decisions rather than the netlink encoding of them. Whether those decisions
//! really work on a kernel is proven by the end-to-end harness, which builds
//! both ends of a real tunnel in network namespaces and pings across it.

use std::collections::HashMap;
use std::sync::Mutex;

use super::*;

/// A machine with a working nftables, already carrying the ruleset for the
/// guests below, for the tests that are about the network rather than the
/// filter. The filter's own decisions are tested in [`crate::fw::tests`].
async fn fw() -> crate::fw::tests::FakeFirewall {
    let fake = crate::fw::tests::FakeFirewall::with_nft();
    let policy = crate::fw::Policy::from_desired(&desired()).unwrap();
    crate::fw::apply(&fake, &policy).await.unwrap();
    fake
}

/// A machine that remembers what it was told, and answers questions from what
/// it has been told so far — so a second `apply` sees the first one's work,
/// which is what makes "converges and then goes quiet" testable.
#[derive(Default)]
pub struct FakeKernel {
    links: Mutex<HashMap<String, (bool, Option<u32>)>>,
    addresses: Mutex<HashMap<String, Vec<IpNetwork>>>,
    routes: Mutex<HashMap<String, Vec<IpNetwork>>>,
    wireguard: Mutex<HashMap<String, WgObserved>>,
    settings: Mutex<Option<WgSettings>>,
    sysctls: Mutex<HashMap<String, String>>,
    /// Knobs this kernel does not have at all.
    missing: Vec<String>,
}

impl FakeKernel {
    fn new() -> Self {
        let sysctls = HashMap::from([
            ("net/ipv4/ip_forward".to_string(), "0".to_string()),
            ("net/ipv6/conf/all/forwarding".to_string(), "0".to_string()),
            (
                format!("net/ipv4/conf/{GUEST_BRIDGE}/proxy_arp"),
                "0".to_string(),
            ),
            (
                format!("net/ipv6/conf/{GUEST_BRIDGE}/proxy_ndp"),
                "0".to_string(),
            ),
        ]);
        Self {
            sysctls: Mutex::new(sysctls),
            ..Default::default()
        }
    }

    fn addresses_of(&self, name: &str) -> Vec<IpNetwork> {
        self.addresses
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    fn routes_of(&self, name: &str) -> Vec<IpNetwork> {
        self.routes
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    fn wg_settings(&self) -> Option<WgSettings> {
        self.settings.lock().unwrap().clone()
    }

    fn sysctl_value(&self, key: &str) -> Option<String> {
        self.sysctls.lock().unwrap().get(key).cloned()
    }
}

#[async_trait]
impl NetOps for FakeKernel {
    async fn link_exists(&self, name: &str) -> Result<bool> {
        Ok(self.links.lock().unwrap().contains_key(name))
    }

    async fn create_wireguard(&self, name: &str) -> Result<()> {
        self.links
            .lock()
            .unwrap()
            .insert(name.to_string(), (false, None));
        self.wireguard
            .lock()
            .unwrap()
            .insert(name.to_string(), WgObserved::default());
        Ok(())
    }

    async fn create_bridge(&self, name: &str) -> Result<()> {
        self.links
            .lock()
            .unwrap()
            .insert(name.to_string(), (false, None));
        Ok(())
    }

    async fn set_up(&self, name: &str, mtu: u32) -> Result<()> {
        self.links
            .lock()
            .unwrap()
            .insert(name.to_string(), (true, Some(mtu)));
        Ok(())
    }

    async fn link_state(&self, name: &str) -> Result<(bool, Option<u32>)> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or((false, None)))
    }

    async fn addresses(&self, name: &str) -> Result<Vec<IpNetwork>> {
        Ok(self.addresses_of(name))
    }

    async fn add_address(&self, name: &str, address: IpNetwork) -> Result<()> {
        self.addresses
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(address);
        Ok(())
    }

    async fn del_address(&self, name: &str, address: IpNetwork) -> Result<()> {
        if let Some(list) = self.addresses.lock().unwrap().get_mut(name) {
            list.retain(|a| *a != address);
        }
        Ok(())
    }

    async fn routes(&self, name: &str) -> Result<Vec<IpNetwork>> {
        Ok(self.routes_of(name))
    }

    async fn add_route(&self, destination: IpNetwork, name: &str) -> Result<()> {
        self.routes
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(destination);
        Ok(())
    }

    async fn del_route(&self, destination: IpNetwork, name: &str) -> Result<()> {
        if let Some(list) = self.routes.lock().unwrap().get_mut(name) {
            list.retain(|r| *r != destination);
        }
        Ok(())
    }

    async fn configure_wireguard(&self, name: &str, settings: &WgSettings) -> Result<()> {
        *self.settings.lock().unwrap() = Some(settings.clone());
        self.wireguard
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .peers
            .retain(|(k, _)| *k != settings.peer_public_key);
        self.wireguard
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .peers
            .push((settings.peer_public_key.clone(), None));
        Ok(())
    }

    async fn remove_wireguard_peer(&self, name: &str, public_key: &str) -> Result<()> {
        if let Some(state) = self.wireguard.lock().unwrap().get_mut(name) {
            state.peers.retain(|(k, _)| k != public_key);
        }
        Ok(())
    }

    async fn wireguard_state(&self, name: &str) -> Result<Option<WgObserved>> {
        Ok(self.wireguard.lock().unwrap().get(name).cloned())
    }

    async fn sysctl(&self, key: &str) -> Result<Option<String>> {
        if self.missing.iter().any(|m| m == key) {
            return Ok(None);
        }
        Ok(self.sysctl_value(key))
    }

    async fn set_sysctl(&self, key: &str, value: &str) -> Result<()> {
        self.sysctls
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
}

fn desired() -> DesiredDataPlane {
    DesiredDataPlane {
        tunnel: DesiredTunnel {
            address4: Some("10.66.0.2/32".to_string()),
            address6: Some("fd00:66::2/128".to_string()),
            gateway4: Some("10.66.0.1".to_string()),
            gateway6: Some("fd00:66::1".to_string()),
            server_public_key: hex::encode([0xab; 32]),
            endpoint: "rs1.example:51820".to_string(),
            keepalive: Some(25),
            mtu: 1420,
        },
        gateways: vec!["203.0.113.1".to_string()],
        guests: vec![DesiredGuest {
            address: "203.0.113.5/32".to_string(),
            gateway: "203.0.113.1".to_string(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
        }],
    }
}

fn key() -> NodeKey {
    let dir = tempfile::tempdir().unwrap();
    wgkey::load_or_generate(dir.path()).unwrap()
}

fn cidr(value: &str) -> IpNetwork {
    value.parse().unwrap()
}

/// A machine with nothing configured must end up with the whole data plane.
/// Any one part missing is a customer with no network.
#[tokio::test]
async fn a_bare_machine_gets_the_whole_data_plane() {
    let kernel = FakeKernel::new();
    let changed = apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    assert!(!changed.is_empty());

    assert_eq!(
        kernel.addresses_of(TUNNEL_INTERFACE),
        vec![cidr("10.66.0.2/32"), cidr("fd00:66::2/128")]
    );
    assert_eq!(
        kernel.link_state(TUNNEL_INTERFACE).await.unwrap(),
        (true, Some(1420))
    );
    // The bridge carries the same payload, so it takes the same MTU: a guest
    // sending 1500 bytes into a 1420-byte tunnel opens a connection and then
    // hangs on the first large transfer.
    assert_eq!(
        kernel.link_state(GUEST_BRIDGE).await.unwrap(),
        (true, Some(1420))
    );

    // Everything goes up the tunnel: the guests use LNVPS addresses, so no
    // traffic of theirs belongs anywhere else.
    let settings = kernel.wg_settings().unwrap();
    assert_eq!(settings.allowed_ips, vec![cidr("0.0.0.0/0"), cidr("::/0")]);
    assert_eq!(settings.keepalive, Some(25));
    assert_eq!(settings.endpoint, "rs1.example:51820");

    let mut tunnel_routes = kernel.routes_of(TUNNEL_INTERFACE);
    tunnel_routes.sort();
    assert_eq!(tunnel_routes, vec![cidr("0.0.0.0/0"), cidr("::/0")]);

    // The gateway belongs to the range, not the node, and is held as a host
    // address so the node answers for it without claiming the rest of the
    // range is local.
    assert_eq!(
        kernel.addresses_of(GUEST_BRIDGE),
        vec![cidr("203.0.113.1/32")]
    );
    assert_eq!(kernel.routes_of(GUEST_BRIDGE), vec![cidr("203.0.113.5/32")]);

    // The guest thinks its neighbours are on-link and will ARP for them; proxy
    // ARP is what lets the node answer and pull that traffic up the tunnel.
    assert_eq!(
        kernel.sysctl_value(&format!("net/ipv4/conf/{GUEST_BRIDGE}/proxy_arp")),
        Some("1".to_string())
    );
    assert_eq!(
        kernel.sysctl_value(&format!("net/ipv6/conf/{GUEST_BRIDGE}/proxy_ndp")),
        Some("1".to_string())
    );
    assert_eq!(
        kernel.sysctl_value("net/ipv4/ip_forward"),
        Some("1".to_string())
    );
    assert_eq!(
        kernel.sysctl_value("net/ipv6/conf/all/forwarding"),
        Some("1".to_string())
    );
}

/// A machine that is already right must be left alone. This runs every minute
/// on hardware LNVPS does not own; churn there is a tunnel that flaps.
#[tokio::test]
async fn a_correct_machine_is_not_touched_again() {
    let kernel = FakeKernel::new();
    apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();

    let changed = apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    // Configuring WireGuard is stated unconditionally — the kernel API takes
    // the whole interface and there is nothing to compare a private key
    // against — but nothing else may move.
    assert_eq!(changed, vec![format!("configured {TUNNEL_INTERFACE}")]);
    assert_eq!(kernel.addresses_of(TUNNEL_INTERFACE).len(), 2);
    assert_eq!(kernel.routes_of(GUEST_BRIDGE), vec![cidr("203.0.113.5/32")]);
}

/// A peer that is not the route server has no business on this interface —
/// most likely a stale key from a re-key, still able to send traffic the node
/// would treat as LNVPS's.
#[tokio::test]
async fn a_stale_peer_is_removed() {
    let kernel = FakeKernel::new();
    kernel.create_wireguard(TUNNEL_INTERFACE).await.unwrap();
    kernel
        .wireguard
        .lock()
        .unwrap()
        .get_mut(TUNNEL_INTERFACE)
        .unwrap()
        .peers
        .push(("c3RyYXk=".to_string(), None));

    let changed = apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    assert!(
        changed
            .iter()
            .any(|c| c.contains("removed stale peer c3RyYXk=")),
        "{changed:?}"
    );
    let peers = kernel
        .wireguard_state(TUNNEL_INTERFACE)
        .await
        .unwrap()
        .unwrap()
        .peers;
    assert_eq!(peers.len(), 1);
}

/// A guest that has been deleted or moved must stop being routed here at once:
/// its address goes back in the pool and may already be somebody else's.
#[tokio::test]
async fn a_departed_guest_stops_being_routed() {
    let kernel = FakeKernel::new();
    apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    kernel
        .add_route(cidr("203.0.113.9/32"), GUEST_BRIDGE)
        .await
        .unwrap();

    let changed = apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    assert!(
        changed
            .iter()
            .any(|c| c.contains("unrouted 203.0.113.9/32")),
        "{changed:?}"
    );
    assert_eq!(kernel.routes_of(GUEST_BRIDGE), vec![cidr("203.0.113.5/32")]);
    // The bridge's own gateway is an address, not a route, so a sweep of
    // departed guests cannot take the bridge's addressing with it.
    assert_eq!(
        kernel.addresses_of(GUEST_BRIDGE),
        vec![cidr("203.0.113.1/32")]
    );
}

/// An address that is no longer ours goes, but the kernel's own link-local
/// address stays: removing it would break the interface, on every refresh.
#[tokio::test]
async fn a_stale_address_goes_and_the_kernels_own_stays() {
    let kernel = FakeKernel::new();
    apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    kernel
        .add_address(TUNNEL_INTERFACE, cidr("10.66.0.9/32"))
        .await
        .unwrap();
    kernel
        .add_address(TUNNEL_INTERFACE, cidr("fe80::1/64"))
        .await
        .unwrap();

    apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    let addresses = kernel.addresses_of(TUNNEL_INTERFACE);
    assert!(!addresses.contains(&cidr("10.66.0.9/32")), "{addresses:?}");
    assert!(addresses.contains(&cidr("fe80::1/64")), "{addresses:?}");
}

/// A single-stack pool must not produce a default route for the family it has
/// no address in: that route black-holes traffic instead of leaving the
/// machine's own routing to handle it.
#[tokio::test]
async fn a_single_stack_tunnel_only_routes_its_own_family() {
    let kernel = FakeKernel::new();
    let mut plane = desired();
    plane.tunnel.address6 = None;
    apply(&kernel, &fw().await, &plane, &key()).await.unwrap();
    assert_eq!(kernel.routes_of(TUNNEL_INTERFACE), vec![cidr("0.0.0.0/0")]);
}

/// A knob this kernel does not have is skipped, not fatal: IPv6 can be compiled
/// out, and a node with no IPv6 guests is still a working node.
#[tokio::test]
async fn a_kernel_without_ipv6_still_configures() {
    let kernel = FakeKernel {
        missing: vec![
            "net/ipv6/conf/all/forwarding".to_string(),
            format!("net/ipv6/conf/{GUEST_BRIDGE}/proxy_ndp"),
        ],
        ..FakeKernel::new()
    };
    apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();
    assert_eq!(
        kernel.sysctl_value("net/ipv4/ip_forward"),
        Some("1".to_string())
    );
}

/// An address LNVPS sent that is not an address is reported against the value:
/// the node has to say which part of the document it could not use.
#[tokio::test]
async fn a_malformed_address_is_reported() {
    let kernel = FakeKernel::new();
    let mut plane = desired();
    plane.tunnel.address4 = Some("not-an-address".to_string());
    let err = apply(&kernel, &fw().await, &plane, &key())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("not-an-address"), "{err:#}");

    let mut plane = desired();
    plane.gateways = vec!["also-not".to_string()];
    let err = apply(&kernel, &fw().await, &plane, &key())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("also-not"), "{err:#}");
}

/// Observation reads the machine rather than remembering what was applied: the
/// point of observing is to catch the case where the two disagree.
#[tokio::test]
async fn observation_reports_what_the_machine_has() {
    let kernel = FakeKernel::new();
    apply(&kernel, &fw().await, &desired(), &key())
        .await
        .unwrap();

    // WireGuard comes up happily with a peer that never answers, so an interface
    // that has never handshaken is configured, not working.
    let state = observe(&kernel, &fw().await).await.unwrap();
    assert!(state.tunnel_up);
    assert_eq!(state.tunnel_mtu, Some(1420));
    assert_eq!(state.last_handshake_secs, None);
    assert!(state.bridge_up);
    assert!(state.forwarding4 && state.forwarding6);
    assert_eq!(state.routed_guests, 1);
    assert!(
        !state.healthy(),
        "a tunnel that never handshook is not healthy"
    );

    // Once the route server has answered, it is.
    kernel
        .wireguard
        .lock()
        .unwrap()
        .get_mut(TUNNEL_INTERFACE)
        .unwrap()
        .peers = vec![("peer".to_string(), Some(12))];
    let state = observe(&kernel, &fw().await).await.unwrap();
    assert_eq!(state.last_handshake_secs, Some(12));
    assert!(state.healthy());
}

/// A machine with nothing configured reports nothing configured rather than
/// failing: "not set up yet" is a state the health gate has to be able to read.
#[tokio::test]
async fn an_unconfigured_machine_observes_cleanly() {
    let kernel = FakeKernel::new();
    // No packet filter either: a machine nobody has configured has not had one
    // installed, and reporting one would be reporting a protection it does not
    // have.
    let state = observe(&kernel, &crate::fw::UnavailableFirewall)
        .await
        .unwrap();
    assert_eq!(state, DataPlaneState::default());
    assert!(!state.healthy());
}

/// `/proc/sys` is read and written as files rather than through the `sysctl`
/// binary: one less program a node must have installed, and a write that either
/// happens or says why.
#[test]
fn kernel_knobs_are_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("net/ipv4")).unwrap();
    std::fs::write(dir.path().join("net/ipv4/ip_forward"), "0\n").unwrap();

    assert_eq!(
        read_sysctl(dir.path(), "net/ipv4/ip_forward").unwrap(),
        Some("0\n".to_string())
    );
    write_sysctl(dir.path(), "net/ipv4/ip_forward", "1").unwrap();
    assert_eq!(
        read_sysctl(dir.path(), "net/ipv4/ip_forward").unwrap(),
        Some("1".to_string())
    );

    // A knob that is not there is a fact about the machine, not a failure.
    assert_eq!(read_sysctl(dir.path(), "net/ipv6/absent").unwrap(), None);
    assert!(write_sysctl(dir.path(), "net/ipv6/absent", "1").is_err());
}
