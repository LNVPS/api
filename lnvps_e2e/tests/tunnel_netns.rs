//! Both ends of a marketplace tunnel, on a real kernel, carrying real packets.
//!
//! Everything below this line has been proved by unit tests that assert what
//! the code *decides*: which commands the route server issues, which netlink
//! operations the node performs. None of that proves a packet moves. This
//! harness builds the two ends out of network namespaces and pings across the
//! tunnel — first the node itself, then a guest sitting behind it, which is the
//! path a customer's traffic actually takes.
//!
//! ```text
//!   [rs netns]                    [test machine's netns]      [lnvps netns]        [guest netns]
//!   wgln<pool>  <══ WireGuard ══>  wgln0 created here, then ═>  wgln0          veth
//!   10.66.0.1/24                   its UDP socket stays here   10.66.0.2/32   br-lnvps ── 203.0.113.5/24
//!        │                                                     203.0.113.1/32
//!    rs_up veth ────────────────── node_up veth
//!    198.51.100.1/24               198.51.100.2/24
//! ```
//!
//! The shape is the production one, including the part that is easy to get
//! wrong: `wgln0` is created in the machine's own namespace so its UDP socket can
//! reach the route server through the operator's uplink, and is then moved into
//! the LNVPS namespace so that everything carried *over* the tunnel is isolated
//! from the operator's network.
//!
//! Requires root (namespaces, veths, WireGuard) so it is `#[ignore]`d; run it
//! with `scripts/tunnel-e2e.sh`.

use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use lnvps_api::router::{Tunnel, TunnelConfig, TunnelRouter, WireguardConfig, WireguardPeer};
use lnvps_node::net::{DesiredDataPlane, DesiredGuest, DesiredTunnel};

/// Underlay: the "internet" between the two machines.
const RS_UNDERLAY: &str = "198.51.100.1/24";
const NODE_UNDERLAY: &str = "198.51.100.2/24";
/// Inner tunnel addresses, as the allocator hands them out.
const RS_INNER: &str = "10.66.0.1/24";
const NODE_INNER: &str = "10.66.0.2/32";
/// A customer address, as LNVPS assigns it to a guest on this node.
const GUEST_ADDRESS: &str = "203.0.113.5";
/// The guest's MAC, which the filter binds its address to. LNVPS knows it
/// because LNVPS assigned it when the VM was created.
const GUEST_MAC: &str = "52:54:00:e2:e0:05";
/// An address nobody assigned this guest, used to prove the filter drops it.
const SPOOFED_ADDRESS: &str = "203.0.113.99";
const GUEST_GATEWAY: &str = "203.0.113.1";

/// Namespaces, torn down on drop even when a test panics.
struct Topology {
    rs: String,
    guest: String,
    /// The node's data plane namespace, pinned where iproute2 looks so an
    /// operator — and this harness — can reach it with `ip netns exec`.
    dataplane: String,
}

impl Topology {
    fn new(tag: &str) -> Result<Self> {
        let topology = Self {
            rs: format!("lnvps-e2e-rs-{tag}"),
            guest: format!("lnvps-e2e-guest-{tag}"),
            dataplane: format!("lnvps-e2e-dp-{tag}"),
        };
        topology.teardown();

        run("ip", &["netns", "add", &topology.rs])?;
        run("ip", &["netns", "add", &topology.guest])?;

        // The underlay: the route server and the node's machine, reachable to
        // each other and to nothing else.
        run(
            "ip",
            &[
                "link", "add", "e2e-rs", "type", "veth", "peer", "name", "e2e-node",
            ],
        )?;
        run("ip", &["link", "set", "e2e-rs", "netns", &topology.rs])?;
        topology.in_rs(&["ip", "addr", "add", RS_UNDERLAY, "dev", "e2e-rs"])?;
        topology.in_rs(&["ip", "link", "set", "e2e-rs", "up"])?;
        topology.in_rs(&["ip", "link", "set", "lo", "up"])?;
        run("ip", &["addr", "add", NODE_UNDERLAY, "dev", "e2e-node"])?;
        run("ip", &["link", "set", "e2e-node", "up"])?;

        Ok(topology)
    }

    fn in_rs(&self, argv: &[&str]) -> Result<String> {
        let mut full = vec!["netns", "exec", &self.rs];
        full.extend_from_slice(argv);
        run("ip", &full)
    }

    fn in_guest(&self, argv: &[&str]) -> Result<String> {
        let mut full = vec!["netns", "exec", &self.guest];
        full.extend_from_slice(argv);
        run("ip", &full)
    }

    /// Run commands in the node's *data plane* namespace, which the production
    /// code created and pinned.
    fn in_dataplane(&self, argv: &[&str]) -> Result<String> {
        let mut full = vec!["netns", "exec", &self.dataplane];
        full.extend_from_slice(argv);
        run("ip", &full)
    }

    /// The namespace the node's code builds, as production code would.
    fn open_dataplane(&self) -> Result<lnvps_node::netns::Handle> {
        lnvps_node::netns::ensure(std::path::Path::new("/run/netns"), &self.dataplane)
    }

    fn teardown(&self) {
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.rs])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.guest])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.dataplane])
            .output();
        // Anything the node's code created in the machine's namespace, which
        // is where a half-finished run leaves it.
        for link in ["e2e-node", "e2e-guest", "wgln0", "wg0", "br-lnvps"] {
            let _ = Command::new("ip").args(["link", "del", link]).output();
        }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    if !out.status.success() {
        bail!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// A route server whose commands run inside a namespace instead of over SSH.
///
/// The commands, and every decision behind them, are the ones a real route
/// server is given; only the transport changes.
fn route_server(namespace: &str) -> lnvps_api::router::LinuxSshRouter {
    let namespace = namespace.to_string();
    lnvps_api::router::LinuxSshRouter::with_exec(Arc::new(move |cmd: &str| {
        let out = Command::new("ip")
            .args(["netns", "exec", &namespace, "sh", "-c", cmd])
            .output()
            .map_err(|e| lnvps_api_common::retry::OpError::Fatal(e.into()))?;
        if !out.status.success() {
            return Err(lnvps_api_common::retry::OpError::Fatal(anyhow::anyhow!(
                "`{cmd}` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }))
}

/// Skip rather than fail when the machine cannot run this at all: a developer's
/// laptop without root should not report a red test it was never able to run.
fn requirements_met() -> bool {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping: needs root for network namespaces and WireGuard");
        return false;
    }
    if run("modprobe", &["wireguard"]).is_err()
        && !std::path::Path::new("/sys/module/wireguard").exists()
    {
        eprintln!("skipping: no WireGuard support in this kernel");
        return false;
    }
    true
}

/// The whole path: LNVPS's route server, the node's daemon code, and a guest
/// behind it — with packets crossing all of it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn a_guest_behind_a_node_is_reachable_from_the_route_server() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    let topology = Topology::new("guest")?;

    // ---- the node generates its own key; LNVPS never sees the private half
    let state_dir = tempfile::tempdir()?;
    let node_key = lnvps_node::wgkey::load_or_generate(state_dir.path())?;

    // ---- the route server's own interface, configured by production code
    let server_key = lnvps_api_common::generate_wireguard_keypair()?;
    let rs = route_server(&topology.rs);
    let interface = "wgln1";
    rs.add_tunnel(&Tunnel {
        id: None,
        name: interface.to_string(),
        local_addr: None,
        remote_addr: None,
        enabled: true,
        config: TunnelConfig::Wireguard(WireguardConfig {
            listen_port: Some(51820),
            private_key: Some(server_key.private_key.clone()),
            public_key: Some(lnvps_api_common::wireguard_key_to_base64(
                &server_key.public_key,
            )),
            peers: vec![],
        }),
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // The pool's address, and the peer as the reconciler builds it: the node's
    // own address plus exactly the guest addresses LNVPS assigned to it, which
    // is the anti-spoof boundary.
    rs.sync_tunnel_addresses(interface, &[RS_INNER.to_string()])
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    rs.set_tunnel_peer(
        interface,
        &WireguardPeer {
            public_key: node_key.public_base64(),
            endpoint: None,
            allowed_ips: vec![NODE_INNER.to_string(), format!("{GUEST_ADDRESS}/32")],
            persistent_keepalive: None,
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    // The pool's block *and* the guest address: an address on a
    // point-to-point interface does not route the rest of its prefix, so
    // without the block the route server cannot reach any node in the pool.
    rs.sync_tunnel_routes(
        interface,
        &["10.66.0.0/24".to_string(), format!("{GUEST_ADDRESS}/32")],
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // ---- the node applies the document LNVPS would have sent it
    let kernel = lnvps_node::net::Kernel::in_namespace(topology.open_dataplane()?)?;
    let desired = DesiredDataPlane {
        tunnel: DesiredTunnel {
            address4: Some(NODE_INNER.to_string()),
            address6: None,
            gateway4: Some("10.66.0.1".to_string()),
            gateway6: None,
            server_public_key: hex::encode(&server_key.public_key),
            endpoint: "198.51.100.1:51820".to_string(),
            keepalive: Some(25),
            mtu: 1420,
        },
        gateways: vec![GUEST_GATEWAY.to_string()],
        guests: vec![DesiredGuest {
            address: format!("{GUEST_ADDRESS}/32"),
            gateway: GUEST_GATEWAY.to_string(),
            mac: Some(GUEST_MAC.to_string()),
        }],
    };
    let firewall = lnvps_node::fw::SystemFirewall::new(topology.open_dataplane()?);
    lnvps_node::net::apply(&kernel, &firewall, &desired, &node_key).await?;

    // ---- a guest on the node's bridge, addressed as a customer's VM is
    run(
        "ip",
        &[
            "link",
            "add",
            "e2e-guest",
            "type",
            "veth",
            "peer",
            "name",
            "e2e-tap",
        ],
    )?;
    run(
        "ip",
        &["link", "set", "e2e-tap", "netns", &topology.dataplane],
    )?;
    topology.in_dataplane(&["ip", "link", "set", "e2e-tap", "master", "br-lnvps"])?;
    topology.in_dataplane(&["ip", "link", "set", "e2e-tap", "up"])?;
    run(
        "ip",
        &["link", "set", "e2e-guest", "netns", &topology.guest],
    )?;
    topology.in_guest(&["ip", "link", "set", "e2e-guest", "address", GUEST_MAC])?;
    topology.in_guest(&[
        "ip",
        "addr",
        "add",
        &format!("{GUEST_ADDRESS}/24"),
        "dev",
        "e2e-guest",
    ])?;
    // A second address the guest simply gave itself. Nothing stops a customer
    // doing this — root in their own VM is the whole product — so the filter is
    // what has to stop the packets.
    topology.in_guest(&[
        "ip",
        "addr",
        "add",
        &format!("{SPOOFED_ADDRESS}/24"),
        "dev",
        "e2e-guest",
    ])?;
    topology.in_guest(&["ip", "link", "set", "e2e-guest", "up"])?;
    // The guest is configured with its range's gateway and believes it is
    // on-link — which is exactly why the node holds that address and answers
    // for it.
    topology.in_guest(&["ip", "route", "replace", "default", "via", GUEST_GATEWAY])?;

    // ---- the tunnel itself
    let node_inner = NODE_INNER.split('/').next().unwrap();
    topology
        .in_rs(&["ping", "-c", "3", "-W", "5", node_inner])
        .with_context(|| {
            format!(
                "the route server could not reach the node over the tunnel\n\
                 route server:\n{}{}\n\
                 node data plane:\n{}{}",
                topology.in_rs(&["ip", "addr"]).unwrap_or_default(),
                topology.in_rs(&["wg", "show"]).unwrap_or_default(),
                topology.in_dataplane(&["ip", "addr"]).unwrap_or_default(),
                topology.in_dataplane(&["wg", "show"]).unwrap_or_default(),
            )
        })?;

    // ---- and the path a customer's traffic actually takes
    topology
        .in_rs(&["ping", "-c", "3", "-W", "5", GUEST_ADDRESS])
        .context("the route server could not reach a guest behind the node")?;

    // The node reports itself healthy only once that has happened: WireGuard comes
    // up perfectly happily with a peer that never answers.
    let state = lnvps_node::net::observe(&kernel, &firewall).await?;
    assert!(state.tunnel_up, "{state:?}");
    assert!(state.bridge_up, "{state:?}");
    assert!(
        state.last_handshake_secs.is_some(),
        "a tunnel that carried packets reported no handshake: {state:?}"
    );
    assert!(state.healthy(), "{state:?}");

    // ---- and what the filter is for
    //
    // The guest's own address reaches the route server; the address it made up
    // does not. This is the check the route server's AllowedIPs cannot make:
    // both addresses are inside the node's peer, so from the far end a guest
    // stealing its neighbour's address is indistinguishable from the real
    // thing.
    let rs_inner = "10.66.0.1";
    topology
        .in_guest(&["ping", "-c", "2", "-W", "5", "-I", GUEST_ADDRESS, rs_inner])
        .context("a guest could not reach the route server from its own address")?;
    assert!(
        topology
            .in_guest(&[
                "ping",
                "-c",
                "2",
                "-W",
                "3",
                "-I",
                SPOOFED_ADDRESS,
                rs_inner
            ])
            .is_err(),
        "a guest reached the network sourcing an address LNVPS never assigned it:\n{}",
        topology
            .in_dataplane(&["nft", "list", "ruleset"])
            .unwrap_or_default()
    );

    // ...and the filter says which ruleset it is enforcing, read back off the
    // kernel rather than remembered by the daemon.
    let firewall_state = lnvps_node::fw::observe(&firewall).await;
    assert!(firewall_state.available, "{firewall_state:?}");
    assert!(firewall_state.present, "{firewall_state:?}");
    assert!(
        firewall_state.isolated,
        "guests were not isolated from each other at layer 2: {firewall_state:?}"
    );
    assert_eq!(
        firewall_state.ruleset,
        Some(lnvps_node::fw::fingerprint(
            &lnvps_node::fw::Policy::from_desired(&desired)?
        )),
        "the machine is enforcing a different ruleset from the one applied"
    );

    // A second apply changes nothing: this runs every few seconds forever, and
    // a node that reported a change on every poll would make the log useless.
    let again = lnvps_node::net::apply(&kernel, &firewall, &desired, &node_key).await?;
    assert!(
        !again.iter().any(|c| c.contains("nft")),
        "the filter was reloaded when nothing had changed: {again:?}"
    );
    Ok(())
}

/// The isolation the namespace exists for: the operator's own network is not
/// reachable from inside the data plane, and their default route is untouched.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn the_operators_machine_keeps_its_own_network() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    let topology = Topology::new("isolation")?;
    let state_dir = tempfile::tempdir()?;
    let node_key = lnvps_node::wgkey::load_or_generate(state_dir.path())?;
    let server_key = lnvps_api_common::generate_wireguard_keypair()?;

    let default_before = run("ip", &["-j", "route", "show", "default"])?;

    // The operator's own WireGuard interface, which is why the node's is not
    // called `wg0`: the node creates its interface in *this* namespace before
    // moving it, so a collision here would either fail outright or, worse,
    // adopt somebody's VPN and move it out from under them.
    run("ip", &["link", "add", "wg0", "type", "wireguard"])?;

    let kernel = lnvps_node::net::Kernel::in_namespace(topology.open_dataplane()?)?;
    let firewall = lnvps_node::fw::SystemFirewall::new(topology.open_dataplane()?);
    lnvps_node::net::apply(
        &kernel,
        &firewall,
        &DesiredDataPlane {
            tunnel: DesiredTunnel {
                address4: Some(NODE_INNER.to_string()),
                address6: None,
                gateway4: Some("10.66.0.1".to_string()),
                gateway6: None,
                server_public_key: hex::encode(&server_key.public_key),
                endpoint: "198.51.100.1:51820".to_string(),
                keepalive: Some(25),
                mtu: 1420,
            },
            gateways: vec![GUEST_GATEWAY.to_string()],
            guests: vec![],
        },
        &node_key,
    )
    .await?;

    // The operator's interface is still theirs, still where they left it.
    assert!(
        run("ip", &["link", "show", "wg0"]).is_ok(),
        "the operator's own wg0 was taken or destroyed"
    );

    // The interfaces exist in the namespace and nowhere else. Asserted first,
    // because if this is wrong every later assertion is wrong for the same
    // reason and this is the one that says why.
    assert!(
        run("ip", &["link", "show", "wgln0"]).is_err(),
        "the node's interface is still in the machine's namespace: {}",
        run("ip", &["link", "show"]).unwrap_or_default()
    );
    assert!(
        topology
            .in_dataplane(&["ip", "link", "show", "wgln0"])
            .is_ok()
    );
    assert!(run("ip", &["link", "show", "br-lnvps"]).is_err());

    // The default route the node installed is the data plane's, not the
    // machine's: taking an operator's default route would send their own
    // traffic up a tunnel they do not own.
    assert_eq!(
        default_before,
        run("ip", &["-j", "route", "show", "default"])?,
        "the machine's default route changed"
    );

    // Forwarding is enabled in the namespace only. On a machine that is also
    // the operator's workstation, turning it on globally is not ours to do.
    let inside = topology.in_dataplane(&["cat", "/proc/sys/net/ipv4/ip_forward"]);
    assert_eq!(inside.unwrap_or_default().trim(), "1");

    assert!(
        topology
            .in_dataplane(&["ip", "link", "show", "e2e-node"])
            .is_err(),
        "the operator's uplink is reachable from inside the data plane"
    );
    Ok(())
}

/// LNVPS and the node hold the bridge name as a constant each. They are not
/// sent to each other precisely so they cannot disagree at runtime — which only
/// works if they agree at build time, and this is where both are in scope.
#[test]
fn both_ends_agree_on_the_bridge() {
    assert_eq!(
        lnvps_api::provisioner::NODE_BRIDGE,
        lnvps_node::net::GUEST_BRIDGE
    );
}
