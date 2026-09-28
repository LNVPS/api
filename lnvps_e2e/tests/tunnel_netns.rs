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
//!   <rs inner>                     its UDP socket stays here   <node inner>   <bridge> ── <guest>
//!        │                                                     203.0.113.1/32
//!    rs_up veth ────────────────── node_up veth
//!    <rs underlay>                 <node underlay>
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

use anyhow::{Context, Result};
use lnvps_e2e::stack::{Addrs, Stack, ip, run};
use lnvps_node::net::{DesiredDataPlane, DesiredTunnel};

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

fn attach_guest(stack: &Stack) -> Result<()> {
    run(
        "ip",
        &[
            "link",
            "add",
            &stack.names.guest_peer,
            "type",
            "veth",
            "peer",
            "name",
            &stack.names.guest_veth,
        ],
    )?;
    run(
        "ip",
        &[
            "link",
            "set",
            &stack.names.guest_veth,
            "netns",
            &stack.names.dataplane_ns,
        ],
    )?;
    stack.in_dataplane(&[
        "ip",
        "link",
        "set",
        &stack.names.guest_veth,
        "master",
        &stack.names.bridge,
    ])?;
    stack.in_dataplane(&["ip", "link", "set", &stack.names.guest_veth, "up"])?;
    run(
        "ip",
        &[
            "link",
            "set",
            &stack.names.guest_peer,
            "netns",
            &stack.names.guest_ns,
        ],
    )?;
    stack.in_guest(&[
        "ip",
        "link",
        "set",
        &stack.names.guest_peer,
        "address",
        &stack.addrs.guest_mac,
    ])?;
    stack.in_guest(&[
        "ip",
        "addr",
        "add",
        &format!("{}/24", &stack.addrs.guest),
        "dev",
        &stack.names.guest_peer,
    ])?;
    stack.in_guest(&["ip", "link", "set", &stack.names.guest_peer, "up"])?;
    // The guest is configured with its range's gateway and believes it is
    // on-link — which is exactly why the node holds that address and answers
    // for it.
    stack.in_guest(&[
        "ip",
        "route",
        "replace",
        "default",
        "via",
        &stack.addrs.guest_gateway,
    ])?;

    Ok(())
}

/// The whole path: LNVPS's route server, the node's daemon code, and a guest
/// behind it — with packets crossing all of it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn a_guest_behind_a_node_is_reachable_from_the_route_server() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    let stack = Stack::new("guest", 1)?;

    // ---- both ends, built by production code from one shared description
    let guest_cidr = format!("{}/32", &stack.addrs.guest);
    let dataplane = stack.bring_up(1, std::slice::from_ref(&guest_cidr)).await?;
    let (kernel, firewall) = (&dataplane.kernel, &dataplane.firewall);

    attach_guest(&stack)?;
    // A second address the guest simply gave itself. Nothing stops a customer
    // doing this — root in their own VM is the whole product — so the filter is
    // what has to stop the packets.
    stack.in_guest(&[
        "ip",
        "addr",
        "add",
        &format!("{}/24", &stack.addrs.guest_spoof),
        "dev",
        &stack.names.guest_peer,
    ])?;

    // ---- the tunnel itself
    let node_inner = stack.addrs.node_inner.split('/').next().unwrap();
    stack
        .in_rs(&["ping", "-c", "3", "-W", "5", node_inner])
        .with_context(|| {
            format!(
                "the route server could not reach the node over the tunnel\n\
                 route server:\n{}{}\n\
                 node data plane:\n{}{}",
                stack.in_rs(&["ip", "addr"]).unwrap_or_default(),
                stack.in_rs(&["wg", "show"]).unwrap_or_default(),
                stack.in_dataplane(&["ip", "addr"]).unwrap_or_default(),
                stack.in_dataplane(&["wg", "show"]).unwrap_or_default(),
            )
        })?;

    // ---- and the path a customer's traffic actually takes
    stack
        .in_rs(&["ping", "-c", "3", "-W", "5", &stack.addrs.guest])
        .context("the route server could not reach a guest behind the node")?;

    // The node reports itself healthy only once that has happened: WireGuard comes
    // up perfectly happily with a peer that never answers.
    let state = lnvps_node::net::observe(kernel, firewall).await?;
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
    let rs_inner = Addrs::bare(&stack.addrs.rs_inner);
    stack
        .in_guest(&[
            "ping",
            "-c",
            "2",
            "-W",
            "5",
            "-I",
            &stack.addrs.guest,
            rs_inner,
        ])
        .context("a guest could not reach the route server from its own address")?;
    assert!(
        stack
            .in_guest(&[
                "ping",
                "-c",
                "2",
                "-W",
                "3",
                "-I",
                &stack.addrs.guest_spoof,
                rs_inner
            ])
            .is_err(),
        "a guest reached the network sourcing an address LNVPS never assigned it:\n{}",
        stack
            .in_dataplane(&["nft", "list", "ruleset"])
            .unwrap_or_default()
    );

    // ...and the filter says which ruleset it is enforcing, read back off the
    // kernel rather than remembered by the daemon.
    let firewall_state = lnvps_node::fw::observe(firewall).await;
    assert!(firewall_state.available, "{firewall_state:?}");
    assert!(firewall_state.present, "{firewall_state:?}");
    assert!(
        firewall_state.isolated,
        "guests were not isolated from each other at layer 2: {firewall_state:?}"
    );
    assert_eq!(
        firewall_state.ruleset,
        Some(lnvps_node::fw::fingerprint(
            &lnvps_node::fw::Policy::from_desired(
                &stack.document(&dataplane.server_key, std::slice::from_ref(&guest_cidr))
            )?
        )),
        "the machine is enforcing a different ruleset from the one applied"
    );

    // A second apply changes nothing: this runs every few seconds forever, and
    // a node that reported a change on every poll would make the log useless.
    let again = lnvps_node::net::apply(
        kernel,
        firewall,
        &stack.document(&dataplane.server_key, std::slice::from_ref(&guest_cidr)),
        &dataplane.node_key,
    )
    .await?;
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
    let stack = Stack::new("isolation", 3)?;
    let state_dir = tempfile::tempdir()?;
    let node_key = lnvps_node::wgkey::load_or_generate(state_dir.path())?;
    let server_key = lnvps_api_common::generate_wireguard_keypair()?;

    let default_before = run("ip", &["-j", "route", "show", "default"])?;

    // The operator's own WireGuard interface, which is why the node's is not
    // called `wg0`: the node creates its interface in *this* namespace before
    // moving it, so a collision here would either fail outright or, worse,
    // adopt somebody's VPN and move it out from under them.
    run(
        "ip",
        &["link", "add", &stack.names.operator_wg, "type", "wireguard"],
    )?;

    let kernel = lnvps_node::net::Kernel::in_namespace(stack.open_dataplane()?)?;
    let firewall = lnvps_node::fw::SystemFirewall::new(stack.open_dataplane()?);
    lnvps_node::net::apply(
        &kernel,
        &firewall,
        &DesiredDataPlane {
            libvirt: None,
            tunnel: DesiredTunnel {
                address4: Some(stack.addrs.node_inner.to_string()),
                address6: None,
                gateway4: Some("10.66.0.1".to_string()),
                gateway6: None,
                server_public_key: hex::encode(&server_key.public_key),
                endpoint: stack.addrs.endpoint(),
                keepalive: Some(25),
                mtu: 1420,
            },
            gateways: vec![stack.addrs.guest_gateway.to_string()],
            guests: vec![],
        },
        &node_key,
    )
    .await?;

    // The operator's interface is still theirs, still where they left it.
    assert!(
        run("ip", &["link", "show", &stack.names.operator_wg]).is_ok(),
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
    assert!(stack.in_dataplane(&["ip", "link", "show", "wgln0"]).is_ok());
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
    let inside = stack.in_dataplane(&["cat", "/proc/sys/net/ipv4/ip_forward"]);
    assert_eq!(inside.unwrap_or_default().trim(), "1");

    assert!(
        stack
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

struct OtherNode {
    ns: String,
}

impl OtherNode {
    const WG: &'static str = "wgother";
    const UNDERLAY_RS: &'static str = "192.0.2.1";
    const UNDERLAY: &'static str = "192.0.2.2";

    fn build(
        stack: &Stack,
        index: u8,
        keys: &lnvps_api_common::WireguardKeypair,
        rs_public_key: &str,
        addresses: &[String],
    ) -> Result<Self> {
        let node = Self {
            ns: format!("{}-ot-{index}", lnvps_e2e::stack::PREFIX),
        };
        node.teardown();
        let (rs_end, own_end) = (format!("e2e{index}or"), format!("e2e{index}ot"));
        ip(&["netns", "add", &node.ns])?;
        ip(&[
            "link", "add", &rs_end, "type", "veth", "peer", "name", &own_end,
        ])?;
        ip(&["link", "set", &rs_end, "netns", &stack.names.rs_ns])?;
        ip(&["link", "set", &own_end, "netns", &node.ns])?;
        stack.in_rs(&[
            "ip",
            "addr",
            "add",
            &format!("{}/24", Self::UNDERLAY_RS),
            "dev",
            &rs_end,
        ])?;
        stack.in_rs(&["ip", "link", "set", &rs_end, "up"])?;
        node.exec(&[
            "ip",
            "addr",
            "add",
            &format!("{}/24", Self::UNDERLAY),
            "dev",
            &own_end,
        ])?;
        node.exec(&["ip", "link", "set", &own_end, "up"])?;
        node.exec(&["ip", "link", "set", "lo", "up"])?;

        let key_file = tempfile::NamedTempFile::new()?;
        std::fs::write(key_file.path(), &keys.private_key)?;
        node.exec(&["ip", "link", "add", Self::WG, "type", "wireguard"])?;
        node.exec(&[
            "wg",
            "set",
            Self::WG,
            "private-key",
            &key_file.path().to_string_lossy(),
            "peer",
            rs_public_key,
            "endpoint",
            &format!("{}:{}", Self::UNDERLAY_RS, stack.addrs.listen_port),
            "allowed-ips",
            "0.0.0.0/0",
            "persistent-keepalive",
            "1",
        ])?;
        for address in addresses {
            node.exec(&["ip", "addr", "add", address, "dev", Self::WG])?;
        }
        node.exec(&["ip", "link", "set", Self::WG, "mtu", "1420", "up"])?;
        node.exec(&["ip", "route", "add", "default", "dev", Self::WG])?;
        Ok(node)
    }

    fn exec(&self, argv: &[&str]) -> Result<String> {
        let mut full = vec!["netns", "exec", self.ns.as_str()];
        full.extend_from_slice(argv);
        ip(&full)
    }

    fn ping(&self, from: &str, to: &str) -> Result<String> {
        self.exec(&["ping", "-c", "2", "-W", "3", "-I", from, to])
    }

    fn teardown(&self) {
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.ns])
            .output();
    }
}

impl Drop for OtherNode {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn another_node_cannot_reach_a_node_through_the_route_server() -> Result<()> {
    use lnvps_api::router::{TunnelRouter, WireguardPeer};

    if !requirements_met() {
        return Ok(());
    }
    let index = 4;
    let stack = Stack::new("hairpin", index)?;
    let guest_cidr = format!("{}/32", &stack.addrs.guest);
    let dataplane = stack
        .bring_up(index, std::slice::from_ref(&guest_cidr))
        .await?;
    attach_guest(&stack)?;
    stack.in_rs(&["sysctl", "-qw", "net.ipv4.ip_forward=1"])?;

    let other_inner = format!("10.66.{index}.3");
    let other_guest = format!("203.0.{index}.77");
    let other_keys = lnvps_api_common::generate_wireguard_keypair()?;
    let rs = stack.route_server();
    rs.set_tunnel_peer(
        &dataplane.rs_interface,
        &WireguardPeer {
            public_key: lnvps_api_common::wireguard_key_to_base64(&other_keys.public_key),
            endpoint: None,
            allowed_ips: vec![format!("{other_inner}/32"), format!("{other_guest}/32")],
            persistent_keepalive: None,
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    rs.sync_tunnel_routes(
        &dataplane.rs_interface,
        &[
            stack.addrs.pool_block.clone(),
            guest_cidr.clone(),
            format!("{other_guest}/32"),
        ],
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let other = OtherNode::build(
        &stack,
        index,
        &other_keys,
        &lnvps_api_common::wireguard_key_to_base64(&dataplane.server_key.public_key),
        &[format!("{other_inner}/32"), format!("{other_guest}/32")],
    )?;

    let node_inner = Addrs::bare(&stack.addrs.node_inner);
    other.ping(&other_inner, node_inner).with_context(|| {
        format!(
            "the hairpin this test closes was not open to begin with\n{}\n{}\n{}\n{}\n{}",
            stack.in_rs(&["wg", "show"]).unwrap_or_default(),
            stack.in_rs(&["ip", "route"]).unwrap_or_default(),
            other.exec(&["wg", "show"]).unwrap_or_default(),
            stack
                .in_dataplane(&["nft", "list", "ruleset"])
                .unwrap_or_default(),
            stack
                .in_rs(&["sysctl", "net.ipv4.ip_forward"])
                .unwrap_or_default(),
        )
    })?;

    rs.sync_peer_isolation(&[
        stack.addrs.pool_block.clone(),
        stack.addrs.pool_block6.clone(),
    ])
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    assert!(
        other.ping(&other_inner, node_inner).is_err(),
        "another node reached this node's inner address through the route server:\n{}",
        stack.in_rs(&["nft", "list", "ruleset"]).unwrap_or_default()
    );
    let ruleset = stack.in_rs(&["nft", "list", "table", "inet", "lnvps_isolation"])?;
    let v4_drop = ruleset
        .lines()
        .find(|l| l.contains("@peers4"))
        .unwrap_or_default();
    assert!(
        v4_drop.contains("counter packets") && !v4_drop.contains("counter packets 0 "),
        "nothing was counted, so the drop was not ours:\n{ruleset}"
    );

    other
        .ping(&other_guest, &stack.addrs.guest)
        .context("guest-to-guest traffic between nodes was blocked as well")?;
    stack
        .in_rs(&["ping", "-c", "2", "-W", "3", node_inner])
        .context("the route server itself lost the node")?;
    Ok(())
}
