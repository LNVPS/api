//! One device, two regions, one address, on a real kernel.
//!
//! This is the property the whole VPN design exists to have, and the one thing
//! no unit test can prove: a customer's device holds **one keypair and one
//! inner address that work in every region**, so switching region is a
//! client-side choice of which endpoint to dial and nothing on the server side
//! moves.
//!
//! ```text
//!            [region ams netns]                    [region sto netns]
//!              wgln<poolA>                           wgln<poolB>
//!              10.64.0.1/24  <══ WireGuard ══╗ ╔══> 10.64.0.1/24
//!              fd00:64::1/64                 ║ ║    fd00:64::1/64
//!                   │                        ║ ║          │
//!               ams veth ───── underlay ─────╨─╨───── sto veth
//!                                  │
//!                            [device netns]
//!                                wg0
//!                          10.64.0.7/32, one key
//! ```
//!
//! Both route servers hold the *same* inner address, because both interfaces
//! are addressed from the service's one block. In production they are different
//! machines and never meet; here they are different namespaces, which is the
//! same isolation.
//!
//! The interfaces are built by [`lnvps_vpn::apply`], the real daemon code, from
//! a document shaped like the one LNVPS publishes. Only the transport is
//! different: the document is constructed here instead of fetched.
//!
//! Requires root (namespaces, veths, WireGuard) so it is `#[ignore]`d; run it
//! with `scripts/tunnel-e2e.sh`.

use anyhow::{Context, Result};
use lnvps_e2e::stack::{ip, run};
use lnvps_netlink::{Kernel, NetOps};
use lnvps_vpn::apply::apply;
use lnvps_vpn::client::{DesiredDataPlane, DesiredInterface, DesiredPeer};

const PREFIX: &str = "lnvpn";

/// The device's one address, in both regions at once.
const DEVICE_V4: &str = "10.64.0.7";
const DEVICE_V6: &str = "fd00:64::7";
/// What each route server answers on. The same in both, deliberately.
const SERVER_V4: &str = "10.64.0.1";
const SERVER_V6: &str = "fd00:64::1";

/// Keys, fixed so a failure is reproducible. Generated with
/// `wg genkey | tee /dev/stderr | wg pubkey`.
const AMS_PRIVATE: &str = "iM7g0lLIF3P7WGZTF8Zgs+A2ZUGZQIS+eEIVN8U9RVo=";
const STO_PRIVATE: &str = "cGDwsizrOfNSDBBaHkjbNCMDVZ7WlrxaS4tQ9AK2n2Q=";
const DEVICE_PRIVATE: &str = "0OSNaTBiNAnkkVYQDs8Y+Yq9GFMBDrLPQ3TgRAqzIm0=";

struct Regions {
    names: Vec<String>,
    device_ns: String,
}

impl Regions {
    fn new() -> Self {
        Self {
            names: vec![format!("{PREFIX}-ams"), format!("{PREFIX}-sto")],
            device_ns: format!("{PREFIX}-dev"),
        }
    }

    fn all(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.names.iter().map(String::as_str).collect();
        v.push(&self.device_ns);
        v
    }

    /// Build the underlay: each region and the device on one segment, so the
    /// outer UDP can flow. Nothing about the tunnels yet.
    fn build(&self) -> Result<()> {
        self.teardown();
        for ns in self.all() {
            ip(&["netns", "add", ns])?;
            self.exec(ns, &["ip", "link", "set", "lo", "up"])?;
        }

        // A bridge in the machine's own namespace joining all three, standing
        // in for the internet between a customer and an exit.
        ip(&["link", "add", &self.bridge(), "type", "bridge"])?;
        ip(&["link", "set", &self.bridge(), "up"])?;

        for (n, ns) in self.all().iter().enumerate() {
            let (outer, inner) = (format!("{PREFIX}{n}o"), format!("{PREFIX}{n}i"));
            ip(&[
                "link", "add", &outer, "type", "veth", "peer", "name", &inner,
            ])?;
            ip(&["link", "set", &outer, "master", &self.bridge()])?;
            ip(&["link", "set", &outer, "up"])?;
            ip(&["link", "set", &inner, "netns", ns])?;
            self.exec(
                ns,
                &[
                    "ip",
                    "addr",
                    "add",
                    &format!("198.51.100.{}/24", n + 1),
                    "dev",
                    &inner,
                ],
            )?;
            self.exec(ns, &["ip", "link", "set", &inner, "up"])?;
        }
        Ok(())
    }

    fn bridge(&self) -> String {
        format!("{PREFIX}br")
    }

    fn underlay(&self, index: usize) -> String {
        format!("198.51.100.{}", index + 1)
    }

    /// `ip netns exec <ns> <program> <args...>`
    fn exec(&self, ns: &str, argv: &[&str]) -> Result<String> {
        let mut cmd = vec!["netns", "exec", ns];
        cmd.extend_from_slice(argv);
        ip(&cmd)
    }

    /// Remove everything this harness owns, ignoring what was never created.
    ///
    /// The veths matter as much as the namespaces: deleting a namespace takes
    /// the inner half with it, but a run that failed before the move left the
    /// outer half in the machine's own namespace, and the next run then died on
    /// "File exists" rather than on whatever it was actually testing.
    fn teardown(&self) {
        for ns in self.all() {
            let _ = std::process::Command::new("ip")
                .args(["netns", "delete", ns])
                .output();
        }
        let mut links = vec![self.bridge()];
        for n in 0..self.all().len() {
            links.push(format!("{PREFIX}{n}o"));
            links.push(format!("{PREFIX}{n}i"));
        }
        for link in links {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", &link])
                .output();
        }
    }
}

impl Drop for Regions {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Skip rather than fail when the machine cannot run this at all: a laptop
/// without root should not report a red test it was never able to run.
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

/// The document LNVPS would publish for one region.
fn a_region_document(pool_id: u64, private_key: &str, port: u16) -> DesiredDataPlane {
    DesiredDataPlane {
        generation: 1,
        interfaces: vec![DesiredInterface {
            pool_id,
            private_key: private_key.to_string(),
            listen_port: port,
            mtu: 1420,
            // The route server's own side of the block. The same in both
            // regions, which is what lets the device keep one address.
            addresses: vec![format!("{SERVER_V4}/24"), format!("{SERVER_V6}/64")],
            routes: vec![],
            peers: vec![DesiredPeer {
                public_key: public_of(DEVICE_PRIVATE),
                // Exactly the addresses this key may use. A device is a single
                // address, not a prefix.
                allowed_ips: vec![format!("{DEVICE_V4}/32"), format!("{DEVICE_V6}/128")],
                endpoint: None,
                persistent_keepalive: None,
            }],
        }],
    }
}

fn public_of(private: &str) -> String {
    lnvps_netlink::wireguard_public_key_base64(private).expect("a fixed test key must parse")
}

/// Configure the device end: one interface, one key, one address, and the two
/// regions as peers. This is the client's half, so it is written with `wg` as a
/// customer's `wg-quick` would be, not with the daemon's code.
fn configure_device(regions: &Regions, endpoints: &[(usize, u16)]) -> Result<()> {
    let ns = &regions.device_ns;
    regions.exec(ns, &["ip", "link", "add", "wg0", "type", "wireguard"])?;
    regions.exec(
        ns,
        &[
            "ip",
            "addr",
            "add",
            &format!("{DEVICE_V4}/32"),
            "dev",
            "wg0",
        ],
    )?;
    regions.exec(
        ns,
        &[
            "ip",
            "-6",
            "addr",
            "add",
            &format!("{DEVICE_V6}/128"),
            "dev",
            "wg0",
        ],
    )?;

    let key_file = std::env::temp_dir().join(format!("{PREFIX}-device.key"));
    std::fs::write(&key_file, DEVICE_PRIVATE)?;
    regions.exec(
        ns,
        &[
            "wg",
            "set",
            "wg0",
            "private-key",
            key_file.to_str().unwrap(),
        ],
    )?;

    for &(region_index, port) in endpoints {
        let private = [AMS_PRIVATE, STO_PRIVATE][region_index];
        regions.exec(
            ns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                &public_of(private),
                "endpoint",
                &format!("{}:{port}", regions.underlay(region_index)),
                "allowed-ips",
                // The route server's addresses, reachable through this peer.
                // Two peers cannot both claim the same allowed-ips on one
                // interface, which is exactly why a real client uses one config
                // at a time. Here each is scoped to its own /32 so both can be
                // configured and selected by route.
                &format!("{}/32", server_alias(region_index)),
            ],
        )?;
    }

    regions.exec(ns, &["ip", "link", "set", "wg0", "up"])?;
    for &(region_index, _) in endpoints {
        regions.exec(
            ns,
            &[
                "ip",
                "route",
                "add",
                &format!("{}/32", server_alias(region_index)),
                "dev",
                "wg0",
            ],
        )?;
    }
    std::fs::remove_file(&key_file).ok();
    Ok(())
}

/// A second address on each route server, unique per region, so the device can
/// address them separately over one interface.
///
/// The shared `10.64.0.1` is what a real client dials, one region at a time.
/// Reaching both at once from a single namespace needs them to be told apart,
/// and giving each an extra address changes nothing about the property under
/// test: the *device's* address is still one address in both regions.
fn server_alias(region_index: usize) -> String {
    format!("10.64.0.{}", 200 + region_index)
}

/// Build one region's interface with the daemon's own apply.
///
/// The link is created by the harness rather than by `apply`, and that is not a
/// shortcut. A namespaced [`Kernel`] creates a WireGuard interface in the
/// machine's own namespace and then moves it in, because a marketplace node's
/// outer UDP has to leave by the operator's uplink. `lvd` uses
/// [`Kernel::host()`], where there is no namespace and no move: its interfaces
/// are the machine's. Since the harness fakes two machines with two namespaces,
/// it has to create each link where that machine's would already be. Everything
/// after creation -- key, port, addresses, routes, peers -- is the daemon's.
async fn bring_up_region(
    regions: &Regions,
    ns: &str,
    interface: &str,
    doc: &DesiredDataPlane,
) -> Result<Kernel> {
    regions.exec(ns, &["ip", "link", "add", interface, "type", "wireguard"])?;
    let handle = lnvps_netlink::netns::Handle::open(
        &std::path::Path::new(lnvps_netlink::netns::NETNS_DIR).join(ns),
    )
    .with_context(|| format!("opening namespace {ns}"))?;
    let kernel = Kernel::in_namespace(handle)?;
    apply(&kernel, doc).await?;
    Ok(kernel)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn one_device_reaches_two_regions_on_one_address() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    let regions = Regions::new();
    regions.build()?;

    // Two regions, two interfaces, built by the daemon's own code from the
    // document LNVPS would publish.
    let ams = a_region_document(11, AMS_PRIVATE, 51820);
    let sto = a_region_document(12, STO_PRIVATE, 51821);
    let ams_kernel = bring_up_region(&regions, &regions.names[0], "wgln11", &ams).await?;
    let sto_kernel = bring_up_region(&regions, &regions.names[1], "wgln12", &sto).await?;

    // The per-region address the device uses to tell them apart. See
    // `server_alias`.
    for (n, ns) in regions.names.iter().enumerate() {
        regions.exec(
            ns,
            &[
                "ip",
                "addr",
                "add",
                &format!("{}/32", server_alias(n)),
                "dev",
                &format!("wgln{}", [11, 12][n]),
            ],
        )?;
    }

    configure_device(&regions, &[(0, 51820), (1, 51821)])?;

    // ---- the property: one address, both regions
    for (n, region) in ["ams", "sto"].iter().enumerate() {
        regions
            .exec(
                &regions.device_ns,
                &[
                    "ping",
                    "-c",
                    "3",
                    "-W",
                    "5",
                    "-I",
                    DEVICE_V4,
                    &server_alias(n),
                ],
            )
            .with_context(|| format!("the device could not reach {region} from its one address"))?;
    }

    // ---- and both ends agree it was the same key
    for (kernel, name) in [(&ams_kernel, "wgln11"), (&sto_kernel, "wgln12")] {
        let state = kernel
            .wireguard_state(name)
            .await?
            .with_context(|| format!("{name} should exist"))?;
        assert_eq!(state.peers.len(), 1, "{name} should carry one device");
        assert_eq!(state.peers[0].public_key, public_of(DEVICE_PRIVATE));
        assert!(
            state.peers[0].last_handshake_secs.is_some(),
            "{name} never completed a handshake with the device"
        );
        // The customer's real address, now in kernel memory. This is what the
        // scrub exists to remove.
        assert!(
            state.peers[0].endpoint.is_some(),
            "{name} should have heard from the device"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn a_revoked_device_stops_working_at_once() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    let regions = Regions::new();
    regions.build()?;

    let mut doc = a_region_document(11, AMS_PRIVATE, 51820);
    let kernel = bring_up_region(&regions, &regions.names[0], "wgln11", &doc).await?;
    regions.exec(
        &regions.names[0],
        &[
            "ip",
            "addr",
            "add",
            &format!("{}/32", server_alias(0)),
            "dev",
            "wgln11",
        ],
    )?;
    configure_device(&regions, &[(0, 51820)])?;

    regions.exec(
        &regions.device_ns,
        &[
            "ping",
            "-c",
            "3",
            "-W",
            "5",
            "-I",
            DEVICE_V4,
            &server_alias(0),
        ],
    )?;

    // Revoked: the next document simply does not list it.
    doc.interfaces[0].peers.clear();
    doc.generation = 2;
    apply(&kernel, &doc).await?;

    assert!(
        kernel
            .wireguard_state("wgln11")
            .await?
            .unwrap()
            .peers
            .is_empty(),
        "a revoked key must not still be configured"
    );
    // The failure that matters: a key LNVPS was told to stop honouring, still
    // carrying traffic.
    assert!(
        regions
            .exec(
                &regions.device_ns,
                &[
                    "ping",
                    "-c",
                    "2",
                    "-W",
                    "3",
                    "-I",
                    DEVICE_V4,
                    &server_alias(0)
                ],
            )
            .is_err(),
        "a revoked device could still reach the route server"
    );

    Ok(())
}

/// A route this daemon added, this daemon can remove.
///
/// A VPN interface asks for no routes at all: its devices sit inside the block
/// the interface is addressed from, so the kernel's connected route already
/// carries them. This exercises the path anyway, because `sync_routes` is
/// shared with the marketplace case where the routes are real, and a delete
/// that silently fails would leave traffic going to a peer that is gone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and network namespaces; run with scripts/tunnel-e2e.sh"]
async fn a_route_is_added_and_removed_by_the_daemon() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    let regions = Regions::new();
    regions.build()?;

    let mut doc = a_region_document(11, AMS_PRIVATE, 51820);
    doc.interfaces[0].routes = vec!["192.0.2.0/24".to_string()];
    let kernel = bring_up_region(&regions, &regions.names[0], "wgln11", &doc).await?;
    assert!(
        kernel
            .routes("wgln11")
            .await?
            .contains(&"192.0.2.0/24".parse()?),
        "the route the document asked for is not there"
    );

    doc.interfaces[0].routes.clear();
    doc.generation = 2;
    apply(&kernel, &doc).await?;
    assert!(
        !kernel
            .routes("wgln11")
            .await?
            .contains(&"192.0.2.0/24".parse()?),
        "a route the document no longer asks for is still carrying traffic"
    );

    // And the connected route for the interface's own block is untouched
    // throughout, because it is the kernel's rather than ours.
    assert!(
        kernel
            .routes("wgln11")
            .await?
            .contains(&"10.64.0.0/24".parse()?),
        "the interface lost the connected route for its own block"
    );
    Ok(())
}
