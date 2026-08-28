//! A whole marketplace node, on a real kernel, built and torn down per test.
//!
//! Every name and address here is *derived*, not written down. That is the
//! point of the module rather than a tidiness exercise: a harness full of
//! literals can only ever run one stack at a time, so tests serialise, a
//! crashed run leaves debris the next one trips over, and two tests that both
//! want "the node" quietly fight over the same interfaces. Deriving everything
//! from one tag and one index means a stack is disposable, several can exist at
//! once, and teardown can be exhaustive because it knows exactly what it made.
//!
//! It also removes a whole class of harness bug. When the address in a test and
//! the address in the fixture are two constants, they can disagree, and what
//! that looks like is a failing assertion about the *production* code.
//!
//! ```text
//!   [rs netns]                  [machine netns]        [dataplane netns]     [guest netns]
//!   wgln<pool> <══ WireGuard ══> wgln0 made here,  ═══> wgln0            veth
//!   <rs inner>                   socket stays here      <node inner>     <bridge> ── <guest>
//!        │                                              answers <gateway>
//!   veth ──────────── underlay ──────────── veth
//! ```

use std::process::Command;

use anyhow::{Context, Result, bail};

/// Prefix for everything this harness creates, so a stray namespace or link is
/// obviously ours and can be swept without guessing.
pub const PREFIX: &str = "lnvps-e2e";

/// The names one stack owns.
///
/// Namespaces are named after the tag, because a human reading `ip netns list`
/// during a failure wants to know which test left them. Interfaces are named
/// after the *index*, because the kernel caps an interface name at 15 bytes and
/// `ip` refuses a longer one outright — a descriptive name is worth nothing if
/// the link cannot be created.
#[derive(Debug, Clone)]
pub struct Names {
    pub rs_ns: String,
    pub guest_ns: String,
    /// The data plane namespace, pinned where iproute2 looks so `ip netns exec`
    /// reaches it — the node's code creates this one, not the harness.
    pub dataplane_ns: String,
    pub rs_veth: String,
    pub node_veth: String,
    pub guest_veth: String,
    /// The guest's end of that pair, which lives in the guest's namespace.
    pub guest_peer: String,
    pub bridge: String,
    /// A WireGuard interface the *operator* owns, which the node must leave
    /// alone. Named `wg0` because that is what the node's own interface used to
    /// be called: an operator with the obvious name for their own tunnel is the
    /// case that made production rename its one to `wgln0`.
    pub operator_wg: String,
}

/// The most an interface name can be, enforced rather than hoped for.
const IFNAME_MAX: usize = 15;

impl Names {
    pub fn new(tag: &str, index: u8) -> Self {
        let names = Self {
            rs_ns: format!("{PREFIX}-rs-{tag}"),
            guest_ns: format!("{PREFIX}-gu-{tag}"),
            dataplane_ns: format!("{PREFIX}-dp-{tag}"),
            rs_veth: format!("e2e{index}rs"),
            node_veth: format!("e2e{index}nd"),
            guest_veth: format!("e2e{index}gu"),
            guest_peer: format!("e2e{index}gp"),
            operator_wg: "wg0".to_string(),
            // The bridge is the node's, and its name is production's decision.
            bridge: lnvps_node::net::GUEST_BRIDGE.to_string(),
        };

        for name in names.interfaces() {
            assert!(
                name.len() <= IFNAME_MAX,
                "{name} is {} bytes; the kernel refuses more than {IFNAME_MAX}",
                name.len()
            );
        }
        names
    }

    /// Every interface this stack may create, which is also what teardown
    /// sweeps — one list, so a link added here cannot be forgotten there.
    pub fn interfaces(&self) -> Vec<&str> {
        vec![
            self.rs_veth.as_str(),
            self.node_veth.as_str(),
            self.guest_veth.as_str(),
            self.guest_peer.as_str(),
            self.bridge.as_str(),
            self.operator_wg.as_str(),
            lnvps_node::net::TUNNEL_INTERFACE,
        ]
    }
}

/// The addresses one stack uses, all derived from its index.
///
/// Index `n` gets its own underlay, tunnel block and customer range, so two
/// stacks on one machine cannot route into each other — which would otherwise
/// show up as a test that passes because *the other* stack answered.
#[derive(Debug, Clone)]
pub struct Addrs {
    pub rs_underlay: String,
    pub node_underlay: String,
    /// The pool's block, which the route server must route explicitly: an
    /// address on a point-to-point interface does not route the rest of its
    /// prefix, so holding `.1/24` answers for nothing else in the block.
    pub pool_block: String,
    /// The pool's v6 block, which probe addresses come out of.
    pub pool_block6: String,
    pub rs_inner: String,
    pub node_inner: String,
    pub guest: String,
    pub guest_gateway: String,
    /// An address nobody assigned the guest, for proving the filter drops it.
    pub guest_spoof: String,
    pub guest_mac: String,
    pub listen_port: u16,
}

impl Addrs {
    /// Where the node dials the route server, as LNVPS states it in the
    /// document. Derived from the same fields the route server is configured
    /// with, so the two cannot drift — a harness where they are separate
    /// literals fails as a *production* bug about handshakes that never happen.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", Self::bare(&self.rs_underlay), self.listen_port)
    }
}

impl Addrs {
    pub fn new(index: u8) -> Self {
        // Documentation ranges throughout (RFC 5737, RFC 3849): a harness that
        // ran with real allocations on a machine that happened to route them
        // would be testing somebody else's network.
        Self {
            rs_underlay: format!("198.51.100.{}/24", index * 2 + 1),
            node_underlay: format!("198.51.100.{}/24", index * 2 + 2),
            pool_block: format!("10.66.{index}.0/24"),
            pool_block6: format!("fd00:66:{index}::/64"),
            rs_inner: format!("10.66.{index}.1/24"),
            node_inner: format!("10.66.{index}.2/32"),
            guest: format!("203.0.{index}.5"),
            guest_gateway: format!("203.0.{index}.1"),
            guest_spoof: format!("203.0.{index}.99"),
            guest_mac: format!("52:54:00:e2:e0:{index:02x}"),
            listen_port: 51820 + index as u16,
        }
    }

    /// The address without its prefix, which is what a ping wants.
    pub fn bare(addr: &str) -> &str {
        addr.split('/').next().unwrap_or(addr)
    }
}

/// Namespaces and links for one stack, removed on drop even when a test panics.
///
/// Teardown runs on construction as well: a previous run killed with SIGKILL
/// leaves its namespaces behind, and a harness that fails because of the
/// previous failure hides which one was real.
pub struct Stack {
    pub names: Names,
    pub addrs: Addrs,
}

impl Stack {
    /// Build the underlay: a route server and a node machine that can reach
    /// each other and nothing else.
    pub fn new(tag: &str, index: u8) -> Result<Self> {
        let stack = Self {
            names: Names::new(tag, index),
            addrs: Addrs::new(index),
        };
        stack.teardown();

        ip(&["netns", "add", &stack.names.rs_ns])?;
        ip(&["netns", "add", &stack.names.guest_ns])?;

        ip(&[
            "link",
            "add",
            &stack.names.rs_veth,
            "type",
            "veth",
            "peer",
            "name",
            &stack.names.node_veth,
        ])?;
        ip(&[
            "link",
            "set",
            &stack.names.rs_veth,
            "netns",
            &stack.names.rs_ns,
        ])?;
        stack.in_rs(&[
            "ip",
            "addr",
            "add",
            &stack.addrs.rs_underlay,
            "dev",
            &stack.names.rs_veth,
        ])?;
        stack.in_rs(&["ip", "link", "set", &stack.names.rs_veth, "up"])?;
        stack.in_rs(&["ip", "link", "set", "lo", "up"])?;
        ip(&[
            "addr",
            "add",
            &stack.addrs.node_underlay,
            "dev",
            &stack.names.node_veth,
        ])?;
        ip(&["link", "set", &stack.names.node_veth, "up"])?;

        Ok(stack)
    }

    pub fn in_rs(&self, argv: &[&str]) -> Result<String> {
        self.in_ns(&self.names.rs_ns, argv)
    }

    pub fn in_guest(&self, argv: &[&str]) -> Result<String> {
        self.in_ns(&self.names.guest_ns, argv)
    }

    /// Run in the node's data plane namespace, which production code created.
    pub fn in_dataplane(&self, argv: &[&str]) -> Result<String> {
        self.in_ns(&self.names.dataplane_ns, argv)
    }

    fn in_ns(&self, ns: &str, argv: &[&str]) -> Result<String> {
        let mut full = vec!["netns", "exec", ns];
        full.extend_from_slice(argv);
        ip(&full)
    }

    /// A handle to the data plane namespace, opened the way the daemon does.
    pub fn open_dataplane(&self) -> Result<lnvps_node::netns::Handle> {
        lnvps_node::netns::ensure(
            std::path::Path::new(lnvps_node::netns::NETNS_DIR),
            &self.names.dataplane_ns,
        )
    }

    /// Remove everything this stack owns, ignoring what was never created.
    pub fn teardown(&self) {
        for ns in [
            &self.names.rs_ns,
            &self.names.guest_ns,
            &self.names.dataplane_ns,
        ] {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
        }
        // What a half-finished run leaves in the machine's own namespace.
        for link in self.names.interfaces() {
            let _ = Command::new("ip").args(["link", "del", link]).output();
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Run something with this thread inside a named namespace.
///
/// LNVPS sits behind the route server, and a node's inner addresses are not
/// routable from the machine's own namespace — that is the isolation the data
/// plane exists to provide. Anything standing in for LNVPS therefore has to run
/// where LNVPS would.
pub fn in_namespace<T, F>(name: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send,
    T: Send,
{
    let handle = lnvps_node::netns::Handle::open(
        &std::path::Path::new(lnvps_node::netns::NETNS_DIR).join(name),
    )
    .with_context(|| format!("opening namespace {name}"))?;
    handle.enter(f)
}

/// Run `ip`, reporting what failed rather than a bare exit code.
pub fn ip(args: &[&str]) -> Result<String> {
    run("ip", args)
}

pub fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program} {}", args.join(" ")))?;
    if !out.status.success() {
        // Both streams: ping writes its diagnosis to stdout and exits non-zero
        // with nothing on stderr, which produced "failed:" and no reason at all.
        bail!(
            "{program} {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// A node whose data plane is up: tunnel, bridge and filter, built by the
/// node's own code from a document LNVPS would have sent it.
pub struct DataPlane {
    pub node_key: lnvps_node::wgkey::NodeKey,
    /// The route server's keypair, kept so a test can rebuild the same document
    /// rather than describing it a second time.
    pub server_key: lnvps_api_common::WireguardKeypair,
    pub kernel: lnvps_node::net::Kernel,
    pub firewall: lnvps_node::fw::SystemFirewall,
    /// The route server's interface name, derived from the pool as production
    /// derives it.
    pub rs_interface: String,
    _state: tempfile::TempDir,
}

impl Stack {
    /// Bring up both ends: the route server's interface and peer, then the
    /// node's own data plane.
    ///
    /// Shared rather than copied into each test, because a second copy is a
    /// second place for the two ends to be configured differently — and a
    /// harness whose ends disagree fails as a production bug.
    pub async fn bring_up(&self, index: u8, guests: &[String]) -> Result<DataPlane> {
        use lnvps_api::router::{
            ObservedInterface, TunnelConfig, TunnelRouter, WireguardConfig, WireguardPeer,
        };

        let state = tempfile::TempDir::new().context("node state directory")?;
        let node_key = lnvps_node::wgkey::load_or_generate(state.path())?;
        let server_key = lnvps_api_common::generate_wireguard_keypair()?;
        let rs = self.route_server();
        let rs_interface = format!("wgln{index}");

        rs.add_tunnel(&ObservedInterface {
            id: None,
            name: rs_interface.clone(),
            local_addr: None,
            remote_addr: None,
            enabled: true,
            config: TunnelConfig::Wireguard(WireguardConfig {
                listen_port: Some(self.addrs.listen_port),
                private_key: Some(server_key.private_key.clone()),
                public_key: Some(lnvps_api_common::wireguard_key_to_base64(
                    &server_key.public_key,
                )),
                peers: vec![],
            }),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        rs.sync_tunnel_addresses(&rs_interface, &[self.addrs.rs_inner.clone()])
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        // The peer's AllowedIPs is the node's own address plus exactly the
        // guests LNVPS placed there — the anti-spoof boundary the node cannot
        // opt out of.
        let mut allowed = vec![self.addrs.node_inner.clone()];
        allowed.extend(guests.iter().cloned());
        rs.set_tunnel_peer(
            &rs_interface,
            &WireguardPeer {
                public_key: node_key.public_base64(),
                endpoint: None,
                allowed_ips: allowed,
                persistent_keepalive: None,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        // The pool's own block as well as the guests: an address on a
        // point-to-point interface does not route the rest of its prefix, so
        // without the block the route server reaches no node in the pool.
        let mut routes = vec![self.addrs.pool_block.clone()];
        routes.extend(guests.iter().cloned());
        rs.sync_tunnel_routes(&rs_interface, &routes)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let kernel = lnvps_node::net::Kernel::in_namespace(self.open_dataplane()?)?;
        let firewall = lnvps_node::fw::SystemFirewall::new(self.open_dataplane()?);
        let desired = self.document(&server_key, guests);
        // Applied before the struct takes ownership of the key, which the
        // document needs.
        lnvps_node::net::apply(&kernel, &firewall, &desired, &node_key).await?;

        Ok(DataPlane {
            node_key,
            server_key,
            kernel,
            firewall,
            rs_interface,
            _state: state,
        })
    }

    /// The document LNVPS would have sent this node.
    pub fn document(
        &self,
        server_key: &lnvps_api_common::WireguardKeypair,
        guests: &[String],
    ) -> lnvps_node::net::DesiredDataPlane {
        lnvps_node::net::DesiredDataPlane {
            // Set by tests that want a hypervisor; the network tests do not,
            // and starting one there would be testing systemd.
            libvirt: None,
            tunnel: lnvps_node::net::DesiredTunnel {
                address4: Some(self.addrs.node_inner.clone()),
                address6: None,
                gateway4: Some(Addrs::bare(&self.addrs.rs_inner).to_string()),
                gateway6: None,
                server_public_key: hex::encode(&server_key.public_key),
                endpoint: self.addrs.endpoint(),
                keepalive: Some(25),
                mtu: 1420,
            },
            gateways: guests
                .iter()
                .map(|_| self.addrs.guest_gateway.clone())
                .collect(),
            guests: guests
                .iter()
                .map(|address| lnvps_node::net::DesiredGuest {
                    address: address.clone(),
                    gateway: self.addrs.guest_gateway.clone(),
                    mac: Some(self.addrs.guest_mac.clone()),
                })
                .collect(),
        }
    }

    /// Configure the route server from the database, exactly as the worker's
    /// reconcile does: `plan_interface` decides the addresses, routes and peers, and
    /// this applies them.
    ///
    /// Used where a test has a real database — it is the production path on the
    /// LNVPS side, so a harness cannot quietly configure the far end more
    /// helpfully than the API would.
    /// The pool's own keypair is used, from the row: that is what production
    /// does, and a harness that configured the route server with a *different*
    /// key would leave the node encrypting to a key nobody holds — which shows
    /// up as a tunnel that comes up, handshakes never complete, and every
    /// packet disappears.
    pub async fn apply_pool(
        &self,
        db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
        pool: &lnvps_db::TunnelPool,
    ) -> Result<String> {
        use lnvps_api::router::{ObservedInterface, TunnelConfig, TunnelRouter, WireguardConfig};

        let plan = lnvps_api::provisioner::wg::TunnelProvisioner::new(db.clone())
            .plan(pool)
            .await?;
        let interface = format!("wgln{}", pool.id);
        let rs = self.route_server();

        rs.add_tunnel(&ObservedInterface {
            id: None,
            name: interface.clone(),
            local_addr: None,
            remote_addr: None,
            enabled: true,
            config: TunnelConfig::Wireguard(WireguardConfig {
                listen_port: Some(pool.listen_port),
                // `as_str`, not `to_string`: Display on an EncryptedString is
                // the literal "[ENCRYPTED]", so the latter configures the route
                // server with a key that is not a key. wg then has no private
                // key and no listen port, the node's handshakes go to a port
                // nothing is on, and the tunnel is up and silent.
                private_key: Some(pool.private_key.as_str().to_string()),
                public_key: Some(lnvps_api_common::wireguard_key_to_base64(&pool.public_key)),
                peers: vec![],
            }),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        rs.sync_tunnel_addresses(&interface, &plan.addresses)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for peer in &plan.peers {
            rs.set_tunnel_peer(&interface, peer)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        rs.sync_tunnel_routes(&interface, &plan.routes)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(interface)
    }

    /// LNVPS's route server, driven through its production configuration path
    /// with commands executed in the route server's namespace.
    pub fn route_server(&self) -> lnvps_api::router::LinuxSshRouter {
        let namespace = self.names.rs_ns.clone();
        lnvps_api::router::LinuxSshRouter::with_exec(std::sync::Arc::new(move |cmd: &str| {
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

    /// Whether this machine can run a stack at all.
    ///
    /// Skipping beats failing: a developer's laptop without root should not
    /// report a red test it was never able to run.
    pub fn requirements_met() -> bool {
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
}

/// A real libvirtd, started from the unit production renders.
///
/// Deliberately not a stand-in. The unit is the artefact most likely to be
/// wrong — two namespaces, four bind mounts and a config file, none of which a
/// unit test can do more than assert the text of — and systemd is the only
/// thing that can say whether it is right. So the harness writes production's
/// unit where systemd reads units, starts it, and lets systemd answer.
///
/// It also runs beside the machine's own libvirtd, which is the point: an
/// instance that disturbed the operator's would be visible here as their
/// daemon failing, not as ours succeeding.
pub struct Libvirtd {
    pub paths: lnvps_node::libvirt::Paths,
    /// What the node registers with LNVPS: its CA, not the leaf libvirtd serves.
    pub ca_pem: String,
    /// Kept so the instance's state outlives construction and no longer.
    _state: tempfile::TempDir,
}

impl Stack {
    /// Configure and start the node's libvirtd for this stack.
    ///
    /// `ca_pem` is LNVPS's client CA, exactly as it arrives in the node's
    /// document.
    pub fn start_libvirtd(&self, ca_pem: &str, allowed_dn: &str) -> Result<Libvirtd> {
        use lnvps_node::libvirt;

        let state = tempfile::TempDir::new().context("libvirt state directory")?;
        let mut paths = libvirt::Paths::new(state.path());
        // Where systemd reads units that do not survive a reboot, which is
        // exactly what a test's unit should be.
        paths.unit_dir = std::path::PathBuf::from("/run/systemd/system");
        paths.netns_name = self.names.dataplane_ns.clone();

        let listen = Addrs::bare(&self.addrs.node_inner)
            .parse()
            .context("the node's inner address")?;
        let identity = libvirt::load_or_generate_identity(&paths, listen)?;
        let params = libvirt::Params {
            listen,
            ca_pem: ca_pem.to_string(),
            allowed_dn: allowed_dn.to_string(),
        };
        let changed = libvirt::apply(&paths, &params, &identity)?;

        // systemd opens the namespace by path, from PID 1's mount namespace.
        // If the pin is invisible there the unit fails with a bare "no such
        // file or directory" naming the *binary*, which is a long way from the
        // truth.
        let pinned = lnvps_node::netns::path(&paths.netns_root, &paths.netns_name);
        anyhow::ensure!(
            pinned.exists(),
            "the data plane namespace is not pinned at {}",
            pinned.display()
        );
        let propagation = run("findmnt", &["-no", "PROPAGATION", "/run/netns"]).unwrap_or_default();
        anyhow::ensure!(
            propagation.contains("shared"),
            "/run/netns propagation is {propagation:?}; systemd cannot see the pin"
        );

        libvirt::ensure_running(&paths, changed)?;

        Ok(Libvirtd {
            ca_pem: identity.ca_pem.clone(),
            paths,
            _state: state,
        })
    }
}

impl Drop for Libvirtd {
    fn drop(&mut self) {
        // Stopped and removed rather than left running: the next test writes
        // the same unit, and systemd would otherwise keep serving the previous
        // one's certificate from a state directory that has been deleted.
        let unit = lnvps_node::libvirt::UNIT;
        let _ = Command::new(&self.paths.systemctl)
            .args(["disable", "--now", unit])
            .output();
        let _ = std::fs::remove_file(self.paths.unit_dir.join(unit));
        let _ = Command::new(&self.paths.systemctl)
            .arg("daemon-reload")
            .output();
    }
}
