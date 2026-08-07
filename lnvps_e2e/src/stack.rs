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
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
