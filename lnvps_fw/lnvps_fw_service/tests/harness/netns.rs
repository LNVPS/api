//! Virtual-network topology built from Linux network namespaces and veth
//! pairs, driven entirely by shelling out to `ip` (iproute2). No extra Rust
//! networking dependencies are required to build the topology itself.
//!
//! Topology (three namespaces wired in a line):
//!
//! ```text
//! [attacker]  a_up <──veth──> f_up  [filter]  f_dn <──veth──> v_dn  [vm]
//!  10.0.0.2/24                10.0.0.1/24      10.0.1.1/24            10.0.1.2/24
//!  fd00:0::2/64               fd00:0::1/64     fd00:1::1/64           fd00:1::2/64
//!                             (XDP attaches on f_up ingress)
//! ```
//!
//! The `filter` namespace forwards between its two veth ends, so packets sent
//! by the attacker to the VM address transit `f_up` (where the XDP ingress
//! program inspects them) before being routed to the `vm` namespace. This
//! mirrors the production datapath (attack traffic entering an uplink NIC
//! bound for a guest IP) closely enough to exercise the whole pipeline.
//!
//! Cleanup is idempotent and RAII: dropping [`NetnsTopology`] deletes the
//! namespaces (which tears down the veth pairs with them), even on panic.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// IPv4 addresses used by the topology.
pub const ATTACKER_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const FILTER_UP_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const FILTER_DN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
pub const VM_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 2);

/// IPv6 addresses used by the topology.
pub const ATTACKER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
pub const FILTER_UP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
pub const FILTER_DN_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);
pub const VM_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 2);

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Run an `ip`/`sysctl` command, returning an error containing stderr on
/// non-zero exit.
fn run(cmd: &str, args: &[&str]) -> std::io::Result<()> {
    let out = Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "`{} {}` failed: {}",
            cmd,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Best-effort variant that never fails (used on the teardown path).
fn run_quiet(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

/// A three-namespace virtual network. Interface and namespace names are unique
/// per instance so multiple topologies can coexist in the same test binary.
pub struct NetnsTopology {
    /// Namespace names (attacker, filter, vm).
    pub attacker_ns: String,
    pub filter_ns: String,
    pub vm_ns: String,
    /// Interface names inside their respective namespaces.
    pub attacker_if: String,
    /// Filter-side uplink interface — the XDP attach point.
    pub filter_up_if: String,
    pub filter_dn_if: String,
    pub vm_if: String,
}

impl NetnsTopology {
    /// Build and configure the whole topology. Requires `CAP_NET_ADMIN`
    /// (run as root).
    pub fn new() -> std::io::Result<Self> {
        let id = std::process::id() % 10_000;
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tag = format!("fw{id}_{n}");

        let topo = Self {
            attacker_ns: format!("{tag}_at"),
            filter_ns: format!("{tag}_fl"),
            vm_ns: format!("{tag}_vm"),
            attacker_if: format!("{tag}au"),
            filter_up_if: format!("{tag}fu"),
            filter_dn_if: format!("{tag}fd"),
            vm_if: format!("{tag}vd"),
        };
        topo.build()?;
        Ok(topo)
    }

    fn build(&self) -> std::io::Result<()> {
        // Namespaces.
        run("ip", &["netns", "add", &self.attacker_ns])?;
        run("ip", &["netns", "add", &self.filter_ns])?;
        run("ip", &["netns", "add", &self.vm_ns])?;

        // attacker <-> filter veth pair.
        run(
            "ip",
            &[
                "link",
                "add",
                &self.attacker_if,
                "type",
                "veth",
                "peer",
                "name",
                &self.filter_up_if,
            ],
        )?;
        run(
            "ip",
            &["link", "set", &self.attacker_if, "netns", &self.attacker_ns],
        )?;
        run(
            "ip",
            &["link", "set", &self.filter_up_if, "netns", &self.filter_ns],
        )?;

        // filter <-> vm veth pair.
        run(
            "ip",
            &[
                "link",
                "add",
                &self.filter_dn_if,
                "type",
                "veth",
                "peer",
                "name",
                &self.vm_if,
            ],
        )?;
        run(
            "ip",
            &["link", "set", &self.filter_dn_if, "netns", &self.filter_ns],
        )?;
        run("ip", &["link", "set", &self.vm_if, "netns", &self.vm_ns])?;

        // Loopback + link up, addresses.
        self.up_loopback(&self.attacker_ns)?;
        self.up_loopback(&self.filter_ns)?;
        self.up_loopback(&self.vm_ns)?;

        self.addr_up(
            &self.attacker_ns,
            &self.attacker_if,
            ATTACKER_V4,
            24,
            ATTACKER_V6,
            64,
        )?;
        self.addr_up(
            &self.filter_ns,
            &self.filter_up_if,
            FILTER_UP_V4,
            24,
            FILTER_UP_V6,
            64,
        )?;
        self.addr_up(
            &self.filter_ns,
            &self.filter_dn_if,
            FILTER_DN_V4,
            24,
            FILTER_DN_V6,
            64,
        )?;
        self.addr_up(&self.vm_ns, &self.vm_if, VM_V4, 24, VM_V6, 64)?;

        // Enable forwarding in the filter namespace.
        self.sysctl(&self.filter_ns, "net.ipv4.ip_forward=1")?;
        self.sysctl(&self.filter_ns, "net.ipv6.conf.all.forwarding=1")?;

        // Routes: attacker reaches the vm subnet via the filter uplink.
        self.route4(&self.attacker_ns, "10.0.1.0/24", FILTER_UP_V4)?;
        self.route6(&self.attacker_ns, "fd00:1::/64", FILTER_UP_V6)?;
        // vm's default route points back through the filter downlink.
        self.route4(&self.vm_ns, "default", FILTER_DN_V4)?;
        self.route6(&self.vm_ns, "default", FILTER_DN_V6)?;

        Ok(())
    }

    fn up_loopback(&self, ns: &str) -> std::io::Result<()> {
        run("ip", &["-n", ns, "link", "set", "lo", "up"])
    }

    #[allow(clippy::too_many_arguments)]
    fn addr_up(
        &self,
        ns: &str,
        ifn: &str,
        v4: Ipv4Addr,
        v4_pfx: u8,
        v6: Ipv6Addr,
        v6_pfx: u8,
    ) -> std::io::Result<()> {
        run("ip", &["-n", ns, "link", "set", ifn, "up"])?;
        run(
            "ip",
            &[
                "-n",
                ns,
                "addr",
                "add",
                &format!("{v4}/{v4_pfx}"),
                "dev",
                ifn,
            ],
        )?;
        // `nodad` avoids the IPv6 duplicate-address-detection delay that would
        // otherwise make the address unusable for the first second.
        run(
            "ip",
            &[
                "-n",
                ns,
                "addr",
                "add",
                &format!("{v6}/{v6_pfx}"),
                "nodad",
                "dev",
                ifn,
            ],
        )?;
        Ok(())
    }

    fn sysctl(&self, ns: &str, kv: &str) -> std::io::Result<()> {
        run("ip", &["netns", "exec", ns, "sysctl", "-qw", kv])
    }

    fn route4(&self, ns: &str, dst: &str, via: Ipv4Addr) -> std::io::Result<()> {
        run(
            "ip",
            &["-n", ns, "route", "add", dst, "via", &via.to_string()],
        )
    }

    fn route6(&self, ns: &str, dst: &str, via: Ipv6Addr) -> std::io::Result<()> {
        run(
            "ip",
            &["-6", "-n", ns, "route", "add", dst, "via", &via.to_string()],
        )
    }

    /// Path to the filter namespace's mount handle, for `setns`.
    pub fn filter_ns_path(&self) -> String {
        format!("/var/run/netns/{}", self.filter_ns)
    }
}

impl Drop for NetnsTopology {
    fn drop(&mut self) {
        // Deleting a namespace tears down any veth ends still inside it.
        run_quiet("ip", &["netns", "del", &self.attacker_ns]);
        run_quiet("ip", &["netns", "del", &self.filter_ns]);
        run_quiet("ip", &["netns", "del", &self.vm_ns]);
    }
}
