//! Applying the data plane LNVPS asked for.
//!
//! The daemon configures the machine itself, with `ip` and `wg`, rather than
//! writing files for something else to read. A marketplace node runs on
//! hardware LNVPS does not own: a data plane that depends on the operator
//! having wired it up correctly is one whose mistakes surface as a customer's
//! VM having no network. Applying it here means it re-converges on every
//! refresh instead.
//!
//! Everything is idempotent and stated declaratively — `ip addr replace`, `ip
//! route replace`, `wg set` — so a node that is already correct is not
//! disturbed, and a node that has drifted is corrected without being torn down.
//!
//! Commands go through [`CommandRunner`] because they run as root on somebody
//! else's machine: the exact command issued is the thing worth asserting, which
//! needs the process boundary replaced rather than mocked around.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::wgkey::{self, NodeKey};

/// The tunnel interface the node terminates its data plane on.
pub const TUNNEL_INTERFACE: &str = "wg0";

/// The bridge guests sit on when LNVPS has not said otherwise — which is only
/// before the first data plane has been fetched.
pub const DEFAULT_BRIDGE: &str = "br-lnvps";

/// Runs a command and reports what happened.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, returning `(exit ok, stdout)`.
    ///
    /// Failure to *launch* is an error; a non-zero exit is not, because several
    /// callers here use a failing command as a question ("does this interface
    /// exist?") rather than as a fault.
    fn run(&self, program: &str, args: &[&str]) -> Result<(bool, String)>;
}

/// Runs commands as real processes.
pub struct SystemCommands;

impl CommandRunner for SystemCommands {
    fn run(&self, program: &str, args: &[&str]) -> Result<(bool, String)> {
        let out = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("Cannot run {program}: is it installed?"))?;
        let text = if out.status.success() {
            String::from_utf8_lossy(&out.stdout).to_string()
        } else {
            // The failure text, not the empty stdout: a caller reporting why
            // something did not apply needs what the tool said.
            String::from_utf8_lossy(&out.stderr).to_string()
        };
        Ok((out.status.success(), text))
    }
}

/// The desired data plane, as LNVPS states it.
///
/// Mirrors `GET /api/v1/node/dataplane`. Fetched and applied as one document
/// because it only makes sense as one: a bridge with no tunnel carries nothing,
/// and a tunnel with no guest routes carries nothing back.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredDataPlane {
    pub tunnel: DesiredTunnel,
    pub bridge: String,
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

/// What the machine currently looks like.
///
/// Reported to LNVPS over the control API, where it is the first thing the
/// health gate checks. Every field is read from the machine, never remembered
/// from what was applied — the point of observing is to catch the case where
/// the two disagree.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DataPlaneState {
    /// Whether `wg0` exists and is up.
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
/// Returns the commands that were actually run, so `dataplane apply` can show
/// an operator what changed and a test can assert it.
pub fn apply(
    runner: &dyn CommandRunner,
    desired: &DesiredDataPlane,
    key: &NodeKey,
    state_dir: &Path,
) -> Result<Vec<String>> {
    let mut applied = Vec::new();
    apply_tunnel(runner, desired, key, state_dir, &mut applied)?;
    apply_bridge(runner, desired, &mut applied)?;
    apply_forwarding(runner, &mut applied)?;
    Ok(applied)
}

/// Bring up `wg0` and point the default route down it.
fn apply_tunnel(
    runner: &dyn CommandRunner,
    desired: &DesiredDataPlane,
    key: &NodeKey,
    state_dir: &Path,
    applied: &mut Vec<String>,
) -> Result<()> {
    let mtu = desired.tunnel.mtu.to_string();
    if !link_exists(runner, TUNNEL_INTERFACE)? {
        run(
            runner,
            "ip",
            &["link", "add", TUNNEL_INTERFACE, "type", "wireguard"],
            applied,
        )?;
    }

    // The private key is handed over as a path. An argument would be visible in
    // `ps` to every user on the machine, and a marketplace node usually has
    // more than one login.
    let key_file = wgkey::write_private_key_file(state_dir, key)?;
    let key_file = key_file.to_string_lossy().to_string();
    run(
        runner,
        "wg",
        &["set", TUNNEL_INTERFACE, "private-key", &key_file],
        applied,
    )?;

    let server_key = wgkey::parse_public_key(&desired.tunnel.server_public_key)?;
    let keepalive = desired.tunnel.keepalive.unwrap_or(0).to_string();
    let mut peer: Vec<&str> = vec![
        "set",
        TUNNEL_INTERFACE,
        "peer",
        &server_key,
        "endpoint",
        &desired.tunnel.endpoint,
        // Everything goes up the tunnel: the node's guests use LNVPS addresses,
        // so there is no traffic of theirs that belongs anywhere else.
        "allowed-ips",
        "0.0.0.0/0,::/0",
    ];
    if desired.tunnel.keepalive.is_some() {
        peer.extend_from_slice(&["persistent-keepalive", &keepalive]);
    }
    run(runner, "wg", &peer, applied)?;

    // A peer that is not the route server has no business on this interface.
    // It would most likely be a stale key from a re-key, still able to send
    // traffic that the node treats as coming from LNVPS.
    for stale in stale_peers(runner, &server_key)? {
        run(
            runner,
            "wg",
            &["set", TUNNEL_INTERFACE, "peer", &stale, "remove"],
            applied,
        )?;
    }

    for address in [&desired.tunnel.address4, &desired.tunnel.address6]
        .into_iter()
        .flatten()
    {
        run(
            runner,
            "ip",
            &["addr", "replace", address, "dev", TUNNEL_INTERFACE],
            applied,
        )?;
    }

    // Not 1500: WireGuard's overhead comes off it, and guessing wrong hangs
    // large transfers rather than failing outright.
    run(
        runner,
        "ip",
        &["link", "set", TUNNEL_INTERFACE, "mtu", &mtu, "up"],
        applied,
    )?;

    // No `via`: the tunnel is point-to-point, so the interface names the next
    // hop by itself, and naming a gateway would be a second copy of the route
    // server's address free to disagree with the one on the peer.
    if desired.tunnel.address4.is_some() {
        run(
            runner,
            "ip",
            &["route", "replace", "default", "dev", TUNNEL_INTERFACE],
            applied,
        )?;
    }
    if desired.tunnel.address6.is_some() {
        run(
            runner,
            "ip",
            &["-6", "route", "replace", "default", "dev", TUNNEL_INTERFACE],
            applied,
        )?;
    }
    Ok(())
}

/// Bring up the guest bridge and route each guest to it.
fn apply_bridge(
    runner: &dyn CommandRunner,
    desired: &DesiredDataPlane,
    applied: &mut Vec<String>,
) -> Result<()> {
    let bridge = desired.bridge.as_str();
    if bridge.is_empty() {
        bail!("LNVPS did not name a bridge, so there is nothing to put guests on");
    }
    if !link_exists(runner, bridge)? {
        run(
            runner,
            "ip",
            &["link", "add", bridge, "type", "bridge"],
            applied,
        )?;
    }
    // The bridge carries the same payload as the tunnel, so it takes the same
    // MTU: a guest that sends 1500 bytes into a 1420-byte tunnel produces a
    // connection that opens and then hangs on the first large transfer.
    let mtu = desired.tunnel.mtu.to_string();
    run(
        runner,
        "ip",
        &["link", "set", bridge, "mtu", &mtu, "up"],
        applied,
    )?;

    // The gateway belongs to the range, not to this node, and the guest
    // believes it is on-link. Held as a host address so the node answers for it
    // without claiming the rest of the range is local — the other addresses in
    // it live on other nodes, up the tunnel.
    for gateway in &desired.gateways {
        let addr = host_prefix(gateway)?;
        run(
            runner,
            "ip",
            &["addr", "replace", &addr, "dev", bridge],
            applied,
        )?;
    }

    // The guest thinks its neighbours are on-link and will ARP for them; proxy
    // ARP is what lets the node answer and pull that traffic up the tunnel
    // instead of it disappearing into a link that has no such address.
    for knob in [
        "net.ipv4.conf.NAME.proxy_arp=1",
        "net.ipv6.conf.NAME.proxy_ndp=1",
    ] {
        // Interface names appear in sysctl keys with dots replaced, or the key
        // itself becomes ambiguous.
        let setting = knob.replace("NAME", &bridge.replace('.', "/"));
        run(runner, "sysctl", &["-w", &setting], applied)?;
    }

    // What belongs on this bridge: the guests, plus the gateways the node
    // answers for. Both are kept so the stale sweep below cannot delete the
    // bridge's own addressing while tidying up after a departed guest.
    let mut want: HashSet<String> = desired.guests.iter().map(|g| g.address.clone()).collect();
    for gateway in &desired.gateways {
        want.insert(host_prefix(gateway)?);
    }
    let want: HashSet<String> = want;
    // Sorted, so a node applying the same document twice runs the same
    // commands in the same order and a diff of two runs means something.
    let mut guests: Vec<&String> = desired.guests.iter().map(|g| &g.address).collect();
    guests.sort();
    for address in guests {
        run(
            runner,
            "ip",
            &["route", "replace", address, "dev", bridge],
            applied,
        )?;
    }
    // A guest that has been deleted or moved must stop being routed here at
    // once: its address goes back in the pool and may already be somebody
    // else's.
    for stale in stale_routes(runner, bridge, &want)? {
        run(
            runner,
            "ip",
            &["route", "del", &stale, "dev", bridge],
            applied,
        )?;
    }
    Ok(())
}

/// A node that does not forward is a node whose guests have no network at all.
fn apply_forwarding(runner: &dyn CommandRunner, applied: &mut Vec<String>) -> Result<()> {
    for setting in ["net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"] {
        run(runner, "sysctl", &["-w", setting], applied)?;
    }
    Ok(())
}

/// Read back what the machine actually has.
pub fn observe(runner: &dyn CommandRunner, bridge: &str) -> Result<DataPlaneState> {
    let (tunnel_up, tunnel_mtu) = link_state(runner, TUNNEL_INTERFACE)?;
    let (bridge_up, _) = link_state(runner, bridge)?;
    Ok(DataPlaneState {
        tunnel_up,
        tunnel_mtu,
        last_handshake_secs: last_handshake(runner)?,
        bridge_up,
        forwarding4: sysctl_enabled(runner, "net.ipv4.ip_forward")?,
        forwarding6: sysctl_enabled(runner, "net.ipv6.conf.all.forwarding")?,
        routed_guests: routed_addresses(runner, bridge)?.len(),
    })
}

/// Whether a link exists at all.
fn link_exists(runner: &dyn CommandRunner, name: &str) -> Result<bool> {
    Ok(runner.run("ip", &["link", "show", name])?.0)
}

/// Whether a link is up, and its MTU.
fn link_state(runner: &dyn CommandRunner, name: &str) -> Result<(bool, Option<u32>)> {
    let (ok, out) = runner.run("ip", &["-j", "link", "show", name])?;
    if !ok {
        return Ok((false, None));
    }
    let links: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap_or_default();
    let Some(link) = links.first() else {
        return Ok((false, None));
    };
    // `operstate` rather than the UP flag: an interface can be administratively
    // up with no carrier, and for a tunnel that is exactly the broken case.
    let up = link
        .get("flags")
        .and_then(|f| f.as_array())
        .map(|f| f.iter().any(|v| v.as_str() == Some("UP")))
        .unwrap_or(false);
    let mtu = link.get("mtu").and_then(|m| m.as_u64()).map(|m| m as u32);
    Ok((up, mtu))
}

/// Seconds since the route server last completed a handshake.
fn last_handshake(runner: &dyn CommandRunner) -> Result<Option<u64>> {
    let (ok, out) = runner.run("wg", &["show", TUNNEL_INTERFACE, "latest-handshakes"])?;
    if !ok {
        return Ok(None);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let latest = out
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|t| t.parse::<u64>().ok())
        // Zero means "never", not "in 1970"; reporting an age of half a century
        // would look like a stale tunnel rather than one that has never worked.
        .filter(|t| *t > 0)
        .max();
    Ok(latest.map(|t| now.saturating_sub(t)))
}

/// Whether a sysctl is on.
fn sysctl_enabled(runner: &dyn CommandRunner, name: &str) -> Result<bool> {
    let (ok, out) = runner.run("sysctl", &["-n", name])?;
    Ok(ok && out.trim() == "1")
}

/// Peers configured on the tunnel that are not the route server.
fn stale_peers(runner: &dyn CommandRunner, server_key: &str) -> Result<Vec<String>> {
    let (ok, out) = runner.run("wg", &["show", TUNNEL_INTERFACE, "peers"])?;
    if !ok {
        return Ok(vec![]);
    }
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != server_key)
        .map(str::to_string)
        .collect())
}

/// Addresses currently routed to the bridge.
fn routed_addresses(runner: &dyn CommandRunner, bridge: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    // Both families asked for separately: `ip route show` is IPv4 only, so a v6
    // guest would look unrouted on every pass and be re-added forever.
    for family in ["-4", "-6"] {
        let (ok, text) = runner.run("ip", &[family, "-j", "route", "show", "dev", bridge])?;
        if !ok {
            continue;
        }
        let routes: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
        for route in routes {
            let Some(dst) = route.get("dst").and_then(|d| d.as_str()) else {
                continue;
            };
            if dst == "default" {
                continue;
            }
            out.push(if dst.contains('/') {
                dst.to_string()
            } else {
                host_prefix(dst)?
            });
        }
    }
    Ok(out)
}

/// Routes on the bridge that no guest accounts for.
fn stale_routes(
    runner: &dyn CommandRunner,
    bridge: &str,
    want: &HashSet<String>,
) -> Result<Vec<String>> {
    Ok(routed_addresses(runner, bridge)?
        .into_iter()
        .filter(|r| !want.contains(r))
        .collect())
}

/// `203.0.113.1` -> `203.0.113.1/32`, and the v6 equivalent.
fn host_prefix(address: &str) -> Result<String> {
    if address.contains('/') {
        return Ok(address.to_string());
    }
    let ip: std::net::IpAddr = address
        .parse()
        .with_context(|| format!("{address} is not an IP address"))?;
    Ok(match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}/32"),
        std::net::IpAddr::V6(v6) => format!("{v6}/128"),
    })
}

/// Run a command that must succeed, recording it.
fn run(
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
    applied: &mut Vec<String>,
) -> Result<()> {
    let (ok, out) = runner.run(program, args)?;
    let line = format!("{program} {}", args.join(" "));
    if !ok {
        bail!("{line}: {}", out.trim());
    }
    applied.push(line);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A machine that answers `ip`/`wg` queries from a fixed script and records
    /// everything it was asked to change.
    ///
    /// The commands run as root on somebody else's hardware, so what is worth
    /// asserting is the exact command issued — which needs the process boundary
    /// replaced, not mocked around.
    struct FakeMachine {
        log: Mutex<Vec<String>>,
        /// Substring -> canned (ok, stdout).
        answers: Vec<(&'static str, bool, &'static str)>,
    }

    impl FakeMachine {
        fn new(answers: Vec<(&'static str, bool, &'static str)>) -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                answers,
            }
        }

        fn ran(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeMachine {
        fn run(&self, program: &str, args: &[&str]) -> Result<(bool, String)> {
            let line = format!("{program} {}", args.join(" "));
            self.log.lock().unwrap().push(line.clone());
            for (needle, ok, out) in &self.answers {
                if line.contains(needle) {
                    return Ok((*ok, out.to_string()));
                }
            }
            Ok((true, String::new()))
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
            bridge: "br-lnvps".to_string(),
            gateways: vec!["203.0.113.1".to_string()],
            guests: vec![DesiredGuest {
                address: "203.0.113.5/32".to_string(),
                gateway: "203.0.113.1".to_string(),
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            }],
        }
    }

    fn key(dir: &Path) -> NodeKey {
        wgkey::load_or_generate(dir).unwrap()
    }

    /// A node with nothing configured must end up with the whole data plane:
    /// tunnel, addresses, MTU, default route, bridge, gateway, guest route and
    /// forwarding. Any one of them missing is a customer with no network.
    #[test]
    fn a_bare_machine_gets_the_whole_data_plane() {
        let dir = tempfile::tempdir().unwrap();
        // Neither interface exists yet.
        let machine = FakeMachine::new(vec![("ip link show", false, "does not exist")]);
        let applied = apply(&machine, &desired(), &key(dir.path()), dir.path()).unwrap();
        let script = applied.join("\n");

        assert!(
            script.contains("ip link add wg0 type wireguard"),
            "{script}"
        );
        assert!(script.contains("wg set wg0 private-key"), "{script}");
        // Everything goes up the tunnel: the guests use LNVPS addresses, so no
        // traffic of theirs belongs anywhere else.
        assert!(script.contains("allowed-ips 0.0.0.0/0,::/0"), "{script}");
        assert!(script.contains("persistent-keepalive 25"), "{script}");
        assert!(
            script.contains("ip addr replace 10.66.0.2/32 dev wg0"),
            "{script}"
        );
        assert!(
            script.contains("ip addr replace fd00:66::2/128 dev wg0"),
            "{script}"
        );
        assert!(script.contains("ip link set wg0 mtu 1420 up"), "{script}");
        assert!(
            script.contains("ip route replace default dev wg0"),
            "{script}"
        );
        assert!(
            script.contains("ip -6 route replace default dev wg0"),
            "{script}"
        );

        assert!(
            script.contains("ip link add br-lnvps type bridge"),
            "{script}"
        );
        // The bridge takes the tunnel's MTU: a guest sending 1500 bytes into a
        // 1420-byte tunnel opens a connection and then hangs on a large one.
        assert!(
            script.contains("ip link set br-lnvps mtu 1420 up"),
            "{script}"
        );
        // The gateway belongs to the range, not the node, and is held as a host
        // address so the node answers for it without claiming the rest of the
        // range is local.
        assert!(
            script.contains("ip addr replace 203.0.113.1/32 dev br-lnvps"),
            "{script}"
        );
        assert!(script.contains("proxy_arp=1"), "{script}");
        assert!(script.contains("proxy_ndp=1"), "{script}");
        assert!(
            script.contains("ip route replace 203.0.113.5/32 dev br-lnvps"),
            "{script}"
        );
        assert!(script.contains("net.ipv4.ip_forward=1"), "{script}");
        assert!(
            script.contains("net.ipv6.conf.all.forwarding=1"),
            "{script}"
        );
    }

    /// The private key reaches `wg` as a path, never as an argument: arguments
    /// are visible in `ps` to every user on the machine.
    #[test]
    fn the_private_key_is_never_an_argument() {
        let dir = tempfile::tempdir().unwrap();
        let node_key = key(dir.path());
        let machine = FakeMachine::new(vec![]);
        apply(&machine, &desired(), &node_key, dir.path()).unwrap();

        let script = machine.ran().join("\n");
        assert!(
            !script.contains(&node_key.private_base64()),
            "the private key was passed on a command line"
        );
        assert!(script.contains("private-key"), "{script}");
    }

    /// An interface that already exists is configured, not recreated:
    /// recreating it drops the tunnel every time the node refreshes.
    #[test]
    fn an_existing_interface_is_not_recreated() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![("ip link show", true, "")]);
        let applied = apply(&machine, &desired(), &key(dir.path()), dir.path()).unwrap();
        let script = applied.join("\n");
        assert!(!script.contains("ip link add"), "{script}");
        assert!(script.contains("ip addr replace"), "{script}");
    }

    /// A peer that is not the route server has no business on this interface —
    /// most likely a stale key from a re-key, still able to send traffic the
    /// node would treat as LNVPS's.
    #[test]
    fn a_stale_peer_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![("wg show wg0 peers", true, "c3RyYXk=\n")]);
        let applied = apply(&machine, &desired(), &key(dir.path()), dir.path()).unwrap();
        let script = applied.join("\n");
        assert!(
            script.contains("wg set wg0 peer c3RyYXk= remove"),
            "{script}"
        );
    }

    /// A guest that has been deleted or moved must stop being routed here at
    /// once: its address goes back in the pool and may already be somebody
    /// else's. The bridge's own gateway must survive that sweep.
    #[test]
    fn a_departed_guest_stops_being_routed_but_the_gateway_stays() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![(
            "-4 -j route show dev br-lnvps",
            true,
            r#"[{"dst":"203.0.113.5"},{"dst":"203.0.113.9"},{"dst":"203.0.113.1"}]"#,
        )]);
        let applied = apply(&machine, &desired(), &key(dir.path()), dir.path()).unwrap();
        let script = applied.join("\n");
        assert!(
            script.contains("ip route del 203.0.113.9/32 dev br-lnvps"),
            "{script}"
        );
        assert!(
            !script.contains("ip route del 203.0.113.5/32"),
            "a guest that is still here was unrouted"
        );
        assert!(
            !script.contains("ip route del 203.0.113.1/32"),
            "the bridge's own gateway was deleted"
        );
    }

    /// A command that fails stops the run and says which one: half a data plane
    /// applied silently is worse than none, because it looks configured.
    #[test]
    fn a_failing_command_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![
            ("ip link show", false, ""),
            ("ip link add wg0", false, "RTNETLINK answers: not permitted"),
        ]);
        let err = apply(&machine, &desired(), &key(dir.path()), dir.path()).unwrap_err();
        assert!(format!("{err}").contains("ip link add wg0"), "{err}");
        assert!(format!("{err}").contains("not permitted"), "{err}");
    }

    /// A document naming no bridge would silently configure a tunnel with
    /// nothing behind it.
    #[test]
    fn a_document_without_a_bridge_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![]);
        let plane = DesiredDataPlane {
            bridge: String::new(),
            ..desired()
        };
        assert!(apply(&machine, &plane, &key(dir.path()), dir.path()).is_err());
    }

    /// A single-stack pool must not produce a default route for the family it
    /// has no address in — that route would black-hole traffic instead of
    /// letting the machine's own routing handle it.
    #[test]
    fn a_single_stack_tunnel_only_routes_its_own_family() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![]);
        let mut plane = desired();
        plane.tunnel.address6 = None;
        let applied = apply(&machine, &plane, &key(dir.path()), dir.path()).unwrap();
        let script = applied.join("\n");
        assert!(script.contains("ip route replace default dev wg0"));
        assert!(!script.contains("ip -6 route replace default"), "{script}");
    }

    /// A gateway that is not an address is reported against the value, not as
    /// a failing `ip` command: LNVPS sent it, and the node has to say which
    /// part of the document it could not use.
    #[test]
    fn a_gateway_that_is_not_an_address_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let machine = FakeMachine::new(vec![]);
        let plane = DesiredDataPlane {
            gateways: vec!["not-an-address".to_string()],
            ..desired()
        };
        let err = apply(&machine, &plane, &key(dir.path()), dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("not-an-address"), "{err:#}");
    }

    /// Observation reads the machine rather than remembering what was applied:
    /// the point of observing is to catch the case where the two disagree.
    #[test]
    fn observation_reports_what_the_machine_has() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let machine = FakeMachine::new(vec![
            (
                "-j link show wg0",
                true,
                r#"[{"ifname":"wg0","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1420}]"#,
            ),
            (
                "-j link show br-lnvps",
                true,
                r#"[{"ifname":"br-lnvps","flags":["BROADCAST","MULTICAST","UP"],"mtu":1420}]"#,
            ),
            (
                "wg show wg0 latest-handshakes",
                true,
                Box::leak(format!("peerkey\t{}\n", now - 12).into_boxed_str()),
            ),
            ("sysctl -n", true, "1\n"),
            (
                "-4 -j route show dev br-lnvps",
                true,
                r#"[{"dst":"203.0.113.5"}]"#,
            ),
        ]);

        let state = observe(&machine, "br-lnvps").unwrap();
        assert!(state.tunnel_up);
        assert_eq!(state.tunnel_mtu, Some(1420));
        assert!(state.last_handshake_secs.unwrap() <= 13);
        assert!(state.bridge_up);
        assert!(state.forwarding4 && state.forwarding6);
        assert_eq!(state.routed_guests, 1);
        assert!(state.healthy());
    }

    /// `wg0` comes up happily with a peer that never answers, so an interface
    /// that has never handshaken is configured, not working — and a node in
    /// that state must not be called healthy.
    #[test]
    fn a_tunnel_that_has_never_handshaken_is_not_healthy() {
        let machine = FakeMachine::new(vec![
            (
                "-j link show",
                true,
                r#"[{"ifname":"wg0","flags":["UP"],"mtu":1420}]"#,
            ),
            // Zero means never, not 1970: reporting an age of half a century
            // would look like a stale tunnel rather than one never used.
            ("latest-handshakes", true, "peerkey\t0\n"),
            ("sysctl -n", true, "1\n"),
        ]);
        let state = observe(&machine, "br-lnvps").unwrap();
        assert!(state.tunnel_up);
        assert_eq!(state.last_handshake_secs, None);
        assert!(!state.healthy());
    }

    /// A machine with nothing configured reports nothing configured, rather
    /// than failing: "not set up yet" is a state the gate has to be able to
    /// read.
    #[test]
    fn an_unconfigured_machine_observes_cleanly() {
        let machine = FakeMachine::new(vec![("", false, "does not exist")]);
        let state = observe(&machine, "br-lnvps").unwrap();
        assert_eq!(state, DataPlaneState::default());
        assert!(!state.healthy());
    }
}
