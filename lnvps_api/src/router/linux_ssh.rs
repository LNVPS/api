use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use reqwest::Url;
use serde::Deserialize;

use lnvps_api_common::retry::OpResult;
use lnvps_api_common::{op_fatal, op_transient};

use crate::router::{
    ArpEntry, BgpPeer, BgpPeerDirection, BgpRoute, BgpRouter, BgpSession, GreConfig, Router,
    Tunnel, TunnelConfig, TunnelRouter, TunnelTraffic, VxlanConfig, WireguardConfig, WireguardPeer,
};
use crate::ssh_client::SshClient;

/// A router backed by a generic Linux machine managed over SSH.
///
/// ARP management is implemented with iproute2 (`ip neigh`). Static neighbour
/// entries are added as `PERMANENT` so they survive without ongoing ARP traffic,
/// mirroring the behaviour of the Mikrotik static-ARP router.
///
/// Connection details are encoded in the router config:
/// - `url`: `ssh://<user>@<host>[:<port>]/<interface>` (port defaults to 22)
/// - `token`: the SSH private key in PEM format
pub struct LinuxSshRouter {
    host: String,
    username: String,
    /// Default network interface used for neighbour entries
    interface: String,
    /// SSH private key (PEM)
    key: String,
}

impl LinuxSshRouter {
    /// Build a router from the stored config `url` and `token`.
    pub fn new(url: &str, key: &str) -> Result<Self> {
        let u = Url::parse(url).context("Invalid linux-ssh router url")?;
        if u.scheme() != "ssh" {
            bail!("linux-ssh router url must use the ssh:// scheme");
        }
        let host = u
            .host_str()
            .context("Missing host in linux-ssh router url")?;
        let port = u.port().unwrap_or(22);
        let username = if u.username().is_empty() {
            "root".to_string()
        } else {
            u.username().to_string()
        };
        let interface = u.path().trim_matches('/').to_string();
        if interface.is_empty() {
            bail!(
                "linux-ssh router url must include an interface in the path, e.g. ssh://root@host/eth0"
            );
        }
        Ok(Self {
            host: format!("{}:{}", host, port),
            username,
            interface,
            key: key.to_string(),
        })
    }

    /// Open a fresh SSH connection for a single operation.
    ///
    /// Connecting per-operation keeps the router `Send + Sync` without holding a
    /// live (non-`Sync`) ssh2 session, and is naturally resilient to dropped
    /// connections.
    async fn connect(&self) -> Result<SshClient> {
        let mut client = SshClient::new()?;
        client
            .connect_with_key(&self.host, &self.username, &self.key)
            .await?;
        Ok(client)
    }

    /// Run a command, mapping connection failures to transient errors and
    /// non-zero exits to fatal errors. Returns stdout on success.
    async fn exec_checked(&self, cmd: &str) -> OpResult<String> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => op_transient!(e),
        };
        let (code, out) = match client.execute(cmd).await {
            Ok(r) => r,
            Err(e) => op_transient!(e),
        };
        if code != 0 {
            op_fatal!("command failed ({}): {} :: {}", code, cmd, out);
        }
        Ok(out)
    }
}

#[async_trait]
impl Router for LinuxSshRouter {
    async fn generate_mac(&self, _ip: &str, _comment: &str) -> Result<Option<ArpEntry>> {
        // Linux doesn't require a specific MAC for the neighbour entry
        Ok(None)
    }

    async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => op_transient!(e),
        };
        let (code, out) = match client.execute("ip -j neigh show").await {
            Ok(r) => r,
            Err(e) => op_transient!(e),
        };
        if code != 0 {
            op_fatal!("ip neigh show failed ({}): {}", code, out);
        }
        let entries: Vec<IpNeighEntry> = match serde_json::from_str(&out) {
            Ok(e) => e,
            Err(e) => op_fatal!("Failed to parse ip neigh output: {}", e),
        };
        Ok(entries
            .into_iter()
            .filter(|e| e.dev == self.interface)
            .filter_map(|e| e.into_arp_entry())
            .collect())
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        let dev = entry.interface.as_deref().unwrap_or(&self.interface);
        let cmd = format!(
            "ip neigh replace {} lladdr {} dev {} nud permanent",
            entry.address, entry.mac_address, dev
        );
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => op_transient!(e),
        };
        let (code, out) = match client.execute(&cmd).await {
            Ok(r) => r,
            Err(e) => op_transient!(e),
        };
        if code != 0 {
            op_fatal!("ip neigh replace failed ({}): {}", code, out);
        }
        // Linux neighbour entries are keyed by (ip, dev); use the ip as the id
        Ok(ArpEntry {
            id: Some(entry.address.clone()),
            interface: Some(dev.to_string()),
            ..entry.clone()
        })
    }

    async fn remove_arp_entry(&self, id: &str) -> OpResult<()> {
        // `id` is the neighbour IP address (see add_arp_entry)
        let cmd = format!("ip neigh del {} dev {}", id, self.interface);
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => op_transient!(e),
        };
        let (code, out) = match client.execute(&cmd).await {
            Ok(r) => r,
            Err(e) => op_transient!(e),
        };
        if code != 0 {
            op_fatal!("ip neigh del failed ({}): {}", code, out);
        }
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        // `ip neigh replace` is idempotent and handles both add and update
        self.add_arp_entry(entry).await
    }

    fn tunnel(&self) -> Option<&dyn TunnelRouter> {
        Some(self)
    }

    fn bgp(&self) -> Option<&dyn BgpRouter> {
        Some(self)
    }
}

#[async_trait]
impl BgpRouter for LinuxSshRouter {
    async fn list_sessions(&self) -> OpResult<Vec<BgpSession>> {
        let out = self.exec_checked("birdc -r show protocols all").await?;
        Ok(parse_bird_protocols(&out))
    }

    async fn originated_routes(&self, candidates: &[String]) -> OpResult<Vec<BgpRoute>> {
        // Routes locally originated by static protocols. The `where` filter is a
        // single in-memory pass in birdc and the *output* is bounded to our own
        // originated prefixes, so this is safe even with a full table loaded.
        //
        // Restrict to real unicast announcements: static protocols also carry
        // blackhole/unreachable/prohibit "anchor" routes (e.g. discard prefixes
        // and router-id host routes) that are not customer announcements and
        // would otherwise show up as noisy next_hop-less entries in the cache.
        let out = self
            .exec_checked("birdc -r 'show route where source = RTS_STATIC && dest = RTD_UNICAST'")
            .await?;
        let mut routes = parse_bird_routes(&out);
        if !candidates.is_empty() {
            let set: std::collections::HashSet<&str> =
                candidates.iter().map(|s| s.as_str()).collect();
            routes.retain(|r| set.contains(r.prefix.as_str()));
        }
        Ok(routes)
    }

    async fn default_routes(&self) -> OpResult<Vec<BgpRoute>> {
        // `ip ro show default` is independent of BIRD's ACL config and reports
        // the default route(s) actually installed in the kernel, including every
        // ECMP next-hop.
        let v4 = self.exec_checked("ip -4 ro show default").await?;
        let v6 = self.exec_checked("ip -6 ro show default").await?;
        let mut routes = parse_ip_default_routes(&v4);
        routes.extend(parse_ip_default_routes(&v6));
        Ok(routes)
    }

    async fn discover_peers(&self) -> OpResult<Vec<BgpPeer>> {
        let sessions = self.list_sessions().await?;
        Ok(sessions
            .into_iter()
            .map(|s| BgpPeer {
                peer_ip: s.peer_ip,
                asn: s.peer_asn,
                direction: s.direction,
            })
            .collect())
    }

    async fn set_default_route(&self, next_hop: &str) -> OpResult<()> {
        // Infer the family from the next hop; an IPv6 next hop manages `::/0`.
        let is_v6 = next_hop.parse::<std::net::Ipv6Addr>().is_ok();
        let family = if is_v6 { "-6" } else { "-4" };
        // `ip route replace default` installs the route or replaces an existing
        // static default for that family.
        self.exec_checked(&format!(
            "ip {} route replace default via {}",
            family,
            shq(next_hop)
        ))
        .await?;
        Ok(())
    }

    async fn clear_default_route(&self) -> OpResult<()> {
        // Remove both the IPv4 and IPv6 defaults; tolerate a missing route so the
        // operation is idempotent.
        self.exec_checked(
            "sh -c 'ip -4 route del default 2>/dev/null; ip -6 route del default 2>/dev/null; true'",
        )
        .await?;
        Ok(())
    }

    async fn set_session_enabled(&self, id: &str, enabled: bool) -> OpResult<()> {
        let action = if enabled { "enable" } else { "disable" };
        self.exec_checked(&format!("birdc {} {}", action, shq(id)))
            .await?;
        Ok(())
    }
}

/// Map a BIRD/RFC-9234 role string to a peer relationship (best-effort).
fn role_to_direction(role: &str) -> BgpPeerDirection {
    match role.to_ascii_lowercase().as_str() {
        // RFC 9234 role is the *local* role; map to the neighbor relationship.
        // role customer  => neighbor is our provider  => upstream
        // role provider  => neighbor is our customer  => downstream
        "customer" | "rs-client" => BgpPeerDirection::Upstream,
        "provider" | "rs-server" => BgpPeerDirection::Downstream,
        "peer" => BgpPeerDirection::Peer,
        _ => BgpPeerDirection::Unknown,
    }
}

/// Find the value after `key` on a line like `  Key: value` within a block.
fn bird_field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.lines().find_map(|l| {
        let t = l.trim();
        t.strip_prefix(key)
            .map(|rest| rest.trim_start_matches(':').trim())
    })
}

/// Parse `birdc show protocols all` output into BGP sessions.
fn parse_bird_protocols(out: &str) -> Vec<BgpSession> {
    let mut sessions = Vec::new();
    let lines: Vec<&str> = out.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        // Header lines start in column 0
        if line.is_empty() || line.starts_with(char::is_whitespace) {
            i += 1;
            continue;
        }
        if line.starts_with("BIRD") || line.starts_with("Name") {
            i += 1;
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        let name = cols.first().copied().unwrap_or("");
        let proto = cols.get(1).copied().unwrap_or("");
        // Gather following indented detail lines into a block
        let header = line;
        let mut block = String::new();
        i += 1;
        while i < lines.len() && (lines[i].is_empty() || lines[i].starts_with(char::is_whitespace))
        {
            block.push_str(lines[i]);
            block.push('\n');
            i += 1;
        }
        if proto != "BGP" {
            continue;
        }
        let peer_ip = bird_field(&block, "Neighbor address").map(|s| s.to_string());
        let peer_asn = bird_field(&block, "Neighbor AS").and_then(|s| s.parse().ok());
        let local_asn = bird_field(&block, "Local AS").and_then(|s| s.parse().ok());
        let state = bird_field(&block, "BGP state")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let (prefixes_received, prefixes_sent) = parse_bird_routes_stats(&block);
        let direction = bird_field(&block, "Role")
            .map(role_to_direction)
            .unwrap_or_default();
        // A disabled protocol is reported with "disabled" in the header info column
        let enabled = !header.to_ascii_lowercase().contains("disabled");
        sessions.push(BgpSession {
            id: name.to_string(),
            name: name.to_string(),
            peer_ip,
            peer_asn,
            local_asn,
            state,
            prefixes_received,
            prefixes_sent,
            enabled,
            direction,
        });
    }
    sessions
}

/// Extract `(imported, exported)` counts from a `Routes: N imported, M exported`
/// line within a protocol detail block.
fn parse_bird_routes_stats(block: &str) -> (Option<u64>, Option<u64>) {
    for l in block.lines() {
        let t = l.trim();
        if let Some(rest) = t.strip_prefix("Routes:") {
            let mut imported = None;
            let mut exported = None;
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            for w in tokens.windows(2) {
                match w[1].trim_end_matches(',') {
                    "imported" => imported = w[0].parse().ok(),
                    "exported" => exported = w[0].parse().ok(),
                    _ => {}
                }
            }
            return (imported, exported);
        }
    }
    (None, None)
}

/// Parse `ip ro show default` output into routes, one per next-hop.
///
/// Handles both the single-path form:
///   default via 10.0.0.1 dev eth0 proto static metric 100
/// and the ECMP form, where each path is on its own `nexthop via ...` line:
///   default proto static metric 100
///       nexthop via 10.0.0.1 dev eth0 weight 1
///       nexthop via 10.0.0.2 dev eth0 weight 1
///
/// The prefix (`0.0.0.0/0` vs `::/0`) is inferred from each next-hop's family.
fn parse_ip_default_routes(out: &str) -> Vec<BgpRoute> {
    out.lines()
        .filter_map(|line| {
            // Both `default via X` and `nexthop via X` lines contain `via `.
            let via = line.split("via ").nth(1)?.split_whitespace().next()?;
            if via.parse::<std::net::Ipv4Addr>().is_ok() {
                Some(BgpRoute {
                    prefix: "0.0.0.0/0".to_string(),
                    next_hop: Some(via.to_string()),
                })
            } else if via.parse::<std::net::Ipv6Addr>().is_ok() {
                Some(BgpRoute {
                    prefix: "::/0".to_string(),
                    next_hop: Some(via.to_string()),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse `birdc show route` output into routes.
fn parse_bird_routes(out: &str) -> Vec<BgpRoute> {
    let mut routes = Vec::new();
    let mut cur: Option<BgpRoute> = None;
    for line in out.lines() {
        if line.starts_with("BIRD") || line.starts_with("Table") || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            if let Some(r) = cur.take() {
                routes.push(r);
            }
            let prefix = line.split_whitespace().next().unwrap_or("").to_string();
            if prefix.contains('/') {
                cur = Some(BgpRoute {
                    prefix,
                    next_hop: None,
                });
            }
        } else if let Some(rest) = line.trim().strip_prefix("via ") {
            let nh = rest.split_whitespace().next().map(|s| s.to_string());
            if let Some(r) = cur.as_mut().filter(|r| r.next_hop.is_none()) {
                r.next_hop = nh;
            }
        }
    }
    if let Some(r) = cur.take() {
        routes.push(r);
    }
    routes
}

/// Quote a value for safe use inside a single-quoted shell string.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Linux interface kinds we treat as tunnels
fn kind_from_info(info_kind: &str) -> Option<&'static str> {
    match info_kind {
        "gre" | "gretap" => Some("gre"),
        "vxlan" => Some("vxlan"),
        "wireguard" => Some("wireguard"),
        _ => None,
    }
}

/// Parse a GRE key which `ip` may render either as a plain integer or as a
/// dotted-quad (e.g. `"0.0.0.10"`).
fn parse_gre_key(s: &str) -> Option<u32> {
    if let Ok(v) = s.parse::<u32>() {
        return Some(v);
    }
    let octets: Vec<u32> = s.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() == 4 {
        Some((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
    } else {
        None
    }
}

/// `ip` may render a GRE key as a JSON number or a dotted-quad string.
fn value_to_gre_key(v: &serde_json::Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    v.as_str().and_then(parse_gre_key)
}

impl LinuxSshRouter {
    /// Build a [`Tunnel`] from a parsed `ip` link entry, optionally augmented
    /// with WireGuard details from `wg show all dump`.
    fn link_to_tunnel(
        link: &IpLink,
        wg: &std::collections::HashMap<String, WireguardConfig>,
    ) -> Option<Tunnel> {
        let info = link.linkinfo.as_ref()?;
        let mapped = kind_from_info(&info.info_kind)?;
        // Skip the kernel fallback GRE devices (`gre0`, `gretap0`). These are
        // created automatically when the `ip_gre`/`ip_gretap` modules load and
        // are not real configured tunnels.
        if matches!(link.ifname.as_str(), "gre0" | "gretap0") {
            return None;
        }
        let data = info.info_data.clone().unwrap_or_default();
        let enabled = link.flags.iter().any(|f| f == "UP");
        let config = match mapped {
            "gre" => TunnelConfig::Gre(GreConfig {
                key: data.ikey.as_ref().and_then(value_to_gre_key),
            }),
            "vxlan" => TunnelConfig::Vxlan(VxlanConfig {
                vni: data.id.unwrap_or(0),
                dst_port: data.port,
            }),
            "wireguard" => {
                TunnelConfig::Wireguard(wg.get(&link.ifname).cloned().unwrap_or_default())
            }
            _ => return None,
        };
        Some(Tunnel {
            id: Some(link.ifname.clone()),
            name: link.ifname.clone(),
            local_addr: data.local.clone(),
            remote_addr: data.remote.clone(),
            enabled,
            config,
        })
    }
}

#[async_trait]
impl TunnelRouter for LinuxSshRouter {
    async fn list_tunnels(&self) -> OpResult<Vec<Tunnel>> {
        let out = self.exec_checked("ip -s -d -j link show").await?;
        let links: Vec<IpLink> = match serde_json::from_str(&out) {
            Ok(l) => l,
            Err(e) => op_fatal!("Failed to parse ip link output: {}", e),
        };
        // Only query WireGuard if any wg interface exists
        let has_wg = links.iter().any(|l| {
            l.linkinfo
                .as_ref()
                .map(|i| i.info_kind == "wireguard")
                .unwrap_or(false)
        });
        let wg = if has_wg {
            let dump = self.exec_checked("wg show all dump").await?;
            parse_wg_dump(&dump)
        } else {
            std::collections::HashMap::new()
        };
        Ok(links
            .iter()
            .filter_map(|l| Self::link_to_tunnel(l, &wg))
            .collect())
    }

    async fn add_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel> {
        let name = &tunnel.name;
        let mut script = String::new();
        match &tunnel.config {
            TunnelConfig::Gre(c) => {
                script.push_str(&format!("ip link add {} type gre", shq(name)));
                if let Some(l) = &tunnel.local_addr {
                    script.push_str(&format!(" local {}", shq(l)));
                }
                if let Some(r) = &tunnel.remote_addr {
                    script.push_str(&format!(" remote {}", shq(r)));
                }
                if let Some(k) = c.key {
                    script.push_str(&format!(" key {}", k));
                }
            }
            TunnelConfig::Vxlan(c) => {
                script.push_str(&format!(
                    "ip link add {} type vxlan id {}",
                    shq(name),
                    c.vni
                ));
                if let Some(l) = &tunnel.local_addr {
                    script.push_str(&format!(" local {}", shq(l)));
                }
                if let Some(r) = &tunnel.remote_addr {
                    script.push_str(&format!(" remote {}", shq(r)));
                }
                if let Some(p) = c.dst_port {
                    script.push_str(&format!(" dstport {}", p));
                }
            }
            TunnelConfig::Wireguard(c) => {
                script.push_str(&format!("ip link add {} type wireguard", shq(name)));
                script.push_str(&format!(" && {}", wg_set_script(name, c)));
            }
        }
        script.push_str(&format!(" && ip link set {} up", shq(name)));
        self.exec_checked(&format!("sh -c {}", shq(&script)))
            .await?;
        Ok(Tunnel {
            id: Some(name.clone()),
            enabled: true,
            ..tunnel.clone()
        })
    }

    async fn remove_tunnel(&self, id: &str) -> OpResult<()> {
        self.exec_checked(&format!("ip link del {}", shq(id)))
            .await?;
        Ok(())
    }

    async fn update_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel> {
        // Recreate the interface to apply config changes deterministically.
        // `ip link del` is ignored if the interface does not yet exist.
        let _ = self
            .exec_checked(&format!(
                "sh -c {}",
                shq(&format!(
                    "ip link del {} 2>/dev/null; true",
                    shq(&tunnel.name)
                ))
            ))
            .await?;
        self.add_tunnel(tunnel).await
    }

    async fn set_tunnel_enabled(&self, id: &str, enabled: bool) -> OpResult<()> {
        // On Linux the tunnel backend id is the interface name.
        let state = if enabled { "up" } else { "down" };
        self.exec_checked(&format!("ip link set {} {}", shq(id), state))
            .await?;
        Ok(())
    }

    async fn tunnel_traffic(&self) -> OpResult<Vec<TunnelTraffic>> {
        let out = self.exec_checked("ip -s -d -j link show").await?;
        let links: Vec<IpLink> = match serde_json::from_str(&out) {
            Ok(l) => l,
            Err(e) => op_fatal!("Failed to parse ip link output: {}", e),
        };
        Ok(links
            .iter()
            .filter(|l| {
                l.linkinfo
                    .as_ref()
                    .map(|i| kind_from_info(&i.info_kind).is_some())
                    .unwrap_or(false)
            })
            .filter_map(|l| {
                l.stats64.as_ref().map(|s| TunnelTraffic {
                    name: l.ifname.clone(),
                    rx_bytes: s.rx.bytes,
                    tx_bytes: s.tx.bytes,
                })
            })
            .collect())
    }
}

/// Build a `wg set` command chain for a WireGuard interface configuration.
fn wg_set_script(name: &str, c: &WireguardConfig) -> String {
    let mut parts = Vec::new();
    // Private key is written to a 0600 temp file and removed afterwards.
    if let Some(pk) = &c.private_key {
        let mut s = format!(
            "umask 077; f=$(mktemp); printf '%s' {} > \"$f\"; wg set {}",
            shq(pk),
            shq(name)
        );
        if let Some(port) = c.listen_port {
            s.push_str(&format!(" listen-port {}", port));
        }
        s.push_str(" private-key \"$f\"; rm -f \"$f\"");
        parts.push(s);
    } else if let Some(port) = c.listen_port {
        parts.push(format!("wg set {} listen-port {}", shq(name), port));
    }
    for p in &c.peers {
        let mut s = format!("wg set {} peer {}", shq(name), shq(&p.public_key));
        if let Some(e) = &p.endpoint {
            s.push_str(&format!(" endpoint {}", shq(e)));
        }
        if !p.allowed_ips.is_empty() {
            s.push_str(&format!(" allowed-ips {}", shq(&p.allowed_ips.join(","))));
        }
        if let Some(k) = p.persistent_keepalive {
            s.push_str(&format!(" persistent-keepalive {}", k));
        }
        parts.push(s);
    }
    if parts.is_empty() {
        "true".to_string()
    } else {
        parts.join(" && ")
    }
}

/// Parse `wg show all dump` into per-interface WireGuard configs.
fn parse_wg_dump(dump: &str) -> std::collections::HashMap<String, WireguardConfig> {
    let mut map: std::collections::HashMap<String, WireguardConfig> =
        std::collections::HashMap::new();
    // Track which interfaces we've seen the header line for
    let mut seen_header: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in dump.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 2 {
            continue;
        }
        let iface = f[0].to_string();
        if !seen_header.contains(&iface) {
            // Interface header: iface, private-key, public-key, listen-port, fwmark
            seen_header.insert(iface.clone());
            let cfg = map.entry(iface).or_default();
            if f.len() >= 5 {
                cfg.public_key = none_if_marker(f[2]).map(|s| s.to_string());
                cfg.listen_port = f[3].parse().ok();
            }
        } else {
            // Peer line: iface, public-key, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive
            let cfg = map.entry(iface).or_default();
            if f.len() >= 5 {
                let allowed_ips = none_if_marker(f[4])
                    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                    .unwrap_or_default();
                cfg.peers.push(WireguardPeer {
                    public_key: f[1].to_string(),
                    endpoint: none_if_marker(f[3]).map(|s| s.to_string()),
                    allowed_ips,
                    persistent_keepalive: f.get(8).and_then(|v| v.parse().ok()),
                });
            }
        }
    }
    map
}

/// WireGuard dump renders absent values as `(none)` or `off`.
fn none_if_marker(s: &str) -> Option<&str> {
    match s {
        "(none)" | "off" | "" => None,
        other => Some(other),
    }
}

/// One entry from `ip -s -d -j link show`
#[derive(Debug, Clone, Deserialize)]
struct IpLink {
    ifname: String,
    #[serde(default)]
    flags: Vec<String>,
    linkinfo: Option<IpLinkInfo>,
    stats64: Option<IpStats64>,
}

#[derive(Debug, Clone, Deserialize)]
struct IpLinkInfo {
    info_kind: String,
    info_data: Option<IpLinkInfoData>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct IpLinkInfoData {
    local: Option<String>,
    remote: Option<String>,
    /// VXLAN VNI
    id: Option<u32>,
    /// VXLAN UDP port
    port: Option<u16>,
    /// GRE input key (number or dotted-quad string)
    ikey: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct IpStats64 {
    rx: IpStatsDir,
    tx: IpStatsDir,
}

#[derive(Debug, Clone, Deserialize)]
struct IpStatsDir {
    bytes: u64,
}

/// One entry from `ip -j neigh show`
#[derive(Debug, Clone, Deserialize)]
struct IpNeighEntry {
    dst: String,
    dev: String,
    lladdr: Option<String>,
}

impl IpNeighEntry {
    /// Convert into an [`ArpEntry`], dropping entries without a resolved MAC
    /// (e.g. `FAILED`/`INCOMPLETE` neighbours).
    fn into_arp_entry(self) -> Option<ArpEntry> {
        let mac = self.lladdr?;
        Some(ArpEntry {
            id: Some(self.dst.clone()),
            address: self.dst,
            mac_address: mac,
            interface: Some(self.dev),
            comment: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_parses_url() -> Result<()> {
        let r = LinuxSshRouter::new("ssh://admin@10.0.0.1:2222/vmbr0", "KEY")?;
        assert_eq!(r.host, "10.0.0.1:2222");
        assert_eq!(r.username, "admin");
        assert_eq!(r.interface, "vmbr0");
        assert_eq!(r.key, "KEY");
        Ok(())
    }

    #[test]
    fn test_new_defaults() -> Result<()> {
        let r = LinuxSshRouter::new("ssh://10.0.0.1/eth0", "K")?;
        assert_eq!(r.host, "10.0.0.1:22");
        assert_eq!(r.username, "root");
        assert_eq!(r.interface, "eth0");
        Ok(())
    }

    #[test]
    fn test_new_rejects_bad_input() {
        assert!(LinuxSshRouter::new("http://10.0.0.1/eth0", "K").is_err());
        assert!(LinuxSshRouter::new("ssh://10.0.0.1", "K").is_err());
        assert!(LinuxSshRouter::new("ssh://10.0.0.1/", "K").is_err());
    }

    #[test]
    fn test_parse_gre_key() {
        assert_eq!(parse_gre_key("10"), Some(10));
        assert_eq!(parse_gre_key("0.0.0.10"), Some(10));
        assert_eq!(parse_gre_key("0.0.1.0"), Some(256));
        assert_eq!(parse_gre_key("garbage"), None);
        assert_eq!(value_to_gre_key(&serde_json::json!(42)), Some(42));
        assert_eq!(value_to_gre_key(&serde_json::json!("0.0.0.5")), Some(5));
    }

    #[test]
    fn test_shq_escaping() {
        assert_eq!(shq("eth0"), "'eth0'");
        assert_eq!(shq("a'b"), "'a'\\''b'");
    }

    #[test]
    fn test_link_to_tunnel_gre_vxlan() {
        let json = r#"[
            {"ifname":"gre1","flags":["POINTOPOINT","UP"],"linkinfo":{"info_kind":"gre","info_data":{"local":"10.0.0.1","remote":"10.0.0.2","ikey":"0.0.0.7"}},"stats64":{"rx":{"bytes":100},"tx":{"bytes":200}}},
            {"ifname":"vx1","flags":["UP"],"linkinfo":{"info_kind":"vxlan","info_data":{"id":42,"local":"10.0.0.1","remote":"10.0.0.3","port":4789}}},
            {"ifname":"eth0","flags":["UP"]}
        ]"#;
        let links: Vec<IpLink> = serde_json::from_str(json).unwrap();
        let wg = std::collections::HashMap::new();
        let tuns: Vec<Tunnel> = links
            .iter()
            .filter_map(|l| LinuxSshRouter::link_to_tunnel(l, &wg))
            .collect();
        assert_eq!(tuns.len(), 2);
        let gre = &tuns[0];
        assert_eq!(gre.name, "gre1");
        assert!(gre.enabled);
        assert_eq!(gre.local_addr.as_deref(), Some("10.0.0.1"));
        match &gre.config {
            TunnelConfig::Gre(c) => assert_eq!(c.key, Some(7)),
            _ => panic!("expected gre"),
        }
        match &tuns[1].config {
            TunnelConfig::Vxlan(c) => {
                assert_eq!(c.vni, 42);
                assert_eq!(c.dst_port, Some(4789));
            }
            _ => panic!("expected vxlan"),
        }
    }

    #[test]
    fn test_parse_wg_dump() {
        let dump = "wg0\tPRIVKEY\tPUBKEY\t51820\toff\n\
 wg0\tPEERPUB\t(none)\t1.2.3.4:51820\t10.0.0.0/24,10.0.1.0/24\t1700000000\t1024\t2048\t25\n"
            .replace(" wg0", "wg0");
        let map = parse_wg_dump(&dump);
        let cfg = map.get("wg0").unwrap();
        assert_eq!(cfg.public_key.as_deref(), Some("PUBKEY"));
        assert_eq!(cfg.listen_port, Some(51820));
        assert_eq!(cfg.peers.len(), 1);
        let p = &cfg.peers[0];
        assert_eq!(p.public_key, "PEERPUB");
        assert_eq!(p.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(p.allowed_ips, vec!["10.0.0.0/24", "10.0.1.0/24"]);
        assert_eq!(p.persistent_keepalive, Some(25));
    }

    #[test]
    fn test_wg_set_script() {
        let c = WireguardConfig {
            listen_port: Some(51820),
            private_key: Some("KEY".to_string()),
            public_key: None,
            peers: vec![WireguardPeer {
                public_key: "PUB".to_string(),
                endpoint: Some("1.2.3.4:51820".to_string()),
                allowed_ips: vec!["10.0.0.0/24".to_string()],
                persistent_keepalive: Some(25),
            }],
        };
        let s = wg_set_script("wg0", &c);
        assert!(s.contains("listen-port 51820"));
        assert!(s.contains("private-key"));
        assert!(s.contains("peer 'PUB'"));
        assert!(s.contains("allowed-ips '10.0.0.0/24'"));
        assert!(s.contains("persistent-keepalive 25"));
    }

    #[test]
    fn test_traffic_filters_non_tunnels() {
        let json = r#"[
            {"ifname":"gre1","flags":["UP"],"linkinfo":{"info_kind":"gre"},"stats64":{"rx":{"bytes":5},"tx":{"bytes":6}}},
            {"ifname":"eth0","flags":["UP"],"stats64":{"rx":{"bytes":1},"tx":{"bytes":2}}}
        ]"#;
        let links: Vec<IpLink> = serde_json::from_str(json).unwrap();
        let traffic: Vec<TunnelTraffic> = links
            .iter()
            .filter(|l| {
                l.linkinfo
                    .as_ref()
                    .map(|i| kind_from_info(&i.info_kind).is_some())
                    .unwrap_or(false)
            })
            .filter_map(|l| {
                l.stats64.as_ref().map(|s| TunnelTraffic {
                    name: l.ifname.clone(),
                    rx_bytes: s.rx.bytes,
                    tx_bytes: s.tx.bytes,
                })
            })
            .collect();
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].name, "gre1");
        assert_eq!(traffic[0].rx_bytes, 5);
    }

    #[test]
    fn test_parse_bird_protocols() {
        let out = [
            "BIRD 2.0.7 ready.",
            "Name       Proto      Table      State  Since         Info",
            "device1    Device     ---        up     2024-06-01    ",
            "bgp1       BGP        ---        up     2024-06-01    Established",
            "  BGP state:          Established",
            "    Neighbor address: 192.0.2.1",
            "    Neighbor AS:      64512",
            "    Local AS:         64500",
            "    Role:             customer",
            "  Channel ipv4",
            "    Routes:         5 imported, 2 exported, 3 preferred",
            "bgp2       BGP        ---        down   2024-06-01    disabled",
            "  BGP state:          Idle",
            "    Neighbor address: 192.0.2.5",
            "    Neighbor AS:      64600",
        ]
        .join("\n");
        let sessions = parse_bird_protocols(&out);
        assert_eq!(sessions.len(), 2);
        let s = &sessions[0];
        assert_eq!(s.name, "bgp1");
        assert_eq!(s.peer_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(s.peer_asn, Some(64512));
        assert_eq!(s.local_asn, Some(64500));
        assert_eq!(s.state, "Established");
        assert_eq!(s.prefixes_received, Some(5));
        assert_eq!(s.prefixes_sent, Some(2));
        assert_eq!(s.direction, BgpPeerDirection::Upstream);
        assert!(s.enabled);

        let s2 = &sessions[1];
        assert_eq!(s2.name, "bgp2");
        assert_eq!(s2.state, "Idle");
        assert!(!s2.enabled);
        assert_eq!(s2.direction, BgpPeerDirection::Unknown);
    }

    #[test]
    fn test_parse_bird_routes() {
        let out = [
            "BIRD 2.0.7 ready.",
            "Table master4:",
            "198.51.100.0/24      unicast [static1 2024-06-01] * (200)",
            "\tvia 192.0.2.1 on eth0",
            "203.0.113.0/24       unicast [static1 2024-06-01] * (200)",
            "\tdev eth0",
        ]
        .join("\n");
        let routes = parse_bird_routes(&out);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].prefix, "198.51.100.0/24");
        assert_eq!(routes[0].next_hop.as_deref(), Some("192.0.2.1"));
        assert_eq!(routes[1].prefix, "203.0.113.0/24");
        assert_eq!(routes[1].next_hop, None);
    }

    #[test]
    fn test_parse_ip_default_routes_single() {
        let out = "default via 10.0.0.1 dev eth0 proto static metric 100";
        let routes = parse_ip_default_routes(out);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "0.0.0.0/0");
        assert_eq!(routes[0].next_hop.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_parse_ip_default_routes_ecmp() {
        let out = [
            "default proto static metric 100",
            "\tnexthop via 10.0.0.1 dev eth0 weight 1",
            "\tnexthop via 10.0.0.2 dev eth1 weight 1",
        ]
        .join("\n");
        let routes = parse_ip_default_routes(&out);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].next_hop.as_deref(), Some("10.0.0.1"));
        assert_eq!(routes[1].next_hop.as_deref(), Some("10.0.0.2"));
        assert!(routes.iter().all(|r| r.prefix == "0.0.0.0/0"));
    }

    #[test]
    fn test_parse_ip_default_routes_v6() {
        let out = "default via fe80::1 dev eth0 proto static metric 1024";
        let routes = parse_ip_default_routes(out);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, "::/0");
        assert_eq!(routes[0].next_hop.as_deref(), Some("fe80::1"));
    }

    #[test]
    fn test_parse_ip_default_routes_empty() {
        assert!(parse_ip_default_routes("").is_empty());
        // A directly-connected default (no `via`) yields no next-hop entry.
        assert!(parse_ip_default_routes("default dev wg0 scope link").is_empty());
    }

    #[test]
    fn test_role_to_direction() {
        assert_eq!(role_to_direction("customer"), BgpPeerDirection::Upstream);
        assert_eq!(role_to_direction("provider"), BgpPeerDirection::Downstream);
        assert_eq!(role_to_direction("peer"), BgpPeerDirection::Peer);
        assert_eq!(role_to_direction("rs-client"), BgpPeerDirection::Upstream);
        assert_eq!(role_to_direction("weird"), BgpPeerDirection::Unknown);
    }

    #[test]
    fn test_neigh_parse_filters_no_mac() {
        let json = r#"[
            {"dst":"10.0.0.5","dev":"vmbr0","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]},
            {"dst":"10.0.0.6","dev":"vmbr0","state":["FAILED"]}
        ]"#;
        let entries: Vec<IpNeighEntry> = serde_json::from_str(json).unwrap();
        let arp: Vec<ArpEntry> = entries
            .into_iter()
            .filter_map(|e| e.into_arp_entry())
            .collect();
        assert_eq!(arp.len(), 1);
        assert_eq!(arp[0].address, "10.0.0.5");
        assert_eq!(arp[0].mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(arp[0].id.as_deref(), Some("10.0.0.5"));
    }
}
