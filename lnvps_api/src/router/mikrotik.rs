use crate::router::{
    ArpEntry, BgpPeer, BgpPeerDirection, BgpRoute, BgpRouter, BgpSession, GreConfig, Router,
    Tunnel, TunnelConfig, TunnelKind, TunnelRouter, TunnelTraffic, VxlanConfig, WireguardConfig,
    WireguardPeer,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lnvps_api_common::JsonApi;
use lnvps_api_common::op_fatal;
use lnvps_api_common::retry::{OpError, OpResult};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub struct MikrotikRouter {
    api: JsonApi,
}

impl MikrotikRouter {
    pub fn new(url: &str, username: &str, password: &str) -> Self {
        let auth = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", username, password))
        );
        Self {
            api: JsonApi::token(url, &auth, true).unwrap(),
        }
    }
}

#[async_trait]
impl Router for MikrotikRouter {
    async fn generate_mac(&self, _ip: &str, _comment: &str) -> Result<Option<ArpEntry>> {
        // Mikrotik router doesn't care what MAC address you use
        Ok(None)
    }

    async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>> {
        let rsp: Vec<MikrotikArpEntry> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/ip/arp", None)
            .await?;
        Ok(rsp.into_iter().filter_map(|e| e.try_into().ok()).collect())
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        let req: MikrotikArpEntry = entry.clone().into();
        let rsp: MikrotikArpEntry = self.api.req(Method::PUT, "/rest/ip/arp", Some(req)).await?;
        rsp.try_into().map_err(OpError::Fatal)
    }

    async fn remove_arp_entry(&self, id: &str) -> OpResult<()> {
        let _rsp: MikrotikArpEntry = self
            .api
            .req::<_, ()>(Method::DELETE, &format!("/rest/ip/arp/{}", id), None)
            .await?;
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        if entry.id.is_none() {
            op_fatal!("Cannot update an arp entry without ID");
        }
        let req: MikrotikArpEntry = entry.clone().into();
        let rsp: MikrotikArpEntry = self
            .api
            .req(
                Method::PATCH,
                &format!("/rest/ip/arp/{}", entry.id.as_ref().unwrap()),
                Some(req),
            )
            .await?;
        rsp.try_into().map_err(OpError::Fatal)
    }

    fn tunnel(&self) -> Option<&dyn TunnelRouter> {
        Some(self)
    }

    fn bgp(&self) -> Option<&dyn BgpRouter> {
        Some(self)
    }
}

#[async_trait]
impl BgpRouter for MikrotikRouter {
    async fn list_sessions(&self) -> OpResult<Vec<BgpSession>> {
        let connections: Vec<MtBgpConnection> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/routing/bgp/connection", None)
            .await?;
        let sessions: Vec<MtBgpSession> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/routing/bgp/session", None)
            .await?;
        Ok(connections
            .into_iter()
            .map(|c| {
                let live = sessions.iter().find(|s| s.name.as_deref() == Some(&c.name));
                let established = live
                    .map(|s| matches!(s.established.as_deref(), Some("true") | Some("yes")))
                    .unwrap_or(false);
                BgpSession {
                    id: c.id.clone().unwrap_or_default(),
                    name: c.name.clone(),
                    peer_ip: live
                        .and_then(|s| s.remote_address.clone())
                        .or(c.remote_address),
                    peer_asn: live
                        .and_then(|s| s.remote_as.as_deref())
                        .or(c.remote_as.as_deref())
                        .and_then(|s| s.parse().ok()),
                    local_asn: c.local_as.and_then(|s| s.parse().ok()),
                    state: if established {
                        "Established".to_string()
                    } else {
                        "Idle".to_string()
                    },
                    prefixes_received: live
                        .and_then(|s| s.prefix_count.as_deref())
                        .and_then(|s| s.parse().ok()),
                    prefixes_sent: None,
                    enabled: mt_enabled(&c.disabled),
                    direction: BgpPeerDirection::Unknown,
                }
            })
            .collect())
    }

    async fn originated_routes(&self, candidates: &[String]) -> OpResult<Vec<BgpRoute>> {
        // IMPORTANT: never `GET /rest/ip/route` unfiltered — on a full-table router
        // that returns hundreds of MB of JSON. Query each candidate prefix with a
        // server-side `dst-address` filter and a trimmed proplist instead.
        let mut out = Vec::new();
        for prefix in candidates {
            let path = format!(
                "/rest/ip/route?dst-address={}&.proplist=dst-address,gateway,bgp",
                prefix
            );
            let routes: Vec<MtRoute> = self
                .api
                .req::<_, ()>(Method::GET, &path, None)
                .await
                .unwrap_or_default();
            for r in routes {
                if let Some(dst) = r.dst_address {
                    out.push(BgpRoute {
                        prefix: dst,
                        next_hop: r.gateway,
                    });
                }
            }
        }
        Ok(out)
    }

    async fn default_routes(&self) -> OpResult<Vec<BgpRoute>> {
        // Filter server-side; do not fetch the whole table. Collect every default
        // route across both families so ECMP next-hops are all reported.
        let mut out = Vec::new();
        for dst in ["0.0.0.0/0", "::/0"] {
            let path = format!(
                "/rest/ip/route?dst-address={}&.proplist=dst-address,gateway",
                dst
            );
            let routes: Vec<MtRoute> = self.api.req::<_, ()>(Method::GET, &path, None).await?;
            out.extend(routes.into_iter().map(|r| BgpRoute {
                prefix: r.dst_address.unwrap_or_else(|| dst.to_string()),
                next_hop: r.gateway,
            }));
        }
        Ok(out)
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
        let (menu, dst) = if is_v6 {
            ("ipv6", "::/0")
        } else {
            ("ip", "0.0.0.0/0")
        };
        // Replace an existing static default for this family, else add a new one.
        let existing: Vec<MtRouteId> = self
            .api
            .req::<_, ()>(
                Method::GET,
                &format!("/rest/{}/route?dst-address={}&.proplist=.id", menu, dst),
                None,
            )
            .await
            .unwrap_or_default();
        if let Some(id) = existing.into_iter().find_map(|r| r.id) {
            let _: serde_json::Value = self
                .api
                .req(
                    Method::PATCH,
                    &format!("/rest/{}/route/{}", menu, id),
                    Some(json!({ "gateway": next_hop })),
                )
                .await?;
        } else {
            let _: serde_json::Value = self
                .api
                .req(
                    Method::POST,
                    &format!("/rest/{}/route", menu),
                    Some(json!({ "dst-address": dst, "gateway": next_hop })),
                )
                .await?;
        }
        Ok(())
    }

    async fn clear_default_route(&self) -> OpResult<()> {
        for (menu, dst) in [("ip", "0.0.0.0/0"), ("ipv6", "::/0")] {
            let existing: Vec<MtRouteId> = self
                .api
                .req::<_, ()>(
                    Method::GET,
                    &format!("/rest/{}/route?dst-address={}&.proplist=.id", menu, dst),
                    None,
                )
                .await
                .unwrap_or_default();
            for id in existing.into_iter().filter_map(|r| r.id) {
                self.api
                    .req_status::<()>(
                        Method::DELETE,
                        &format!("/rest/{}/route/{}", menu, id),
                        None,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn set_session_enabled(&self, id: &str, enabled: bool) -> OpResult<()> {
        let body = json!({ "disabled": (!enabled).to_string() });
        let _: serde_json::Value = self
            .api
            .req(
                Method::PATCH,
                &format!("/rest/routing/bgp/connection/{}", id),
                Some(body),
            )
            .await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct MtBgpConnection {
    #[serde(rename = ".id")]
    id: Option<String>,
    name: String,
    #[serde(rename = "remote.address")]
    remote_address: Option<String>,
    #[serde(rename = "remote.as")]
    remote_as: Option<String>,
    #[serde(rename = "local.as")]
    local_as: Option<String>,
    disabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtBgpSession {
    name: Option<String>,
    #[serde(rename = "remote.address")]
    remote_address: Option<String>,
    #[serde(rename = "remote.as")]
    remote_as: Option<String>,
    established: Option<String>,
    #[serde(rename = "prefix-count")]
    prefix_count: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtRoute {
    #[serde(rename = "dst-address")]
    dst_address: Option<String>,
    gateway: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtRouteId {
    #[serde(rename = ".id")]
    id: Option<String>,
}

/// RouterOS REST menu path for a tunnel kind
fn tunnel_endpoint(kind: TunnelKind) -> &'static str {
    match kind {
        TunnelKind::Gre => "gre",
        TunnelKind::Vxlan => "vxlan",
        TunnelKind::Wireguard => "wireguard",
    }
}

/// RouterOS renders booleans as the strings "true"/"false"; an interface is
/// enabled when it is not disabled.
fn mt_enabled(disabled: &Option<String>) -> bool {
    !matches!(disabled.as_deref(), Some("true") | Some("yes"))
}

#[async_trait]
impl TunnelRouter for MikrotikRouter {
    async fn list_tunnels(&self) -> OpResult<Vec<Tunnel>> {
        let mut out = Vec::new();

        let gres: Vec<MtGre> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/interface/gre", None)
            .await?;
        for g in gres {
            out.push(Tunnel {
                id: Some(format!("gre:{}", g.id.clone().unwrap_or_default())),
                name: g.name,
                local_addr: g.local_address,
                remote_addr: g.remote_address,
                enabled: mt_enabled(&g.disabled),
                config: TunnelConfig::Gre(GreConfig::default()),
            });
        }

        let vxlans: Vec<MtVxlan> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/interface/vxlan", None)
            .await?;
        for v in vxlans {
            out.push(Tunnel {
                id: Some(format!("vxlan:{}", v.id.clone().unwrap_or_default())),
                name: v.name,
                local_addr: v.local_address,
                remote_addr: None,
                enabled: mt_enabled(&v.disabled),
                config: TunnelConfig::Vxlan(VxlanConfig {
                    vni: v.vni.and_then(|s| s.parse().ok()).unwrap_or(0),
                    dst_port: v.port.and_then(|s| s.parse().ok()),
                }),
            });
        }

        let wgs: Vec<MtWireguard> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/interface/wireguard", None)
            .await?;
        if !wgs.is_empty() {
            let peers: Vec<MtWgPeer> = self
                .api
                .req::<_, ()>(Method::GET, "/rest/interface/wireguard/peers", None)
                .await?;
            for w in wgs {
                let cfg = WireguardConfig {
                    listen_port: w.listen_port.and_then(|s| s.parse().ok()),
                    private_key: None, // never return secrets when listing
                    public_key: w.public_key,
                    peers: peers
                        .iter()
                        .filter(|p| p.interface.as_deref() == Some(&w.name))
                        .map(|p| WireguardPeer {
                            public_key: p.public_key.clone().unwrap_or_default(),
                            endpoint: p.endpoint(),
                            allowed_ips: p
                                .allowed_address
                                .as_deref()
                                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                                .unwrap_or_default(),
                            persistent_keepalive: p.keepalive_secs(),
                        })
                        .collect(),
                };
                out.push(Tunnel {
                    id: Some(format!("wireguard:{}", w.id.clone().unwrap_or_default())),
                    name: w.name,
                    local_addr: None,
                    remote_addr: None,
                    enabled: mt_enabled(&w.disabled),
                    config: TunnelConfig::Wireguard(cfg),
                });
            }
        }

        Ok(out)
    }

    async fn add_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel> {
        let endpoint = tunnel_endpoint(tunnel.kind());
        let path = format!("/rest/interface/{}", endpoint);
        let created: MtCreated = match &tunnel.config {
            TunnelConfig::Gre(_) => {
                let body = json!({
                    "name": tunnel.name,
                    "local-address": tunnel.local_addr,
                    "remote-address": tunnel.remote_addr,
                });
                self.api.req(Method::PUT, &path, Some(body)).await?
            }
            TunnelConfig::Vxlan(c) => {
                let body = json!({
                    "name": tunnel.name,
                    "vni": c.vni.to_string(),
                    "port": c.dst_port.map(|p| p.to_string()),
                    "local-address": tunnel.local_addr,
                });
                self.api.req(Method::PUT, &path, Some(body)).await?
            }
            TunnelConfig::Wireguard(c) => {
                let body = json!({
                    "name": tunnel.name,
                    "listen-port": c.listen_port.map(|p| p.to_string()),
                    "private-key": c.private_key,
                });
                let created: MtCreated = self.api.req(Method::PUT, &path, Some(body)).await?;
                for p in &c.peers {
                    let (ep_addr, ep_port) = split_endpoint(p.endpoint.as_deref());
                    let pbody = json!({
                        "interface": tunnel.name,
                        "public-key": p.public_key,
                        "endpoint-address": ep_addr,
                        "endpoint-port": ep_port,
                        "allowed-address": if p.allowed_ips.is_empty() { None } else { Some(p.allowed_ips.join(",")) },
                        "persistent-keepalive": p.persistent_keepalive.map(|k| k.to_string()),
                    });
                    let _: MtCreated = self
                        .api
                        .req(Method::PUT, "/rest/interface/wireguard/peers", Some(pbody))
                        .await?;
                }
                created
            }
        };
        Ok(Tunnel {
            id: Some(format!("{}:{}", endpoint, created.id.unwrap_or_default())),
            enabled: true,
            ..tunnel.clone()
        })
    }

    async fn remove_tunnel(&self, id: &str) -> OpResult<()> {
        let (endpoint, ros_id) = split_tunnel_id(id)?;
        let _: serde_json::Value = self
            .api
            .req::<_, ()>(
                Method::DELETE,
                &format!("/rest/interface/{}/{}", endpoint, ros_id),
                None,
            )
            .await
            .or_else(|e| match e {
                // DELETE returns an empty body which fails JSON parsing; treat as success
                OpError::Fatal(_) => Ok(serde_json::Value::Null),
                other => Err(other),
            })?;
        Ok(())
    }

    async fn update_tunnel(&self, tunnel: &Tunnel) -> OpResult<Tunnel> {
        let id = tunnel
            .id
            .as_deref()
            .ok_or_else(|| OpError::Fatal(anyhow::anyhow!("update_tunnel requires an id")))?;
        let (endpoint, ros_id) = split_tunnel_id(id)?;
        let path = format!("/rest/interface/{}/{}", endpoint, ros_id);
        let body = match &tunnel.config {
            TunnelConfig::Gre(_) => json!({
                "local-address": tunnel.local_addr,
                "remote-address": tunnel.remote_addr,
                "disabled": (!tunnel.enabled).to_string(),
            }),
            TunnelConfig::Vxlan(c) => json!({
                "vni": c.vni.to_string(),
                "port": c.dst_port.map(|p| p.to_string()),
                "local-address": tunnel.local_addr,
                "disabled": (!tunnel.enabled).to_string(),
            }),
            TunnelConfig::Wireguard(c) => json!({
                "listen-port": c.listen_port.map(|p| p.to_string()),
                "disabled": (!tunnel.enabled).to_string(),
            }),
        };
        let _: serde_json::Value = self.api.req(Method::PATCH, &path, Some(body)).await?;
        Ok(tunnel.clone())
    }

    async fn set_tunnel_enabled(&self, id: &str, enabled: bool) -> OpResult<()> {
        let (endpoint, ros_id) = split_tunnel_id(id)?;
        let body = json!({ "disabled": (!enabled).to_string() });
        let _: serde_json::Value = self
            .api
            .req(
                Method::PATCH,
                &format!("/rest/interface/{}/{}", endpoint, ros_id),
                Some(body),
            )
            .await?;
        Ok(())
    }

    async fn tunnel_traffic(&self) -> OpResult<Vec<TunnelTraffic>> {
        let ifaces: Vec<MtInterface> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/interface", None)
            .await?;
        Ok(ifaces
            .into_iter()
            .filter(|i| matches!(i.kind.as_deref(), Some("gre") | Some("vxlan") | Some("wg")))
            .map(|i| TunnelTraffic {
                name: i.name,
                rx_bytes: i.rx_byte.and_then(|s| s.parse().ok()).unwrap_or(0),
                tx_bytes: i.tx_byte.and_then(|s| s.parse().ok()).unwrap_or(0),
            })
            .collect())
    }
}

/// Split a tunnel id of the form `"<endpoint>:<ros_id>"`.
fn split_tunnel_id(id: &str) -> OpResult<(&str, &str)> {
    match id.split_once(':') {
        Some((endpoint @ ("gre" | "vxlan" | "wireguard"), ros_id)) => Ok((endpoint, ros_id)),
        _ => Err(OpError::Fatal(anyhow::anyhow!(
            "Invalid mikrotik tunnel id: {}",
            id
        ))),
    }
}

/// Split a `host:port` endpoint into separate address/port components.
fn split_endpoint(ep: Option<&str>) -> (Option<String>, Option<String>) {
    match ep.and_then(|e| e.rsplit_once(':')) {
        Some((addr, port)) => (Some(addr.to_string()), Some(port.to_string())),
        None => (ep.map(|s| s.to_string()), None),
    }
}

#[derive(Debug, Deserialize)]
struct MtCreated {
    #[serde(rename = ".id")]
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtGre {
    #[serde(rename = ".id")]
    id: Option<String>,
    name: String,
    #[serde(rename = "local-address")]
    local_address: Option<String>,
    #[serde(rename = "remote-address")]
    remote_address: Option<String>,
    disabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtVxlan {
    #[serde(rename = ".id")]
    id: Option<String>,
    name: String,
    vni: Option<String>,
    port: Option<String>,
    #[serde(rename = "local-address")]
    local_address: Option<String>,
    disabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtWireguard {
    #[serde(rename = ".id")]
    id: Option<String>,
    name: String,
    #[serde(rename = "listen-port")]
    listen_port: Option<String>,
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    disabled: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MtWgPeer {
    interface: Option<String>,
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    #[serde(rename = "endpoint-address")]
    endpoint_address: Option<String>,
    #[serde(rename = "endpoint-port")]
    endpoint_port: Option<String>,
    #[serde(rename = "allowed-address")]
    allowed_address: Option<String>,
    #[serde(rename = "persistent-keepalive")]
    persistent_keepalive: Option<String>,
}

impl MtWgPeer {
    /// Combine RouterOS endpoint-address/endpoint-port into a `host:port` string.
    fn endpoint(&self) -> Option<String> {
        match (&self.endpoint_address, &self.endpoint_port) {
            (Some(a), Some(p)) if !a.is_empty() => Some(format!("{}:{}", a, p)),
            (Some(a), None) if !a.is_empty() => Some(a.clone()),
            _ => None,
        }
    }

    /// RouterOS renders persistent-keepalive as a duration string (e.g. "25s" or
    /// "00:00:25"); extract the seconds component best-effort.
    fn keepalive_secs(&self) -> Option<u16> {
        let v = self.persistent_keepalive.as_deref()?;
        if let Some(stripped) = v.strip_suffix('s') {
            return stripped.parse().ok();
        }
        // hh:mm:ss form
        if let Some(sec) = v.rsplit(':').next() {
            return sec.parse().ok();
        }
        v.parse().ok()
    }
}

#[derive(Debug, Deserialize)]
struct MtInterface {
    name: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(rename = "rx-byte")]
    rx_byte: Option<String>,
    #[serde(rename = "tx-byte")]
    tx_byte: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MikrotikArpEntry {
    #[serde(rename = ".id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "mac-address")]
    pub mac_address: Option<String>,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl TryFrom<MikrotikArpEntry> for ArpEntry {
    type Error = anyhow::Error;

    fn try_from(value: MikrotikArpEntry) -> std::result::Result<Self, Self::Error> {
        Ok(ArpEntry {
            id: value.id,
            address: value.address,
            mac_address: value.mac_address.context("Mac address is empty")?,
            interface: Some(value.interface),
            comment: value.comment,
        })
    }
}

impl From<ArpEntry> for MikrotikArpEntry {
    fn from(val: ArpEntry) -> Self {
        MikrotikArpEntry {
            id: val.id,
            address: val.address,
            mac_address: Some(val.mac_address),
            interface: val.interface.unwrap(),
            comment: val.comment,
        }
    }
}

#[cfg(test)]
mod tunnel_tests {
    use super::*;

    #[test]
    fn test_mt_enabled() {
        assert!(mt_enabled(&None));
        assert!(mt_enabled(&Some("false".to_string())));
        assert!(!mt_enabled(&Some("true".to_string())));
        assert!(!mt_enabled(&Some("yes".to_string())));
    }

    #[test]
    fn test_tunnel_endpoint() {
        assert_eq!(tunnel_endpoint(TunnelKind::Gre), "gre");
        assert_eq!(tunnel_endpoint(TunnelKind::Vxlan), "vxlan");
        assert_eq!(tunnel_endpoint(TunnelKind::Wireguard), "wireguard");
    }

    #[test]
    fn test_split_tunnel_id() {
        assert_eq!(split_tunnel_id("gre:*1").unwrap(), ("gre", "*1"));
        assert_eq!(
            split_tunnel_id("wireguard:*A").unwrap(),
            ("wireguard", "*A")
        );
        assert!(split_tunnel_id("bogus:*1").is_err());
        assert!(split_tunnel_id("noseparator").is_err());
    }

    #[test]
    fn test_split_endpoint() {
        assert_eq!(
            split_endpoint(Some("1.2.3.4:51820")),
            (Some("1.2.3.4".to_string()), Some("51820".to_string()))
        );
        assert_eq!(
            split_endpoint(Some("host")),
            (Some("host".to_string()), None)
        );
        assert_eq!(split_endpoint(None), (None, None));
    }

    #[test]
    fn test_wg_peer_endpoint_and_keepalive() {
        let p = MtWgPeer {
            interface: Some("wg0".to_string()),
            public_key: Some("PUB".to_string()),
            endpoint_address: Some("1.2.3.4".to_string()),
            endpoint_port: Some("51820".to_string()),
            allowed_address: Some("10.0.0.0/24,10.0.1.0/24".to_string()),
            persistent_keepalive: Some("25s".to_string()),
        };
        assert_eq!(p.endpoint().as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(p.keepalive_secs(), Some(25));

        let p2 = MtWgPeer {
            persistent_keepalive: Some("00:00:30".to_string()),
            endpoint_address: None,
            endpoint_port: None,
            ..p
        };
        assert_eq!(p2.keepalive_secs(), Some(30));
        assert_eq!(p2.endpoint(), None);
    }
}
