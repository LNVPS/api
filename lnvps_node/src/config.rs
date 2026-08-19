//! Node daemon configuration.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::credential::CredentialConfig;

/// Everything the daemon needs to start.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NodeConfig {
    /// Base URL of the LNVPS user API, e.g. `https://api.lnvps.net`.
    ///
    /// The node calls this outbound to register and to send heartbeats. It is
    /// separate from the inbound control listener below because the two run in
    /// opposite directions and at different stages: registration happens before
    /// any tunnel exists.
    pub api_url: String,

    /// The operator's credential; the node authenticates as their account.
    pub credential: CredentialConfig,

    /// Inbound control API. Absent until the node is paired and its tunnel is
    /// up — there is no address to bind to before then.
    #[serde(default)]
    pub control: Option<ControlConfig>,

    /// Where the daemon keeps its state (assigned node id, tunnel key).
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,

    /// Seconds between heartbeats.
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
}

/// The inbound control API LNVPS uses to drive this node.
///
/// **Direction:** LNVPS dials the node, not the other way round. Commands are
/// request/response with a result to report — start a VM, stop a VM — which is
/// what HTTP already is. A persistent socket would mean rebuilding correlation
/// ids, in-flight replay and reconnect semantics to get back to the same thing.
/// The outbound-only design that a websocket buys is unnecessary here: once the
/// WireGuard tunnel is up, LNVPS can reach the node directly, and the node is
/// useless without that tunnel anyway. This also matches `lnvps_fw`, so the
/// operational model is one model rather than two.
///
/// **Authentication** is NIP-98 against a public key compiled into the binary
/// (see [`crate::control_auth`]) — there is no token here to provision, rotate
/// or leak.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ControlConfig {
    /// Address to bind. Must be an address of [`tunnel_interface`](Self::tunnel_interface):
    /// see [`validate_listen_address`].
    pub listen: IpAddr,

    /// Port to bind.
    #[serde(default = "default_control_port")]
    pub port: u16,

    /// The WireGuard interface whose address `listen` must belong to.
    #[serde(default = "default_tunnel_interface")]
    pub tunnel_interface: String,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/lnvps-node")
}

fn default_heartbeat_secs() -> u64 {
    60
}

fn default_control_port() -> u16 {
    // The filter opens this port on the tunnel interface; a listener anywhere
    // else is one LNVPS cannot reach.
    crate::fw::CONTROL_PORT
}

fn default_tunnel_interface() -> String {
    crate::net::TUNNEL_INTERFACE.to_string()
}

impl NodeConfig {
    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(config::Environment::with_prefix("LNVPS_NODE").separator("__"))
            .build()
            .with_context(|| format!("Cannot read config {}", path.display()))?;
        settings
            .try_deserialize()
            .with_context(|| format!("Invalid config {}", path.display()))
    }
}

/// Refuse a control listener that is reachable from anywhere but the tunnel.
///
/// The control API can start and stop other people's virtual machines, so where
/// it listens is a security property, not a preference. Binding the wildcard
/// address on a marketplace node — somebody else's hardware, on somebody else's
/// network — publishes that power to their LAN and, behind a typical home
/// router, to anyone who can reach a forwarded port.
///
/// Enforced at startup rather than documented, because a comment in a config
/// file does not survive being copied between machines.
pub fn validate_listen_address(listen: IpAddr, interface_addrs: &[IpAddr]) -> Result<()> {
    if listen.is_unspecified() {
        bail!(
            "control listen address {listen} binds every interface; it must be the node's tunnel address"
        );
    }

    if !interface_addrs.contains(&listen) {
        bail!(
            "control listen address {listen} is not an address of the tunnel interface ({}); \
             the control API must only be reachable over the tunnel",
            if interface_addrs.is_empty() {
                "no addresses found".to_string()
            } else {
                interface_addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
    }

    Ok(())
}

/// Addresses currently assigned to `interface`.
///
/// Split out from [`validate_listen_address`] so the rule is testable without a
/// tunnel: this function is the only part that touches the machine.
pub fn interface_addresses(interface: &str) -> Result<Vec<IpAddr>> {
    let addrs = if_addrs::get_if_addrs()
        .with_context(|| format!("Cannot read network interfaces to find {interface}"))?;

    let found: Vec<IpAddr> = addrs
        .iter()
        .filter(|i| i.name == interface)
        .map(|i| i.addr.ip())
        .collect();

    if found.is_empty() {
        bail!(
            "Tunnel interface {interface} has no addresses (is it up?); the control API cannot \
             be bound to the tunnel, so it will not be started"
        );
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_tunnel_address_is_accepted() {
        let tunnel = [v4("10.66.0.1"), "fd00::1".parse().unwrap()];
        validate_listen_address(v4("10.66.0.1"), &tunnel).unwrap();
        validate_listen_address("fd00::1".parse().unwrap(), &tunnel).unwrap();
    }

    /// The failure this guard exists for: binding every interface on hardware
    /// LNVPS does not control publishes start/stop to the operator's LAN.
    #[test]
    fn the_wildcard_address_is_refused() {
        let tunnel = [v4("10.66.0.1")];
        for wildcard in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ] {
            let err = validate_listen_address(wildcard, &tunnel)
                .unwrap_err()
                .to_string();
            assert!(err.contains("binds every interface"), "got: {err}");
        }
    }

    /// A node's real NIC address is on the operator's own network. Listening
    /// there is the same exposure as the wildcard, just less obvious.
    #[test]
    fn an_address_outside_the_tunnel_is_refused() {
        let tunnel = [v4("10.66.0.1")];
        for outside in [
            v4("192.168.1.50"), // operator's LAN
            v4("203.0.113.7"),  // public address
            v4("127.0.0.1"),    // loopback: unreachable over the tunnel
            v4("10.66.0.2"),    // the *other* end of the tunnel, not ours
        ] {
            let err = validate_listen_address(outside, &tunnel)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("not an address of the tunnel interface"),
                "{outside} must be refused, got: {err}"
            );
        }
    }

    /// If the interface has no addresses the tunnel is not up, so there is
    /// nothing legitimate to bind and the message should say so rather than
    /// printing an empty list.
    #[test]
    fn a_tunnel_with_no_addresses_refuses_everything() {
        let err = validate_listen_address(v4("10.66.0.1"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no addresses found"), "got: {err}");
    }

    #[test]
    fn config_parses_with_defaults() {
        let yaml = r#"
api-url: "https://api.lnvps.net"
credential:
  kind: nostr-key
  file: /etc/lnvps-node/key
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, yaml).unwrap();

        let config = NodeConfig::load(&path).unwrap();
        assert_eq!(config.api_url, "https://api.lnvps.net");
        assert_eq!(config.state_dir, PathBuf::from("/var/lib/lnvps-node"));
        assert_eq!(config.heartbeat_secs, 60);
        // No tunnel yet, so no control listener.
        assert!(config.control.is_none());
    }

    #[test]
    fn control_config_parses() {
        let yaml = r#"
api-url: "https://api.lnvps.net"
credential:
  kind: session-token
  file: /etc/lnvps-node/token
control:
  listen: "10.66.0.1"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, yaml).unwrap();

        let control = NodeConfig::load(&path).unwrap().control.unwrap();
        assert_eq!(control.listen, v4("10.66.0.1"));
        assert_eq!(control.port, 8890);
        assert_eq!(control.tunnel_interface, "wgln0");
    }

    /// A typo in a key must not be silently ignored: a misspelled `listen`
    /// would otherwise leave the listener on its default.
    #[test]
    fn unknown_keys_are_rejected() {
        let yaml = r#"
api-url: "https://api.lnvps.net"
credential:
  kind: nostr-key
  file: /etc/lnvps-node/key
listne: "10.66.0.1"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, yaml).unwrap();
        assert!(NodeConfig::load(&path).is_err());
    }
}
