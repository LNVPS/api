//! What a WireGuard data plane needs from the kernel, and the shape of the
//! answers.
//!
//! The kernel calls sit behind [`NetOps`] so that everything deciding *what* to
//! configure can be tested without root. Whether the netlink implementation of
//! those decisions really works on a kernel is proven by the netns end-to-end
//! harness, which runs both ends of a real tunnel and passes traffic across it.

use anyhow::{Result, bail};
use async_trait::async_trait;
use ipnetwork::IpNetwork;

/// How a WireGuard interface should be configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgSettings {
    /// Base64, as WireGuard states keys.
    pub private_key: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub keepalive: Option<u16>,
    /// Everything, for a node: its guests use LNVPS addresses, so no traffic of
    /// theirs belongs anywhere else.
    pub allowed_ips: Vec<IpNetwork>,
}

/// What a WireGuard interface currently is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WgObserved {
    /// Peers keyed by public key, with seconds since each last handshake.
    pub peers: Vec<(String, Option<u64>)>,
}

/// The kernel operations the data plane needs.
///
/// A trait so the orchestration above it can be tested without root, and so the
/// end-to-end harness can drive the same code inside a network namespace.
#[async_trait]
pub trait NetOps: Send + Sync {
    /// Whether a link exists.
    async fn link_exists(&self, name: &str) -> Result<bool>;
    /// Create a WireGuard interface.
    async fn create_wireguard(&self, name: &str) -> Result<()>;
    /// Create a bridge.
    async fn create_bridge(&self, name: &str) -> Result<()>;
    /// Bring a link up with the given MTU.
    async fn set_up(&self, name: &str, mtu: u32) -> Result<()>;
    /// Whether a link is up, and its MTU.
    async fn link_state(&self, name: &str) -> Result<(bool, Option<u32>)>;

    async fn addresses(&self, name: &str) -> Result<Vec<IpNetwork>>;
    async fn add_address(&self, name: &str, address: IpNetwork) -> Result<()>;
    async fn del_address(&self, name: &str, address: IpNetwork) -> Result<()>;

    /// Destinations routed out of `name`.
    async fn routes(&self, name: &str) -> Result<Vec<IpNetwork>>;
    async fn add_route(&self, destination: IpNetwork, name: &str) -> Result<()>;
    async fn del_route(&self, destination: IpNetwork, name: &str) -> Result<()>;

    /// Configure the WireGuard interface: key, peer, allowed IPs.
    async fn configure_wireguard(&self, name: &str, settings: &WgSettings) -> Result<()>;
    /// Remove a peer by public key.
    async fn remove_wireguard_peer(&self, name: &str, public_key: &str) -> Result<()>;
    /// Read the interface back, or `None` when it does not exist.
    async fn wireguard_state(&self, name: &str) -> Result<Option<WgObserved>>;

    /// Read a kernel knob, or `None` when this kernel does not have it.
    async fn sysctl(&self, key: &str) -> Result<Option<String>>;
    async fn set_sysctl(&self, key: &str, value: &str) -> Result<()>;
}

/// A machine whose network cannot be read.
///
/// Not a mock: it is what a node that has never been configured looks like from
/// outside, and reporting that truthfully is what lets the health gate say
/// "this node has no data plane" instead of timing out.
pub struct UnavailableKernel;

#[async_trait]
impl NetOps for UnavailableKernel {
    async fn link_exists(&self, _name: &str) -> Result<bool> {
        Ok(false)
    }
    async fn create_wireguard(&self, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn create_bridge(&self, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn set_up(&self, _name: &str, _mtu: u32) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn link_state(&self, _name: &str) -> Result<(bool, Option<u32>)> {
        Ok((false, None))
    }
    async fn addresses(&self, _name: &str) -> Result<Vec<IpNetwork>> {
        Ok(vec![])
    }
    async fn add_address(&self, _name: &str, _address: IpNetwork) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn del_address(&self, _name: &str, _address: IpNetwork) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn routes(&self, _name: &str) -> Result<Vec<IpNetwork>> {
        Ok(vec![])
    }
    async fn add_route(&self, _destination: IpNetwork, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn del_route(&self, _destination: IpNetwork, _name: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn configure_wireguard(&self, _name: &str, _settings: &WgSettings) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn remove_wireguard_peer(&self, _name: &str, _public_key: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
    async fn wireguard_state(&self, _name: &str) -> Result<Option<WgObserved>> {
        Ok(None)
    }
    async fn sysctl(&self, _key: &str) -> Result<Option<String>> {
        Ok(None)
    }
    async fn set_sysctl(&self, _key: &str, _value: &str) -> Result<()> {
        bail!("This node cannot configure its network")
    }
}
