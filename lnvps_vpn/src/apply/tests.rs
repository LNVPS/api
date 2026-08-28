//! What the daemon decides to do to a machine.
//!
//! The kernel sits behind [`NetOps`], so these run without root and assert the
//! decisions rather than the netlink encoding of them. Whether the decisions
//! work on a real kernel is the netns harness's job.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Result, bail};
use async_trait::async_trait;
use lnvps_netlink::{WgObserved, WgPeerState, WgSettings};

use super::*;
use crate::client::DesiredPeer;

/// A key and its public half, so a test can hand the daemon something that
/// derives rather than a placeholder it would reject.
const PRIVATE: &str = "iM7g0lLIF3P7WGZTF8Zgs+A2ZUGZQIS+eEIVN8U9RVo=";

/// A machine that remembers what it was told and answers from it, so a second
/// apply sees the first one's work. That is what makes "converges and then goes
/// quiet" testable at all.
#[derive(Default)]
pub struct FakeKernel {
    links: Mutex<HashMap<String, (bool, Option<u32>)>>,
    addresses: Mutex<HashMap<String, Vec<IpNetwork>>>,
    routes: Mutex<HashMap<String, Vec<IpNetwork>>>,
    wireguard: Mutex<HashMap<String, WgObserved>>,
    /// Every call that changed something, so a test can assert an apply was
    /// silent rather than only that it succeeded.
    pub calls: Mutex<Vec<String>>,
}

impl FakeKernel {
    fn record(&self, what: impl Into<String>) {
        self.calls.lock().unwrap().push(what.into());
    }

    pub fn peers_of(&self, name: &str) -> Vec<WgPeerState> {
        self.wireguard
            .lock()
            .unwrap()
            .get(name)
            .map(|w| w.peers.clone())
            .unwrap_or_default()
    }

    /// Pretend a peer has handshaken, and been heard from at `endpoint`.
    pub fn peer_spoke(&self, name: &str, public_key: &str, endpoint: &str, secs_ago: u64) {
        let mut wg = self.wireguard.lock().unwrap();
        if let Some(peer) = wg
            .get_mut(name)
            .and_then(|w| w.peers.iter_mut().find(|p| p.public_key == public_key))
        {
            peer.last_handshake_secs = Some(secs_ago);
            peer.endpoint = Some(endpoint.to_string());
        }
    }
}

#[async_trait]
impl NetOps for FakeKernel {
    async fn link_exists(&self, name: &str) -> Result<bool> {
        Ok(self.links.lock().unwrap().contains_key(name))
    }
    async fn create_wireguard(&self, name: &str) -> Result<()> {
        self.record(format!("create {name}"));
        self.links
            .lock()
            .unwrap()
            .insert(name.to_string(), (false, None));
        self.wireguard
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default();
        Ok(())
    }
    async fn create_bridge(&self, _name: &str) -> Result<()> {
        bail!("a route server has no bridge")
    }
    async fn set_up(&self, name: &str, mtu: u32) -> Result<()> {
        self.record(format!("up {name} {mtu}"));
        self.links
            .lock()
            .unwrap()
            .insert(name.to_string(), (true, Some(mtu)));
        Ok(())
    }
    async fn link_state(&self, name: &str) -> Result<(bool, Option<u32>)> {
        Ok(self
            .links
            .lock()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or((false, None)))
    }
    async fn addresses(&self, name: &str) -> Result<Vec<IpNetwork>> {
        Ok(self
            .addresses
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default())
    }
    async fn add_address(&self, name: &str, address: IpNetwork) -> Result<()> {
        self.record(format!("addr+ {name} {address}"));
        self.addresses
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(address);
        Ok(())
    }
    async fn del_address(&self, name: &str, address: IpNetwork) -> Result<()> {
        self.record(format!("addr- {name} {address}"));
        if let Some(a) = self.addresses.lock().unwrap().get_mut(name) {
            a.retain(|x| *x != address);
        }
        Ok(())
    }
    async fn routes(&self, name: &str) -> Result<Vec<IpNetwork>> {
        Ok(self
            .routes
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default())
    }
    async fn add_route(&self, destination: IpNetwork, name: &str) -> Result<()> {
        self.record(format!("route+ {name} {destination}"));
        self.routes
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(destination);
        Ok(())
    }
    async fn del_route(&self, destination: IpNetwork, name: &str) -> Result<()> {
        self.record(format!("route- {name} {destination}"));
        if let Some(r) = self.routes.lock().unwrap().get_mut(name) {
            r.retain(|x| *x != destination);
        }
        Ok(())
    }
    async fn configure_wireguard(&self, _name: &str, _settings: &WgSettings) -> Result<()> {
        bail!("a route server does not dial out")
    }
    async fn configure_wireguard_interface(
        &self,
        name: &str,
        private_key: &str,
        listen_port: u16,
    ) -> Result<()> {
        self.record(format!("key {name} {listen_port}"));
        let mut wg = self.wireguard.lock().unwrap();
        let state = wg.entry(name.to_string()).or_default();
        state.listen_port = listen_port;
        state.public_key = Some(lnvps_netlink::wireguard_public_key_base64(private_key)?);
        // As the kernel does: stating the device's configuration replaces its
        // peer set with it.
        state.peers.clear();
        Ok(())
    }
    async fn set_wireguard_peer(&self, name: &str, peer: &WgPeer) -> Result<()> {
        self.record(format!("peer+ {name} {}", peer.public_key));
        let mut wg = self.wireguard.lock().unwrap();
        let state = wg.entry(name.to_string()).or_default();
        state.peers.retain(|p| p.public_key != peer.public_key);
        state.peers.push(WgPeerState {
            public_key: peer.public_key.clone(),
            last_handshake_secs: None,
            allowed_ips: peer.allowed_ips.clone(),
            endpoint: peer.endpoint.clone(),
            rx_bytes: 0,
            tx_bytes: 0,
        });
        Ok(())
    }
    async fn remove_wireguard_peer(&self, name: &str, public_key: &str) -> Result<()> {
        self.record(format!("peer- {name} {public_key}"));
        if let Some(state) = self.wireguard.lock().unwrap().get_mut(name) {
            state.peers.retain(|p| p.public_key != public_key);
        }
        Ok(())
    }
    async fn wireguard_state(&self, name: &str) -> Result<Option<WgObserved>> {
        Ok(self.wireguard.lock().unwrap().get(name).cloned())
    }
    async fn sysctl(&self, _key: &str) -> Result<Option<String>> {
        Ok(None)
    }
    async fn set_sysctl(&self, _key: &str, _value: &str) -> Result<()> {
        Ok(())
    }
}

pub fn a_peer(public_key: &str, allowed: &[&str]) -> DesiredPeer {
    DesiredPeer {
        public_key: public_key.to_string(),
        allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
        endpoint: None,
        persistent_keepalive: None,
    }
}

pub fn a_document(peers: Vec<DesiredPeer>) -> DesiredDataPlane {
    DesiredDataPlane {
        generation: 1,
        interfaces: vec![DesiredInterface {
            pool_id: 7,
            private_key: PRIVATE.to_string(),
            listen_port: 51820,
            mtu: 1420,
            addresses: vec!["10.64.0.1/24".to_string()],
            routes: vec![],
            peers,
        }],
    }
}

#[tokio::test]
async fn a_first_apply_builds_the_interface() {
    let kernel = FakeKernel::default();
    let doc = a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]);

    let applied = apply(&kernel, &doc).await.unwrap();

    assert!(applied.changes.iter().any(|c| c.contains("created wgln7")));
    assert!(applied.changes.iter().any(|c| c.contains("keyed wgln7")));
    assert_eq!(kernel.peers_of("wgln7").len(), 1);
    assert_eq!(
        kernel.addresses("wgln7").await.unwrap(),
        vec!["10.64.0.1/24".parse::<IpNetwork>().unwrap()]
    );
}

#[tokio::test]
async fn a_second_apply_changes_nothing() {
    let kernel = FakeKernel::default();
    let doc = a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]);
    apply(&kernel, &doc).await.unwrap();
    kernel.calls.lock().unwrap().clear();

    let applied = apply(&kernel, &doc).await.unwrap();

    // The whole point. A route server is applied on every fetch, and an apply
    // that rewrote the interface would reset every session on it each time.
    assert!(applied.is_empty(), "{applied:?}");
    assert!(kernel.calls.lock().unwrap().is_empty(), "{kernel:?}",);
}

#[tokio::test]
async fn adding_one_device_does_not_disturb_the_others() {
    let kernel = FakeKernel::default();
    apply(
        &kernel,
        &a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]),
    )
    .await
    .unwrap();
    kernel.calls.lock().unwrap().clear();

    apply(
        &kernel,
        &a_document(vec![
            a_peer("cGVlcjE=", &["10.64.0.7/32"]),
            a_peer("cGVlcjI=", &["10.64.0.8/32"]),
        ]),
    )
    .await
    .unwrap();

    // Exactly one call, for the new peer. If the interface were re-keyed or the
    // peer set replaced, every existing customer would renegotiate because
    // somebody else bought a phone.
    let calls = kernel.calls.lock().unwrap().clone();
    assert_eq!(calls, vec!["peer+ wgln7 cGVlcjI=".to_string()], "{calls:?}");
}

#[tokio::test]
async fn a_revoked_device_is_removed() {
    let kernel = FakeKernel::default();
    apply(
        &kernel,
        &a_document(vec![
            a_peer("cGVlcjE=", &["10.64.0.7/32"]),
            a_peer("cGVlcjI=", &["10.64.0.8/32"]),
        ]),
    )
    .await
    .unwrap();

    apply(
        &kernel,
        &a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]),
    )
    .await
    .unwrap();

    // The failure that matters: a key LNVPS was told to stop honouring, still
    // configured and still working.
    let left: Vec<String> = kernel
        .peers_of("wgln7")
        .into_iter()
        .map(|p| p.public_key)
        .collect();
    assert_eq!(left, vec!["cGVlcjE=".to_string()]);
}

#[tokio::test]
async fn a_peer_whose_address_moved_is_rewritten() {
    let kernel = FakeKernel::default();
    apply(
        &kernel,
        &a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]),
    )
    .await
    .unwrap();
    kernel.calls.lock().unwrap().clear();

    apply(
        &kernel,
        &a_document(vec![a_peer("cGVlcjE=", &["10.64.0.9/32"])]),
    )
    .await
    .unwrap();

    assert_eq!(
        kernel.calls.lock().unwrap().clone(),
        vec!["peer+ wgln7 cGVlcjE=".to_string()]
    );
    assert_eq!(
        kernel.peers_of("wgln7")[0].allowed_ips,
        vec!["10.64.0.9/32".parse::<IpNetwork>().unwrap()]
    );
}

#[tokio::test]
async fn allowed_ips_in_a_different_order_are_the_same_allowed_ips() {
    let kernel = FakeKernel::default();
    apply(
        &kernel,
        &a_document(vec![a_peer(
            "cGVlcjE=",
            &["10.64.0.7/32", "fd00:64::7/128"],
        )]),
    )
    .await
    .unwrap();
    kernel.calls.lock().unwrap().clear();

    apply(
        &kernel,
        &a_document(vec![a_peer(
            "cGVlcjE=",
            &["fd00:64::7/128", "10.64.0.7/32"],
        )]),
    )
    .await
    .unwrap();

    // The kernel reports them in its own order. Rewriting a peer because a list
    // was shuffled would reset a session for nothing.
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_interface_the_document_does_not_mention_is_left_alone() {
    let kernel = FakeKernel::default();
    kernel.create_wireguard("wg-operators-own").await.unwrap();
    kernel
        .set_wireguard_peer(
            "wg-operators-own",
            &WgPeer {
                public_key: "b3RoZXI=".to_string(),
                allowed_ips: vec!["192.0.2.0/24".parse().unwrap()],
                endpoint: None,
                persistent_keepalive: None,
            },
        )
        .await
        .unwrap();

    apply(&kernel, &a_document(vec![])).await.unwrap();

    // A route server is not necessarily only a route server. A bug here must
    // not be able to take out the operator's own networking.
    assert_eq!(kernel.peers_of("wg-operators-own").len(), 1);
}

#[tokio::test]
async fn a_key_that_is_not_a_key_is_refused_rather_than_configured() {
    let kernel = FakeKernel::default();
    let mut doc = a_document(vec![]);
    doc.interfaces[0].private_key = "not a key".to_string();

    let err = apply(&kernel, &doc).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("not a WireGuard key"),
        "{err:#}"
    );
}

impl std::fmt::Debug for FakeKernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeKernel")
            .field("calls", &self.calls.lock().unwrap())
            .finish()
    }
}

#[tokio::test]
async fn the_connected_route_of_an_interface_address_is_not_drift() {
    let kernel = FakeKernel::default();
    let mut doc = a_document(vec![]);
    doc.interfaces[0].addresses = vec!["10.64.0.1/24".to_string(), "fd00:64::1/64".to_string()];
    apply(&kernel, &doc).await.unwrap();

    // As the kernel does: an address brings its own connected route with it.
    kernel
        .add_route("10.64.0.0/24".parse().unwrap(), "wgln7")
        .await
        .unwrap();
    kernel
        .add_route("fd00:64::/64".parse().unwrap(), "wgln7")
        .await
        .unwrap();
    kernel.calls.lock().unwrap().clear();

    let applied = apply(&kernel, &doc).await.unwrap();

    // That route is the kernel's, not ours. Deleting it is a fight we lose on
    // every apply: it comes back with the address, and the delete itself fails
    // with ESRCH once two addresses imply the same prefix. Found by the netns
    // harness, where it stopped a route server coming up at all.
    assert!(applied.is_empty(), "{applied:?}");
    assert!(kernel.calls.lock().unwrap().is_empty(), "{kernel:?}");
}

#[tokio::test]
async fn a_route_nobody_asked_for_is_still_removed() {
    let kernel = FakeKernel::default();
    let mut doc = a_document(vec![]);
    doc.interfaces[0].addresses = vec!["10.64.0.1/24".to_string()];
    apply(&kernel, &doc).await.unwrap();
    // Not implied by any address: a leftover from a block that was withdrawn.
    kernel
        .add_route("10.99.0.0/24".parse().unwrap(), "wgln7")
        .await
        .unwrap();
    kernel.calls.lock().unwrap().clear();

    apply(&kernel, &doc).await.unwrap();

    assert_eq!(
        kernel.calls.lock().unwrap().clone(),
        vec!["route- wgln7 10.99.0.0/24".to_string()]
    );
}
