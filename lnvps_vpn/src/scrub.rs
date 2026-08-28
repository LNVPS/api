//! Forgetting where a customer was.
//!
//! WireGuard records, per peer, the address it was last heard from. It has to:
//! that is how a roaming client is found, and it is why a phone can move from
//! wifi to mobile without renegotiating. For a VPN device that address is the
//! customer's real one, the single piece of information this service exists to
//! keep to itself, sitting in kernel memory for as long as the peer is
//! configured.
//!
//! Nothing here can stop it being recorded while a peer is talking. What can be
//! stopped is it being kept afterwards. Once a peer has gone quiet for long
//! enough that it is plainly not connected, the peer is removed and re-added,
//! which is the only way to clear the field: the kernel offers no "forget where
//! this peer was" and setting an endpoint requires an address to set it to.
//!
//! Copied from Mullvad, who do the same at 600 seconds. The cost of being wrong
//! is small in one direction and not the other: scrub too eagerly and a client
//! sends one handshake to reconnect, which it does anyway on any change of
//! network; scrub too late and the address is held for no reason.

use anyhow::Result;
use lnvps_netlink::{NetOps, WgPeer};

use crate::client::{DesiredDataPlane, DesiredPeer};

/// Scrub the recorded endpoint of every peer that has been quiet for longer
/// than `after_secs`.
///
/// Returns the keys scrubbed, for logging. Peers that never handshook at all
/// are skipped: there is nothing recorded to remove, and removing and re-adding
/// them on every pass would be churn for its own sake.
pub async fn scrub_quiet_peers(
    ops: &dyn NetOps,
    desired: &DesiredDataPlane,
    after_secs: u64,
) -> Result<Vec<String>> {
    let mut scrubbed = Vec::new();

    for interface in &desired.interfaces {
        let name = interface.interface();
        let Some(observed) = ops.wireguard_state(&name).await? else {
            continue;
        };

        for peer in &observed.peers {
            // No recorded address means nothing to forget.
            if peer.endpoint.is_none() {
                continue;
            }
            // Never handshook: whatever address is there was never confirmed to
            // be anyone, and the peer is not connected to be disturbed.
            let Some(quiet_for) = peer.last_handshake_secs else {
                continue;
            };
            if quiet_for < after_secs {
                continue;
            }
            // Only peers LNVPS asked for. An interface may carry something the
            // operator put there, and removing it would be this daemon
            // reaching outside what it was given.
            let Some(wanted) = interface
                .peers
                .iter()
                .find(|p| p.public_key == peer.public_key)
            else {
                continue;
            };

            ops.remove_wireguard_peer(&name, &peer.public_key).await?;
            ops.set_wireguard_peer(&name, &as_peer(wanted)?).await?;
            scrubbed.push(peer.public_key.clone());
        }
    }

    Ok(scrubbed)
}

/// Rebuild a peer from the document rather than from what was read back, so a
/// scrub cannot quietly re-apply drift it happened to observe.
fn as_peer(desired: &DesiredPeer) -> Result<WgPeer> {
    Ok(WgPeer {
        public_key: desired.public_key.clone(),
        allowed_ips: desired
            .allowed_ips
            .iter()
            .map(|a| a.parse())
            .collect::<Result<Vec<_>, _>>()?,
        endpoint: desired.endpoint.clone(),
        persistent_keepalive: desired.persistent_keepalive,
    })
}

#[cfg(test)]
mod tests;
