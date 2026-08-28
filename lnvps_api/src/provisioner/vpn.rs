//! Registering a VPN device, and what its interfaces should look like.
//!
//! A marketplace node's tunnel is terminated by one route server, so its
//! addresses are carved from that route server's pool and its peer exists on
//! exactly one interface. A VPN device is the opposite: one keypair and one
//! inner address, valid on every region at once, with the region chosen
//! client-side by dialling a different endpoint and server key.
//!
//! So allocation happens once, against the [`VpnService`] that owns the address
//! block, and the result is pushed to every interface terminating that service.
//! Nothing here is per-region, which is exactly what makes switching regions
//! instant: the client edits two lines of its config and nothing on our side
//! changes at all.
//!
//! The customer generates their own keypair and presents only the public half,
//! so a private key belonging to a machine LNVPS does not own never exists here.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use ipnetwork::IpNetwork;
use lnvps_db::{LNVpsDb, RouterTunnelKind, Tunnel, VpnDevice, VpnService, VpnSubscription};

use crate::provisioner::tunnel::{Placement, carve_peer};

/// Register `peer_pubkey` as a device on `plan`.
///
/// Idempotent on the key: a client that asks twice, or retries a request whose
/// response it lost, gets the device it already has rather than burning a slot.
///
/// A key that is already registered *on another account* is refused rather than
/// moved. Two accounts cannot share one key, and silently transferring it would
/// let anybody who learned a public key take over the address behind it.
pub async fn register_vpn_device(
    db: &Arc<dyn LNVpsDb>,
    plan: &VpnSubscription,
    name: &str,
    peer_pubkey: &[u8],
) -> Result<VpnDevice> {
    if peer_pubkey.len() != 32 {
        bail!(
            "A WireGuard public key is 32 bytes, got {}",
            peer_pubkey.len()
        );
    }

    let service = db.get_vpn_service(plan.vpn_service_id).await?;
    if !service.enabled {
        bail!("VPN service {} is not accepting new devices", service.name);
    }

    if let Some(existing) = db.get_vpn_device_by_pubkey(peer_pubkey).await? {
        if existing.vpn_subscription_id != plan.id {
            bail!("That public key is already registered to another account");
        }
        return Ok(existing);
    }

    // Both the slot and the address are proposed from a read and enforced by a
    // unique key, so a simultaneous registration on the same plan can take
    // either between the two. Losing that race is not the customer's problem:
    // re-read and take the next one instead of handing back an error for
    // something that will succeed immediately.
    //
    // A full plan or an exhausted block is *not* contention and is not retried:
    // both propagate on the first attempt, because trying again cannot help.
    for attempt in 1..=REGISTER_ATTEMPTS {
        let devices = db.list_vpn_devices(plan.id).await?;
        let slot = next_free_slot(&devices, service.default_device_limit)?;
        let (address4, address6) = carve_device_addresses(db, &service).await?;

        // The peer is a tunnel, the same as a marketplace node's. `pool_id` and
        // `router_id` stay NULL: a device is a peer on every interface
        // terminating its service at once, so naming one would be false.
        let tunnel = Tunnel {
            id: 0,
            kind: RouterTunnelKind::Wireguard,
            user_id: plan.user_id,
            router_id: None,
            pool_id: None,
            name: peer_name(plan, slot),
            peer_pubkey: Some(peer_pubkey.to_vec()),
            // Clients dial out from behind NAT, so the endpoint is learned from
            // the handshake.
            peer_endpoint: None,
            address4,
            address6,
            keepalive: None,
            enabled: true,
            created: chrono::Utc::now(),
        };

        let tunnel_id = match db.insert_tunnel(&tunnel).await {
            Ok(id) => id,
            // The last attempt's failure is the answer. Returning it here,
            // rather than remembering one and reporting it after the loop,
            // keeps "we ran out of attempts but recorded no error" from being
            // a state that has to exist and be handled.
            Err(e) if attempt == REGISTER_ATTEMPTS => {
                return Err(anyhow::Error::from(e).context(format!(
                    "Could not register a device after {REGISTER_ATTEMPTS} attempts"
                )));
            }
            Err(_) => continue,
        };

        match db
            .insert_vpn_device(&VpnDevice {
                id: 0,
                vpn_subscription_id: plan.id,
                slot,
                name: name.trim().to_string(),
                tunnel_id,
                created: chrono::Utc::now(),
            })
            .await
        {
            Ok(id) => return Ok(db.get_vpn_device(id).await?),
            Err(e) => {
                // The tunnel is this registration's, and nothing points at it
                // yet, so a failed link leaves an address allocated to nobody
                // unless it goes back now.
                let _ = db.delete_tunnel(tunnel_id).await;
                if attempt == REGISTER_ATTEMPTS {
                    return Err(anyhow::Error::from(e).context(format!(
                        "Could not register a device after {REGISTER_ATTEMPTS} attempts"
                    )));
                }
            }
        }
    }

    unreachable!("the loop returns on its last attempt")
}

/// The peer name configured on the route servers.
///
/// Derived from the plan and slot so it is stable across a rename and unique
/// across the fleet, which the customer's own label for the device is neither.
fn peer_name(plan: &VpnSubscription, slot: u8) -> String {
    format!("vpn-{}-{}", plan.id, slot)
}

/// How many times a registration re-reads and tries again after losing a race
/// for a slot or an address.
///
/// Small on purpose. Contention is between the devices of one account, so the
/// realistic case is a customer double-clicking or a client retrying, not a
/// stampede; if four attempts in a row all lose, something other than
/// contention is wrong and looping harder would only hide it.
const REGISTER_ATTEMPTS: usize = 4;

/// The lowest unused slot below `limit`.
///
/// Lowest-free rather than next-highest so a customer who removes a device and
/// adds another reuses the slot instead of walking off the end of their plan.
///
/// This is a *proposal*, not the enforcement: `uk_vpn_device_slot` is what makes
/// the limit hold, because between reading this list and inserting, a
/// concurrent registration can take the same slot. The loser's insert is
/// rejected by the database rather than producing a sixth device on a
/// five-device plan.
fn next_free_slot(devices: &[VpnDevice], limit: u8) -> Result<u8> {
    (0..limit)
        .find(|s| !devices.iter().any(|d| d.slot == *s))
        .ok_or_else(|| {
            anyhow!(
                "This plan is limited to {limit} device{}; remove one before adding another",
                if limit == 1 { "" } else { "s" }
            )
        })
}

/// Carve the next free address out of the service's blocks.
///
/// The only thing this does that carving a marketplace link does not is read
/// the taken set from the service's devices rather than a pool's tunnels — and
/// take *every* device, whatever its billing state, because a lapsed customer's
/// address is still theirs and reissuing it would deliver their traffic to
/// somebody else the moment they paid again.
async fn carve_device_addresses(
    db: &Arc<dyn LNVpsDb>,
    service: &VpnService,
) -> Result<(Option<String>, Option<String>)> {
    let tunnels = db.list_vpn_tunnels_in_service(service.id).await?;
    let taken: Vec<IpNetwork> = tunnels
        .iter()
        .flat_map(|t| [t.address4.clone(), t.address6.clone()])
        .flatten()
        .filter_map(|a| a.parse::<IpNetwork>().ok())
        .collect();

    carve_peer(
        service.device_cidr4.as_deref(),
        service.device_cidr6.as_deref(),
        &taken,
        &format!("VPN service {}", service.id),
        Placement::Random,
    )
}

#[cfg(test)]
mod tests;
