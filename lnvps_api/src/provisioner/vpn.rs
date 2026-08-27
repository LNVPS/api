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
use lnvps_db::{LNVpsDb, VpnDevice, VpnService, VpnSubscription};

use crate::provisioner::allocate_subnet;
use crate::provisioner::tunnel::{PoolPlan, host_address, reserved_addresses, server_address};
use crate::router::WireguardPeer;

/// A device holds a single address, not a link.
///
/// WireGuard is layer 3 and point-to-point, so there is no on-link requirement
/// and nothing for a wider prefix to describe. A /31 per device would spend two
/// addresses to say what one says, and multiply the block by five again on a
/// five-device plan.
const DEVICE_PREFIX_V4: u8 = 32;
const DEVICE_PREFIX_V6: u8 = 128;

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

    let devices = db.list_vpn_devices(plan.id).await?;
    let slot = next_free_slot(&devices, plan.device_limit)?;
    let (address4, address6) = carve_device_addresses(db, &service).await?;

    let id = db
        .insert_vpn_device(&VpnDevice {
            id: 0,
            vpn_subscription_id: plan.id,
            slot,
            name: name.trim().to_string(),
            peer_pubkey: peer_pubkey.to_vec(),
            address4,
            address6,
            enabled: true,
            created: chrono::Utc::now(),
        })
        .await?;

    db.get_vpn_device(id).await.map_err(Into::into)
}

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

/// Carve the next free address out of the service's blocks, in the device's own
/// form (`10.64.0.7/32`).
///
/// A service with both blocks supplies both halves. A device given only one
/// family would silently be single-stack, which is discovered by a customer
/// rather than by us.
///
/// The taken set is every device on the service, whatever its billing state:
/// a lapsed customer's address is still theirs, and reissuing it would deliver
/// their traffic to somebody else the moment they paid again.
async fn carve_device_addresses(
    db: &Arc<dyn LNVpsDb>,
    service: &VpnService,
) -> Result<(Option<String>, Option<String>)> {
    let taken: Vec<IpNetwork> = db
        .list_vpn_devices_in_service(service.id)
        .await?
        .iter()
        .flat_map(|d| [d.address4.clone(), d.address6.clone()])
        .flatten()
        .filter_map(|a| a.parse::<IpNetwork>().ok())
        .collect();

    let address4 = match service.device_cidr4.as_deref() {
        Some(cidr) => Some(carve_one(cidr, DEVICE_PREFIX_V4, &taken, service)?),
        None => None,
    };
    let address6 = match service.device_cidr6.as_deref() {
        Some(cidr) => Some(carve_one(cidr, DEVICE_PREFIX_V6, &taken, service)?),
        None => None,
    };
    Ok((address4, address6))
}

fn carve_one(cidr: &str, prefix: u8, taken: &[IpNetwork], service: &VpnService) -> Result<String> {
    let block: IpNetwork = cidr.parse().map_err(|e| {
        anyhow!(
            "VPN service {} has an unparseable block {cidr}: {e}",
            service.id
        )
    })?;
    let mut taken = taken.to_vec();
    // The route servers hold the whole block on-link, so what the block
    // reserves is reserved here too: its network address, the servers' shared
    // address just after it, and on IPv4 its broadcast address. Handing any of
    // them to a device produces an address no route server will forward to.
    taken.extend(reserved_addresses(cidr));
    let addr = allocate_subnet(&block, prefix, &taken).ok_or_else(|| {
        anyhow!(
            "VPN service {} has no free /{prefix} left in {cidr}; widen the block",
            service.id
        )
    })?;
    Ok(addr.to_string())
}

/// What a device-terminating interface should have configured on its route
/// server.
///
/// Every interface on a service gets the *same* plan: the same peers, the same
/// addresses, the same routes. That is the whole design. It also means this is
/// computed per pool but depends on nothing about the pool beyond which service
/// it terminates, so two route servers that disagree are drift rather than a
/// difference of opinion.
pub async fn plan_vpn_pool(db: &Arc<dyn LNVpsDb>, service: &VpnService) -> Result<PoolPlan> {
    let mut plan = PoolPlan::default();

    // One address for the whole service, carrying the block's prefix so every
    // device is on-link. Shared by every route server, because a device's
    // gateway must not change when it switches region.
    plan.addresses.extend(
        [
            server_address(service.device_cidr4.as_deref()),
            server_address(service.device_cidr6.as_deref()),
        ]
        .into_iter()
        .flatten(),
    );

    // An address on a point-to-point interface gives the kernel no route to the
    // rest of its prefix, so without this the route server holds `10.64.0.1/12`
    // and still answers "network is unreachable" for every device in it.
    plan.routes.extend(
        [
            service.device_cidr4.as_deref(),
            service.device_cidr6.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::to_string),
    );

    // Suspension is applied by this query, not by a flag anybody has to
    // remember to set: an unpaid, expired or deactivated plan stops matching
    // and its devices simply leave the peer set.
    for device in db.list_active_vpn_devices(service.id).await? {
        // AllowedIPs is both the route to this peer and the anti-spoof
        // boundary: WireGuard drops an inbound packet whose source is not
        // listed, so one customer cannot claim another's address. A device gets
        // its own addresses and nothing else, which is what makes a VPN peer
        // different from a node peer carrying guest prefixes behind it.
        let allowed_ips: Vec<String> = [
            host_address(device.address4.as_deref()),
            host_address(device.address6.as_deref()),
        ]
        .into_iter()
        .flatten()
        .collect();

        // A device with no address is not configurable, and a peer with an
        // empty AllowedIPs would be a peer that can send nothing — worse than
        // absent, because it looks configured.
        if allowed_ips.is_empty() {
            continue;
        }

        plan.peers.push(WireguardPeer {
            public_key: lnvps_api_common::wireguard_key_to_base64(&device.peer_pubkey),
            // Clients dial out from behind NAT, so the endpoint is learned from
            // the handshake. Configuring one would pin a device to whichever
            // address it last connected from.
            endpoint: None,
            allowed_ips,
            // Per interface, not per device: it is a property of the link the
            // route server offers, and every interface on a service offers the
            // same one.
            persistent_keepalive: None,
        });
    }

    Ok(plan)
}

#[cfg(test)]
mod tests;
