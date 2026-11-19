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
use lnvps_db::{LNVpsDb, VpnDevice, VpnPeerTemplate, VpnService, VpnSubscription};

use crate::provisioner::wg::address::{Placement, carve_peer, taken_addresses};

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

        // One peer per interface the service terminates, all carrying this key
        // and these addresses -- a `tunnel` row means a peer on an interface,
        // and a device reachable in three regions is three peers. The database
        // writes them with the device in one transaction, because a device
        // whose peers landed on some interfaces and not others is a customer
        // whose VPN works in some regions and not others.
        let device = VpnDevice {
            id: 0,
            vpn_subscription_id: plan.id,
            slot,
            name: name.trim().to_string(),
            created: chrono::Utc::now(),
        };
        let peer = VpnPeerTemplate {
            user_id: plan.user_id,
            name: peer_name(plan, slot),
            peer_pubkey: peer_pubkey.to_vec(),
            address4,
            address6,
        };

        // Both the slot and the address are proposed from a read and enforced
        // by a unique key, so a simultaneous registration on the same plan can
        // take either between the two. Losing that race is not the customer's
        // problem: re-read and take the next one instead of handing back an
        // error for something that will succeed immediately.
        //
        // A full plan or an exhausted block is *not* contention and is not
        // retried: both propagate from `next_free_slot` and
        // `carve_device_addresses` above, because trying again cannot help.
        match db.insert_vpn_device_with_peers(&device, &peer).await {
            Ok(id) => return Ok(db.get_vpn_device(id).await?),
            // The last attempt's failure is the answer. Returning it here,
            // rather than remembering one and reporting it after the loop,
            // keeps "we ran out of attempts but recorded no error" from being a
            // state that has to exist and be handled.
            Err(e) if attempt == REGISTER_ATTEMPTS => {
                return Err(anyhow::Error::from(e).context(format!(
                    "Could not register a device after {REGISTER_ATTEMPTS} attempts"
                )));
            }
            Err(_) => continue,
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

#[cfg(test)]
mod tests;

/// Carve the next free address out of a service's block.
///
/// Random placement: a sequential address encodes roughly when it was issued
/// and how many came before it, so anybody who sees one learns the size of the
/// fleet and the age of the account behind it.
///
/// The taken set is every peer on the service, whatever its billing state. A
/// lapsed customer's address is still theirs, and reissuing it would deliver
/// their traffic to somebody else the moment they paid again.
async fn carve_device_addresses(
    db: &Arc<dyn LNVpsDb>,
    service: &VpnService,
) -> Result<(Option<String>, Option<String>)> {
    // The block belongs to the interfaces, and every interface on a service
    // carries the same one — enforced when a pool is linked — so any of them
    // answers. A service with no interface has nowhere for a device to connect,
    // which is worth saying plainly rather than allocating an address into
    // nothing.
    let pool = db
        .list_vpn_service_pools(service.id)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            anyhow!(
                "VPN service {} has no interface, so there is no block to carve from \
                 and nowhere for a device to connect",
                service.id
            )
        })?;

    let taken = taken_addresses(&db.list_vpn_tunnels_in_service(service.id).await?);
    carve_peer(
        pool.cidr4.as_deref(),
        pool.cidr6.as_deref(),
        &taken,
        &format!("VPN service {}", service.id),
        Placement::Random,
    )
}
