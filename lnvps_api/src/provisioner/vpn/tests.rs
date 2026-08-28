//! What a device registration allocates, and what it must refuse.

use lnvps_api_common::MockDb;
use lnvps_db::{
    IntervalType, LineItemType, Router, RouterKind, Subscription, SubscriptionLineItem, TunnelPool,
};

use super::*;

/// Every service is sold by a company, so one has to exist before any of this.
async fn a_company(mock: &MockDb) -> u64 {
    mock.companies
        .lock()
        .await
        .entry(1)
        .or_insert(lnvps_db::Company {
            id: 1,
            name: "LNVPS".to_string(),
            base_currency: "EUR".to_string(),
            ..Default::default()
        });
    1
}

/// A dual-stack service. `/28` and `/124` are deliberately tiny so exhaustion
/// is reachable in a test rather than theoretical.
async fn a_service(db: &Arc<dyn LNVpsDb>, mock: &MockDb) -> Result<VpnService> {
    let company_id = a_company(mock).await;
    let id = db
        .insert_vpn_service(&VpnService {
            name: "eu".to_string(),
            company_id,
            currency: "EUR".to_string(),
            amount: 500,
            device_cidr4: Some("10.64.0.0/28".to_string()),
            device_cidr6: Some("fd00:64::/124".to_string()),
            dns: Some("10.64.0.1".to_string()),
            default_device_limit: 5,
            enabled: true,
            ..Default::default()
        })
        .await?;
    Ok(db.get_vpn_service(id).await?)
}

/// A paid plan on `service` for a fresh account.
async fn a_plan(db: &Arc<dyn LNVpsDb>, service: &VpnService, seed: u8) -> Result<VpnSubscription> {
    a_plan_with(db, service, seed, 5, true).await
}

/// A service whose allowance is `limit`, since the allowance is per service.
async fn a_service_limited(db: &Arc<dyn LNVpsDb>, mock: &MockDb, limit: u8) -> Result<VpnService> {
    let company_id = a_company(mock).await;
    let id = db
        .insert_vpn_service(&VpnService {
            name: "small".to_string(),
            company_id,
            currency: "EUR".to_string(),
            device_cidr4: Some("10.65.0.0/28".to_string()),
            default_device_limit: limit,
            enabled: true,
            ..Default::default()
        })
        .await?;
    Ok(db.get_vpn_service(id).await?)
}

async fn a_plan_with(
    db: &Arc<dyn LNVpsDb>,
    service: &VpnService,
    seed: u8,
    _device_limit: u8,
    paid: bool,
) -> Result<VpnSubscription> {
    let user_id = db.upsert_user(&[seed; 32]).await?;
    let (_, items) = db
        .insert_subscription_with_line_items(
            &Subscription {
                id: 0,
                user_id,
                company_id: 1,
                name: "vpn".to_string(),
                description: None,
                created: chrono::Utc::now(),
                expires: None,
                is_active: true,
                is_setup: paid,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: false,
                external_id: None,
            },
            vec![SubscriptionLineItem {
                id: 0,
                subscription_id: 0,
                subscription_type: LineItemType::Vps,
                name: "vpn".to_string(),
                description: None,
                amount: 500,
                setup_amount: 0,
                configuration: None,
            }],
        )
        .await?;
    let id = db
        .insert_vpn_subscription(&VpnSubscription {
            vpn_service_id: service.id,
            user_id,
            subscription_line_item_id: items[0],
            ..Default::default()
        })
        .await?;
    Ok(db.get_vpn_subscription(id).await?)
}

/// An interface terminating `service`, so `plan_pool` has something to dispatch
/// on.
async fn a_pool(db: &Arc<dyn LNVpsDb>, mock: &MockDb, service: &VpnService) -> Result<TunnelPool> {
    let router_id = {
        let mut routers = mock.router.lock().await;
        let id = routers.keys().max().copied().unwrap_or(0) + 1;
        routers.insert(
            id,
            Router {
                id,
                name: "rs".to_string(),
                enabled: true,
                kind: RouterKind::MockRouter,
                url: "mock://rs".to_string(),
                token: "t".into(),
            },
        );
        id
    };
    let pool_id = db
        .insert_tunnel_pool(&TunnelPool {
            router_id,
            region_id: 1,
            name: "vpn-ams".to_string(),
            listen_addr: "rs.example".to_string(),
            listen_port: 51820,
            private_key: lnvps_api_common::generate_wireguard_keypair()?
                .private_key
                .into(),
            public_key: vec![0x33; 32],
            // A VPN pool still carries its own block, because it is an ordinary
            // interface. It is simply not what devices are addressed from.
            cidr4: Some("10.200.0.0/24".to_string()),
            cidr6: None,
            keepalive: Some(25),
            mtu: 1420,
            enabled: true,
            ..Default::default()
        })
        .await?;
    db.link_vpn_service_pool(service.id, pool_id).await?;
    Ok(db.get_tunnel_pool(pool_id).await?)
}

fn key(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

/// A device's peer. The key and addresses live on the tunnel now, because a
/// device *is* a WireGuard peer and there is one table for those.
async fn peer(db: &Arc<dyn LNVpsDb>, device: &VpnDevice) -> Result<lnvps_db::Tunnel> {
    Ok(db.get_tunnel(device.tunnel_id).await?)
}

/// Addresses are placed at random, so a test can only assert the properties
/// that matter: inside the block, a host prefix, and not one of the addresses
/// the block reserves for itself.
#[track_caller]
fn assert_usable(addr: Option<&str>, cidr: &str, prefix: u8) {
    use ipnetwork::IpNetwork;
    let addr = addr.expect("no address allocated");
    let net: IpNetwork = addr.parse().expect("unparseable address");
    let block: IpNetwork = cidr.parse().unwrap();
    assert_eq!(net.prefix(), prefix, "{addr} is not a /{prefix}");
    assert!(block.contains(net.ip()), "{addr} is outside {cidr}");
    assert!(
        !crate::provisioner::reserved_addresses(cidr)
            .iter()
            .any(|r| r.ip() == net.ip()),
        "{addr} is one of {cidr}'s reserved addresses"
    );
}

/// The first device gets slot zero and one address from each of the service's
/// blocks, skipping what the block reserves.
#[tokio::test]
async fn a_device_is_given_a_slot_and_an_address() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let device = register_vpn_device(&db, &plan, " phone ", &key(1)).await?;

    assert_eq!(device.slot, 0);
    assert_eq!(device.name, "phone", "the label is trimmed, not stored raw");
    let p = peer(&db, &device).await?;
    assert!(p.enabled);
    assert_usable(p.address4.as_deref(), "10.64.0.0/28", 32);
    assert_usable(p.address6.as_deref(), "fd00:64::/124", 128);
    assert_eq!(p.peer_pubkey.as_deref(), Some(&key(1)[..]));
    assert_eq!(p.pool_id, None, "a device is a peer on every interface");
    assert_eq!(p.router_id, None);

    // A second device does not collide with the first.
    let other = register_vpn_device(&db, &plan, "laptop", &key(2)).await?;
    let op = peer(&db, &other).await?;
    assert_eq!(other.slot, 1);
    assert_ne!(op.address4, p.address4);
    assert_ne!(op.address6, p.address6);
    Ok(())
}

/// A client that retries a request whose response it lost must get the device
/// it already has, not a second one burning another slot.
#[tokio::test]
async fn registering_the_same_key_twice_is_idempotent() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let first = register_vpn_device(&db, &plan, "phone", &key(1)).await?;
    let again = register_vpn_device(&db, &plan, "phone", &key(1)).await?;

    assert_eq!(first.id, again.id);
    assert_eq!(first.tunnel_id, again.tunnel_id);
    assert_eq!(db.list_vpn_devices(plan.id).await?.len(), 1);
    Ok(())
}

/// A key belongs to one account. Moving it on request would let anybody who
/// learned a public key take over the address behind it.
#[tokio::test]
async fn a_key_registered_elsewhere_is_refused() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let mine = a_plan(&db, &service, 1).await?;
    let theirs = a_plan(&db, &service, 2).await?;

    register_vpn_device(&db, &mine, "phone", &key(1)).await?;
    let err = register_vpn_device(&db, &theirs, "steal", &key(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("another account"), "{err}");
    Ok(())
}

/// Anything that is not a 32-byte key would be configured on every route server
/// and authenticate nobody.
#[tokio::test]
async fn a_key_that_is_not_a_key_is_refused() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let err = register_vpn_device(&db, &plan, "phone", &[1, 2, 3])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("32 bytes"), "{err}");
    Ok(())
}

/// Disabling a service stops new devices without touching the ones already
/// allocated and configured.
#[tokio::test]
async fn a_disabled_service_takes_no_new_devices() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;
    register_vpn_device(&db, &plan, "phone", &key(1)).await?;

    db.update_vpn_service(&VpnService {
        enabled: false,
        ..service.clone()
    })
    .await?;

    let err = register_vpn_device(&db, &plan, "laptop", &key(2))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not accepting new devices"), "{err}");
    // The device that already exists is untouched.
    assert_eq!(db.list_vpn_devices(plan.id).await?.len(), 1);
    Ok(())
}

/// The plan's limit is what is sold, and slots are reused so removing a device
/// and adding another does not walk off the end of it.
#[tokio::test]
async fn the_device_limit_is_the_plan_limit() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service_limited(&db, &mock, 2).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let a = register_vpn_device(&db, &plan, "a", &key(1)).await?;
    let b = register_vpn_device(&db, &plan, "b", &key(2)).await?;
    assert_eq!((a.slot, b.slot), (0, 1));

    let err = register_vpn_device(&db, &plan, "c", &key(3))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("limited to 2 devices"), "{err}");

    // Freeing the lower slot means the next device takes it back.
    db.delete_vpn_device(a.id).await?;
    let c = register_vpn_device(&db, &plan, "c", &key(3)).await?;
    assert_eq!(c.slot, 0);
    Ok(())
}

/// A one-device plan must not say "1 devices".
#[test]
fn the_limit_message_is_not_written_by_a_robot() {
    let err = next_free_slot(
        &[VpnDevice {
            slot: 0,
            ..Default::default()
        }],
        1,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("limited to 1 device;"), "{err}");
}

/// A lapsed customer's address is still theirs. Reissuing it would deliver
/// their traffic to somebody else the moment they paid again.
#[tokio::test]
async fn an_unpaid_devices_address_is_not_reissued() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;

    let lapsed = a_plan_with(&db, &service, 1, 5, false).await?;
    let held = peer(
        &db,
        &register_vpn_device(&db, &lapsed, "old", &key(1)).await?,
    )
    .await?;

    let paying = a_plan(&db, &service, 2).await?;
    let fresh = peer(
        &db,
        &register_vpn_device(&db, &paying, "new", &key(2)).await?,
    )
    .await?;

    assert_ne!(fresh.address4, held.address4);
    assert_ne!(fresh.address6, held.address6);
    Ok(())
}

/// A single-stack service allocates the family it has and nothing else, rather
/// than failing or inventing the other half.
#[tokio::test]
async fn a_v6_only_service_gives_v6_only() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let id = db
        .insert_vpn_service(&VpnService {
            name: "v6".to_string(),
            company_id: a_company(&mock).await,
            default_device_limit: 5,
            device_cidr6: Some("fd00:99::/120".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await?;
    let service = db.get_vpn_service(id).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let p = peer(
        &db,
        &register_vpn_device(&db, &plan, "phone", &key(1)).await?,
    )
    .await?;
    assert_eq!(p.address4, None);
    assert_usable(p.address6.as_deref(), "fd00:99::/120", 128);
    Ok(())
}

/// Running out of block is an error naming the fix, not a device with no
/// address that looks configured.
#[tokio::test]
async fn an_exhausted_block_says_so() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    // /30: network, server, broadcast and exactly one usable address.
    let id = db
        .insert_vpn_service(&VpnService {
            name: "tiny".to_string(),
            company_id: a_company(&mock).await,
            default_device_limit: 5,
            device_cidr4: Some("10.70.0.0/30".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await?;
    let service = db.get_vpn_service(id).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let only = peer(&db, &register_vpn_device(&db, &plan, "a", &key(1)).await?).await?;
    assert_eq!(only.address4.as_deref(), Some("10.70.0.2/32"));

    let err = register_vpn_device(&db, &plan, "b", &key(2))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no free /32"), "{err}");
    assert!(err.contains("widen the block"), "{err}");
    Ok(())
}

/// A block that is not a block is the admin's mistake, and has to be reported
/// as one rather than as "no addresses left".
#[tokio::test]
async fn an_unparseable_block_is_reported_as_one() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let id = db
        .insert_vpn_service(&VpnService {
            name: "broken".to_string(),
            company_id: a_company(&mock).await,
            default_device_limit: 5,
            device_cidr4: Some("not-a-cidr".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await?;
    let service = db.get_vpn_service(id).await?;
    let plan = a_plan(&db, &service, 1).await?;

    let err = register_vpn_device(&db, &plan, "a", &key(1))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("unparseable block"), "{err}");
    Ok(())
}

/// Every interface on a service carries the same peers, addresses and routes.
/// The route servers' own address comes from the service's block, so a device's
/// gateway does not change when it switches region.
#[tokio::test]
async fn a_vpn_interface_carries_the_services_devices() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let pool = a_pool(&db, &mock, &service).await?;
    let plan = a_plan(&db, &service, 1).await?;
    let device = register_vpn_device(&db, &plan, "phone", &key(1)).await?;
    let p = peer(&db, &device).await?;

    let out = crate::provisioner::plan_pool(&db, &pool).await?;

    assert_eq!(
        out.addresses,
        vec!["10.64.0.1/28".to_string(), "fd00:64::1/124".to_string()],
        "one shared gateway per family, carrying the block's prefix"
    );
    assert_eq!(
        out.routes,
        vec!["10.64.0.0/28".to_string(), "fd00:64::/124".to_string()],
        "an address alone gives the kernel no route to the rest of the prefix"
    );
    assert_eq!(out.peers.len(), 1);
    let wg = &out.peers[0];
    assert_eq!(
        wg.public_key,
        lnvps_api_common::wireguard_key_to_base64(&key(1))
    );
    assert_eq!(
        wg.allowed_ips,
        vec![p.address4.clone().unwrap(), p.address6.clone().unwrap()],
        "a device may claim its own addresses and nothing else"
    );
    assert_eq!(wg.endpoint, None, "clients dial out from behind NAT");
    Ok(())
}

/// Suspension is applied by the planner, so a lapsed customer's peers leave the
/// route server without anybody having had to disable them.
#[tokio::test]
async fn an_unpaid_plans_devices_are_not_configured() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let pool = a_pool(&db, &mock, &service).await?;

    let paid = a_plan(&db, &service, 1).await?;
    register_vpn_device(&db, &paid, "paid", &key(1)).await?;
    let unpaid = a_plan_with(&db, &service, 2, 5, false).await?;
    register_vpn_device(&db, &unpaid, "unpaid", &key(2)).await?;

    let out = crate::provisioner::plan_pool(&db, &pool).await?;
    assert_eq!(out.peers.len(), 1);
    assert_eq!(
        out.peers[0].public_key,
        lnvps_api_common::wireguard_key_to_base64(&key(1))
    );
    Ok(())
}

/// A VPN device has nothing behind it, so its AllowedIPs is exactly its own
/// addresses. Anything else would be a route the customer was never given.
#[tokio::test]
async fn a_vpn_peer_carries_nothing_behind_it() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let pool = a_pool(&db, &mock, &service).await?;
    let plan = a_plan(&db, &service, 1).await?;
    let device = register_vpn_device(&db, &plan, "phone", &key(1)).await?;
    let p = peer(&db, &device).await?;

    let out = crate::provisioner::plan_pool(&db, &pool).await?;
    assert_eq!(out.peers[0].allowed_ips.len(), 2);
    // In particular no probe address: that is a marketplace node's, derived by
    // offsetting its v6 address, and with random placement it could land on
    // another customer's real address.
    assert!(
        !out.peers[0]
            .allowed_ips
            .iter()
            .any(|a| a != p.address4.as_deref().unwrap() && a != p.address6.as_deref().unwrap()),
        "{:?}",
        out.peers[0].allowed_ips
    );
    // And the block itself is routed, but no per-peer routes beyond it.
    assert_eq!(out.routes.len(), 2);
    Ok(())
}

/// A pool records nothing about what it is for, so the generic planner has to
/// dispatch on the link. An unlinked pool must keep behaving exactly as it did
/// before VPNs existed.
#[tokio::test]
async fn plan_pool_dispatches_on_the_service_link() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;
    register_vpn_device(&db, &plan, "phone", &key(1)).await?;
    let pool = a_pool(&db, &mock, &service).await?;

    let linked = crate::provisioner::plan_pool(&db, &pool).await?;
    assert_eq!(
        linked.addresses,
        vec!["10.64.0.1/28".to_string(), "fd00:64::1/124".to_string()],
        "a VPN interface is addressed from the service, not from its own block"
    );
    assert_eq!(linked.peers.len(), 1);

    // Unlinking returns it to an ordinary pool, addressed from its own block
    // and carrying the tunnels carved out of it — of which there are none.
    db.unlink_vpn_service_pool(pool.id).await?;
    let unlinked = crate::provisioner::plan_pool(&db, &pool).await?;
    assert_eq!(unlinked.addresses, vec!["10.200.0.1/24".to_string()]);
    assert!(unlinked.peers.is_empty());
    Ok(())
}

/// Losing a race for a slot must not surface as an error to a customer whose
/// next slot is free. The interleave is forced rather than hoped for: holding
/// the plans lock stops the allocator inside its address carve, *after* it has
/// proposed a slot, so a device inserted in the meantime takes the slot it was
/// about to use.
#[tokio::test]
async fn a_lost_slot_race_takes_the_next_slot() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;

    // Block the allocator part-way through: it has listed the devices (none)
    // and proposed slot 0, and is now waiting to read the service's devices.
    let plans = mock.vpn_subscriptions.lock().await;
    let racer = {
        let db = db.clone();
        let plan = plan.clone();
        tokio::spawn(async move { register_vpn_device(&db, &plan, "phone", &[1u8; 32]).await })
    };
    tokio::task::yield_now().await;

    // Somebody else takes slot 0 out from under it.
    mock.vpn_devices.lock().await.insert(
        99,
        VpnDevice {
            id: 99,
            vpn_subscription_id: plan.id,
            slot: 0,
            name: "raced".to_string(),
            tunnel_id: 12345,
            created: chrono::Utc::now(),
        },
    );
    drop(plans);

    let device = racer.await??;
    assert_eq!(device.slot, 1, "the loser re-reads and takes the next slot");
    assert_usable(
        peer(&db, &device).await?.address4.as_deref(),
        "10.64.0.0/28",
        32,
    );
    Ok(())
}

/// If every attempt loses, that is not contention any more and looping harder
/// would only hide it, so it is reported.
///
/// Reached by giving two services overlapping blocks, which the schema permits:
/// the carve only sees its own service's devices, so it keeps proposing
/// addresses the *global* unique index already refuses. That is a
/// misconfiguration, and it has to fail loudly rather than quietly handing two
/// customers one address.
#[tokio::test]
async fn overlapping_service_blocks_fail_loudly() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let plan = a_plan(&db, &service, 1).await?;

    // Every address in the shared block, held as peers this service's carve
    // cannot see but the unique index still can, so every insert collides
    // however many times the carve re-reads.
    for host in 0..16u8 {
        let _ = db
            .insert_tunnel(&lnvps_db::Tunnel {
                kind: lnvps_db::RouterTunnelKind::Wireguard,
                user_id: plan.user_id,
                name: format!("squat-{host}"),
                peer_pubkey: Some(vec![100 + host; 32]),
                address4: Some(format!("10.64.0.{host}/32")),
                address6: Some(format!("fd00:64::{host:x}/128")),
                enabled: true,
                ..Default::default()
            })
            .await;
    }

    let err = register_vpn_device(&db, &plan, "phone", &[1u8; 32])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("after 4 attempts"),
        "an overlapping block must be reported, not worked around: {err}"
    );
    Ok(())
}

/// A service fills its block from the bottom, so by the time it is busy the
/// first free address is at position `n` and every earlier one has to be
/// stepped over. This is the shape that made the allocator quadratic: at 20k
/// devices a single registration cost 355ms of CPU, quadrupling with each
/// doubling of `n`. The cursor in `allocate_subnet` brought that to 5.5ms.
///
/// Asserted on the answer rather than the clock, so it cannot flake on a busy
/// machine; what it guards is that the cursor still steps over a dense block
/// correctly, which is the part of that change with any risk in it.
#[test]
fn a_dense_block_allocates_the_first_free_address() {
    use ipnetwork::IpNetwork;

    const N: u32 = 20_000;
    let block: IpNetwork = "10.64.0.0/12".parse().unwrap();
    let mut taken = crate::provisioner::reserved_addresses("10.64.0.0/12");
    taken.extend((0..N).map(|i| {
        let a = std::net::Ipv4Addr::from(0x0a40_0000u32 + 2 + i);
        IpNetwork::new(std::net::IpAddr::V4(a), 32).unwrap()
    }));

    // .0 is the network address and .1 the gateway, so N devices occupy
    // .2 .. .2+N-1 and the next free address is .2+N.
    let expected = std::net::Ipv4Addr::from(0x0a40_0000u32 + 2 + N);
    assert_eq!(
        crate::provisioner::allocate_subnet(&block, 32, &taken).map(|n| n.ip().to_string()),
        Some(expected.to_string())
    );
}
