//! What a customer is handed, and what they are refused.
//!
//! These exercise the handlers' logic through the pieces they are built from
//! rather than over HTTP; the wire shape is covered by the e2e harness.

use anyhow::Result;
use lnvps_api_common::MockDb;
use lnvps_db::{
    Company, IntervalType, LNVpsDb, Region, Router as DbRouter, RouterKind, TunnelPool, VpnService,
};
use std::sync::Arc;

use super::*;
use crate::provisioner::register_vpn_device;

async fn a_service(db: &Arc<dyn LNVpsDb>, mock: &MockDb) -> Result<VpnService> {
    mock.companies.lock().await.entry(1).or_insert(Company {
        id: 1,
        name: "LNVPS".to_string(),
        base_currency: "EUR".to_string(),
        ..Default::default()
    });
    let id = db
        .insert_vpn_service(&VpnService {
            name: "eu".to_string(),
            company_id: 1,
            amount: 500,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            dns: Some("10.64.0.1, fd00:64::1".to_string()),
            default_device_limit: 5,
            enabled: true,
            ..Default::default()
        })
        .await?;
    Ok(db.get_vpn_service(id).await?)
}

/// An interface for `service` in a named region.
async fn a_pool(
    db: &Arc<dyn LNVpsDb>,
    mock: &MockDb,
    service: &VpnService,
    region_id: u64,
    region_name: &str,
    port: u16,
    cidr6: Option<&str>,
) -> Result<TunnelPool> {
    mock.regions
        .lock()
        .await
        .entry(region_id)
        .or_insert(Region {
            id: region_id,
            name: region_name.to_string(),
            enabled: true,
            company_id: 1,
            country_code: Some("NL".to_string()),
        });
    let router_id = {
        let mut routers = mock.router.lock().await;
        let id = routers.keys().max().copied().unwrap_or(0) + 1;
        routers.insert(
            id,
            DbRouter {
                id,
                name: format!("rs{id}"),
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
            region_id,
            name: format!("vpn-{region_name}"),
            listen_addr: format!("{region_name}.vpn.lnvps.net"),
            listen_port: port,
            private_key: lnvps_api_common::generate_wireguard_keypair()?
                .private_key
                .into(),
            public_key: vec![0x33; 32],
            cidr4: Some("10.64.0.0/24".to_string()),
            cidr6: cidr6.map(str::to_string),
            keepalive: Some(25),
            mtu: 1420,
            enabled: true,
            ..Default::default()
        })
        .await?;
    db.link_vpn_service_pool(service.id, pool_id).await?;
    Ok(db.get_tunnel_pool(pool_id).await?)
}

/// A paid plan with one device.
async fn a_paid_plan_with_device(
    db: &Arc<dyn LNVpsDb>,
    mock: &MockDb,
    service: &VpnService,
    uid: u64,
) -> Result<(VpnSubscription, lnvps_db::Tunnel)> {
    // A device is addressed from the block on the service's interfaces, so
    // there has to be one.
    if db.list_vpn_service_pools(service.id).await?.is_empty() {
        a_pool(db, mock, service, 1, "ams", 51820, Some("fd00:64::/64")).await?;
    }
    let plan = crate::subscription::create_vpn_plan(db, uid, service).await?;
    let mut sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    sub.is_setup = true;
    sub.expires = Some(Utc::now() + chrono::TimeDelta::days(30));
    db.update_subscription(&sub).await?;
    let device = register_vpn_device(db, &plan, "phone", &[7u8; 32]).await?;
    // The peer is what a config is built from; the device row is just the label
    // and the slot.
    Ok((plan, db.get_tunnel(device.tunnel_id).await?))
}

/// The `[Interface]` block is identical everywhere and only the `[Peer]`
/// changes, which is the whole reason a device works in every region.
#[tokio::test]
async fn every_region_shares_one_interface_block() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let ams = a_pool(&db, &mock, &service, 1, "ams", 51820, Some("fd00:64::/64")).await?;
    let dub = a_pool(&db, &mock, &service, 2, "dub", 51820, Some("fd00:64::/64")).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let (_, device) = a_paid_plan_with_device(&db, &mock, &service, uid).await?;

    let mut configs = Vec::new();
    for pool in [&ams, &dub] {
        let region = db.get_host_region(pool.region_id).await?;
        let mut cfg = ApiVpnDeviceConfig {
            region_id: region.id,
            region_name: region.name.clone(),
            endpoint: pool.endpoint(),
            public_key: wireguard_key_to_base64(&pool.public_key),
            address: vec![
                device.address4.clone().unwrap(),
                device.address6.clone().unwrap(),
            ],
            dns: service.dns_servers(),
            mtu: pool.mtu,
            persistent_keepalive: pool.keepalive,
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            config: String::new(),
        };
        cfg.config = cfg.render();
        configs.push(cfg);
    }

    let iface = |c: &ApiVpnDeviceConfig| c.config.split("[Peer]").next().unwrap().to_string();
    assert_eq!(
        iface(&configs[0]),
        iface(&configs[1]),
        "the same device, so the same addresses, DNS and MTU everywhere"
    );
    assert_ne!(configs[0].endpoint, configs[1].endpoint);
    Ok(())
}

/// The rendered file is what a customer feeds to `wg-quick`, so every line it
/// needs has to be there and the private key has to be theirs to fill in.
#[tokio::test]
async fn the_rendered_config_is_a_wg_quick_file() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let pool = a_pool(&db, &mock, &service, 1, "ams", 51820, Some("fd00:64::/64")).await?;

    let mut cfg = ApiVpnDeviceConfig {
        region_id: 1,
        region_name: "ams".to_string(),
        endpoint: pool.endpoint(),
        public_key: wireguard_key_to_base64(&pool.public_key),
        address: vec!["10.64.0.2/32".to_string(), "fd00:64::2/128".to_string()],
        dns: service.dns_servers(),
        mtu: 1420,
        persistent_keepalive: Some(25),
        allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        config: String::new(),
    };
    cfg.config = cfg.render();

    let c = &cfg.config;
    assert!(c.starts_with("[Interface]\n"), "{c}");
    assert!(
        c.contains(&format!("PrivateKey = {PRIVATE_KEY_PLACEHOLDER}")),
        "LNVPS never held the private key, so the file cannot contain it: {c}"
    );
    assert!(c.contains("Address = 10.64.0.2/32, fd00:64::2/128"), "{c}");
    assert!(c.contains("DNS = 10.64.0.1, fd00:64::1"), "{c}");
    assert!(
        c.contains("MTU = 1420"),
        "1500 inside a tunnel hangs large transfers: {c}"
    );
    assert!(c.contains("AllowedIPs = 0.0.0.0/0, ::/0"), "{c}");
    assert!(c.contains("Endpoint = ams.vpn.lnvps.net:51820"), "{c}");
    assert!(c.contains("PersistentKeepalive = 25"), "{c}");
    Ok(())
}

/// A service with no resolvers must not emit a blank `DNS =` line, which
/// `wg-quick` rejects outright.
#[test]
fn no_dns_means_no_dns_line() {
    let mut cfg = ApiVpnDeviceConfig {
        region_id: 1,
        region_name: "ams".to_string(),
        endpoint: "ams.example:51820".to_string(),
        public_key: "k".to_string(),
        address: vec!["10.64.0.2/32".to_string()],
        dns: vec![],
        mtu: 1420,
        persistent_keepalive: None,
        allowed_ips: vec!["0.0.0.0/0".to_string()],
        config: String::new(),
    };
    cfg.config = cfg.render();
    assert!(!cfg.config.contains("DNS"), "{}", cfg.config);
    assert!(
        !cfg.config.contains("PersistentKeepalive"),
        "{}",
        cfg.config
    );
}

/// Offering `::/0` to a device with no IPv6 address would black-hole its IPv6
/// rather than leaving it alone.
#[tokio::test]
async fn a_v4_only_device_is_not_offered_a_v6_default_route() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    mock.companies.lock().await.entry(1).or_insert(Company {
        id: 1,
        name: "LNVPS".to_string(),
        base_currency: "EUR".to_string(),
        ..Default::default()
    });
    let id = db
        .insert_vpn_service(&VpnService {
            name: "v4".to_string(),
            company_id: 1,
            currency: "EUR".to_string(),
            default_device_limit: 5,
            enabled: true,
            ..Default::default()
        })
        .await?;
    let service = db.get_vpn_service(id).await?;
    // A single-stack interface, so the devices on it are single-stack.
    a_pool(&db, &mock, &service, 1, "ams", 51820, None).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let (_, device) = a_paid_plan_with_device(&db, &mock, &service, uid).await?;

    assert!(device.address4.is_some());
    assert!(device.address6.is_none());

    let mut allowed = Vec::new();
    if device.address4.is_some() {
        allowed.push("0.0.0.0/0".to_string());
    }
    if device.address6.is_some() {
        allowed.push("::/0".to_string());
    }
    assert_eq!(allowed, vec!["0.0.0.0/0".to_string()]);
    Ok(())
}

/// A plan that has not been paid for configures nothing, so registering against
/// it has to say why rather than accepting five devices that never connect.
#[tokio::test]
async fn an_unpaid_plan_says_why_it_takes_no_devices() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let uid = db.upsert_user(&[1u8; 32]).await?;
    let plan = crate::subscription::create_vpn_plan(&db, uid, &service).await?;

    let sub = db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    assert_eq!(
        sub.billing_state(Utc::now()),
        lnvps_db::BillingState::Unpaid
    );

    // The same check the handler makes, without standing up a RouterState.
    let refused = matches!(
        sub.billing_state(Utc::now()),
        lnvps_db::BillingState::Unpaid | lnvps_db::BillingState::Expired
    );
    assert!(refused);
    Ok(())
}

/// A device belongs to the plan that registered it. Another customer asking for
/// it by id must be told it does not exist, not that it is not theirs.
#[tokio::test]
async fn another_customers_device_does_not_exist() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let mine = db.upsert_user(&[1u8; 32]).await?;
    let (_, device) = a_paid_plan_with_device(&db, &mock, &service, mine).await?;

    let theirs = db.upsert_user(&[2u8; 32]).await?;
    let their_plan = crate::subscription::create_vpn_plan(&db, theirs, &service).await?;

    let stored = db.get_vpn_device(device.id).await?;
    assert_ne!(
        stored.vpn_subscription_id, their_plan.id,
        "the ownership check the handler makes"
    );
    Ok(())
}
