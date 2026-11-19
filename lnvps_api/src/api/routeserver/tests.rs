//! What a route server is told, and what it is refused.
//!
//! These drive the pieces the handler is built from rather than going over
//! HTTP; the wire shape is the e2e harness's job. What is worth asserting here
//! is that the document says nothing about who a peer is, and that the
//! generation moves when, and only when, the peer set does.

use anyhow::Result;
use lnvps_api_common::MockDb;
use lnvps_db::{
    Company, IntervalType, LNVpsDb, Region, Router as DbRouter, RouterKind, TunnelPool, VpnService,
};
use std::sync::Arc;

use super::*;

async fn a_route_server(mock: &MockDb, kind: RouterKind) -> u64 {
    let mut routers = mock.router.lock().await;
    let id = routers.keys().max().copied().unwrap_or(0) + 1;
    routers.insert(
        id,
        DbRouter {
            id,
            name: format!("rs{id}"),
            enabled: true,
            kind,
            url: String::new(),
            token: "s3cret".into(),
        },
    );
    id
}

async fn a_service(db: &Arc<dyn LNVpsDb>, mock: &MockDb) -> Result<VpnService> {
    mock.companies.lock().await.entry(1).or_insert(Company {
        id: 1,
        name: "LNVPS".to_string(),
        base_currency: "EUR".to_string(),
        ..Default::default()
    });
    mock.regions.lock().await.entry(1).or_insert(Region {
        id: 1,
        name: "ams".to_string(),
        enabled: true,
        company_id: 1,
        country_code: Some("NL".to_string()),
    });
    let id = db
        .insert_vpn_service(&VpnService {
            name: "eu".to_string(),
            company_id: 1,
            amount: 500,
            currency: "EUR".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            default_device_limit: 5,
            enabled: true,
            ..Default::default()
        })
        .await?;
    Ok(db.get_vpn_service(id).await?)
}

async fn a_pool(
    db: &Arc<dyn LNVpsDb>,
    service: &VpnService,
    router_id: u64,
    port: u16,
    enabled: bool,
) -> Result<TunnelPool> {
    let id = db
        .insert_tunnel_pool(&TunnelPool {
            router_id,
            region_id: 1,
            name: format!("vpn-{port}"),
            listen_addr: "ams.vpn.lnvps.net".to_string(),
            listen_port: port,
            private_key: lnvps_api_common::generate_wireguard_keypair()?
                .private_key
                .into(),
            public_key: vec![0x33; 32],
            cidr4: Some("10.64.0.0/24".to_string()),
            cidr6: Some("fd00:64::/64".to_string()),
            keepalive: Some(25),
            mtu: 1420,
            enabled,
            ..Default::default()
        })
        .await?;
    db.link_vpn_service_pool(service.id, id).await?;
    Ok(db.get_tunnel_pool(id).await?)
}

#[test]
fn the_document_generation_is_the_highest_interface() {
    let pool = |generation| TunnelPool {
        generation,
        ..Default::default()
    };
    // Taking the highest is what stops removing an interface from lowering the
    // number: a route server that was handed a lower one than it had applied
    // would either loop or go quiet, depending on which way it compared.
    assert_eq!(current_generation(&[pool(3), pool(9), pool(1)]), 9);
    // A route server with nothing to run is still answered, and its `0` is
    // below the `1` every pool starts at, so it is never told to wait forever.
    assert_eq!(current_generation(&[]), 0);
}

#[tokio::test]
async fn a_route_server_is_told_only_about_its_own_interfaces() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;

    let mine = a_route_server(&mock, RouterKind::Lvd).await;
    let theirs = a_route_server(&mock, RouterKind::Lvd).await;
    let a = a_pool(&db, &service, mine, 51820, true).await?;
    a_pool(&db, &service, theirs, 51821, true).await?;

    let pools = route_server_pools(&db, mine).await.unwrap();
    assert_eq!(pools.iter().map(|p| p.id).collect::<Vec<_>>(), vec![a.id]);
    Ok(())
}

#[tokio::test]
async fn a_disabled_interface_is_withheld_rather_than_flagged() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let rs = a_route_server(&mock, RouterKind::Lvd).await;
    let pool = a_pool(&db, &service, rs, 51820, true).await?;

    assert_eq!(route_server_pools(&db, rs).await.unwrap().len(), 1);

    let mut off = db.get_tunnel_pool(pool.id).await?;
    off.enabled = false;
    db.update_tunnel_pool(&off).await?;

    // Not sent with `enabled: false`: a route server has no use for an
    // interface it must not bring up, and sending one hands a private key to a
    // machine with no reason to hold it.
    assert!(route_server_pools(&db, rs).await.unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn the_generation_moves_when_the_peer_set_does() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let rs = a_route_server(&mock, RouterKind::Lvd).await;
    let pool = a_pool(&db, &service, rs, 51820, true).await?;

    let before = current_generation(&route_server_pools(&db, rs).await.unwrap());

    db.bump_tunnel_pool_generation(pool.id).await?;

    let after = current_generation(&route_server_pools(&db, rs).await.unwrap());
    assert!(
        after > before,
        "a route server holding {before} must be woken by a bump, got {after}"
    );
    Ok(())
}

#[tokio::test]
async fn the_document_says_nothing_about_who_a_peer_is() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let rs = a_route_server(&mock, RouterKind::Lvd).await;
    let pool = a_pool(&db, &service, rs, 51820, true).await?;

    let iface = desired_interface(&db, &pool).await.unwrap();

    // Serialised and read back as text, because what matters is what crosses
    // the wire and would be found on a seized machine, not what the struct
    // happens to be called.
    let json = serde_json::to_string(&iface)?;
    for leaked in ["user", "subscription", "device", "name", "slot", "email"] {
        assert!(
            !json.contains(leaked),
            "the document must not carry {leaked}: {json}"
        );
    }
    assert_eq!(iface.pool_id, pool.id);
    assert_eq!(iface.listen_port, 51820);
    Ok(())
}

#[tokio::test]
async fn a_bump_is_announced_where_a_waiting_route_server_is_listening() -> Result<()> {
    let mock = MockDb::default();
    let db: Arc<dyn LNVpsDb> = Arc::new(mock.clone());
    let service = a_service(&db, &mock).await?;
    let rs = a_route_server(&mock, RouterKind::Lvd).await;
    let pool = a_pool(&db, &service, rs, 51820, true).await?;

    // The two ends compute the channel from the same constructor, which is the
    // whole reason that constructor exists: a bump announced where nobody is
    // subscribed is a route server that waits out its deadline for a change
    // that already happened.
    let announced = lnvps_api_common::JobFeedback::channel_name(
        &lnvps_api_common::JobFeedback::tunnel_pool_job_id(pool.id),
    );
    assert_eq!(
        announced,
        format!("worker:feedback:tunnel_pool:{}", pool.id)
    );

    let listening = route_server_pools(&db, rs)
        .await
        .unwrap()
        .into_iter()
        .map(|p| {
            lnvps_api_common::JobFeedback::channel_name(
                &lnvps_api_common::JobFeedback::tunnel_pool_job_id(p.id),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(listening, vec![announced]);
    Ok(())
}
