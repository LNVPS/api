//! What a probe builds, and what it must never build.

use lnvps_api_common::MockDb;
use lnvps_db::{
    LNVpsDbBase, MarketplaceNodeStatus, MarketplaceOperator, Router, RouterKind, TunnelPool,
    VmHostKind,
};

use super::*;

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA probe";

/// A pool for the node's region, with a v6 block: a probe is IPv6 only, so a
/// pool without one is a region that cannot be probed at all.
async fn a_pool(db: &Arc<dyn LNVpsDb>, mock: &MockDb) -> Result<u64> {
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
    Ok(db
        .insert_tunnel_pool(&TunnelPool {
            router_id,
            region_id: 1,
            name: "pool".to_string(),
            listen_addr: "rs.example".to_string(),
            listen_port: 51820,
            private_key: lnvps_api_common::generate_wireguard_keypair()?
                .private_key
                .into(),
            public_key: vec![0x33; 32],
            cidr4: Some("10.66.0.0/24".to_string()),
            cidr6: Some("fd00:66::/64".to_string()),
            keepalive: Some(25),
            mtu: 1420,
            enabled: true,
            ..Default::default()
        })
        .await?)
}

/// A template and an image for the region, because a probe deliberately uses
/// what customers are sold rather than a shape of its own.
async fn a_catalogue(mock: &MockDb) {
    mock.templates.lock().await.insert(
        1,
        lnvps_db::VmTemplate {
            cpu_arch: lnvps_db::CpuArch::X86_64,
            ..MockDb::mock_template()
        },
    );
    // An image for an architecture this template cannot run. Present so the
    // choice below has to be made rather than fallen into: an x86 image on an
    // arm host does not boot, and the probe would report a broken node.
    mock.os_images.lock().await.insert(
        2,
        lnvps_db::VmOsImage {
            id: 2,
            enabled: true,
            release_date: chrono::Utc::now() + chrono::Duration::days(1),
            url: "https://example.com/debian_12_arm.img".to_string(),
            cpu_arch: lnvps_db::CpuArch::ARM64,
            distribution: lnvps_db::OsDistribution::Debian,
            flavour: "server".to_string(),
            version: "12".to_string(),
            default_username: Some("debian".to_string()),
            sha2: None,
            sha2_url: None,
        },
    );
    mock.os_images.lock().await.insert(
        1,
        lnvps_db::VmOsImage {
            id: 1,
            distribution: lnvps_db::OsDistribution::Debian,
            flavour: "server".to_string(),
            version: "12".to_string(),
            enabled: true,
            release_date: chrono::Utc::now(),
            url: "https://example.com/debian_12.img".to_string(),
            cpu_arch: lnvps_db::CpuArch::X86_64,
            default_username: Some("debian".to_string()),
            sha2: None,
            sha2_url: None,
        },
    );
}

/// Hands out a node id no other test in this binary will use.
///
/// A probe's VM id is derived from its node id, and every test builds a fresh
/// `MockDb` whose ids restart at 1 — so without this every probe test works on
/// the *same* VM id. The dummy host keys VMs by id in a process-wide map (see
/// `DummyVmHost::new_persistent`; `get_host_client`'s `cfg!(test)` arm never
/// fires, because this crate is compiled as a dependency where `cfg(test)` is
/// false), so those tests were creating, deleting and asserting against each
/// other's VMs. Ordering hid it while every delete was inline; a delete issued
/// from `ProbeVmGuard`'s `Drop` lands whenever the runtime next polls, which
/// can be inside another test's create/assert window.
///
/// Counter rather than a per-test constant so a test added later cannot
/// silently reintroduce the collision by picking a number already in use.
fn a_unique_node_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

async fn a_node(db: &Arc<dyn LNVpsDb>) -> Result<MarketplaceNode> {
    let user_id = db.upsert_user(&[5u8; 32]).await?;
    let operator_id = db
        .insert_marketplace_operator(&MarketplaceOperator {
            user_id,
            enabled: true,
            ..Default::default()
        })
        .await?;
    // `MockDb` assigns `max(id) + 1` and ignores the id it is handed, so the
    // only way to land on a chosen id is to fill the ones below it. The
    // placeholders are left `Pending`, which is the default: `probe_candidates`
    // lists only approved nodes, so they cannot alter which node a selection
    // test picks.
    let wanted = a_unique_node_id();
    for _ in 1..wanted {
        db.insert_marketplace_node(&MarketplaceNode {
            operator_id,
            name: "placeholder".to_string(),
            ..Default::default()
        })
        .await?;
    }
    let node_id = db
        .insert_marketplace_node(&MarketplaceNode {
            operator_id,
            name: "rack 1".to_string(),
            status: MarketplaceNodeStatus::Approved,
            ..Default::default()
        })
        .await?;
    assert_eq!(
        node_id, wanted,
        "a test did not get the node id it reserved"
    );
    db.create_host(&lnvps_db::VmHost {
        kind: VmHostKind::MarketplaceNode,
        region_id: 1,
        name: "node".to_string(),
        enabled: false,
        marketplace_node_id: Some(node_id),
        ..Default::default()
    })
    .await?;
    let node = db.get_marketplace_node(node_id).await?;
    super::super::allocate_node_tunnel(db, &node, &[7u8; 32]).await?;
    db.get_marketplace_node(node_id).await.map_err(Into::into)
}

/// A probe's id is outside anything an AUTO_INCREMENT column could ever issue.
///
/// Domains are named from the VM id and `delete_vm` finds a domain by that name,
/// so a probe sharing an id with a customer's VM would destroy a customer's
/// disk. This is the assertion that makes that impossible rather than unlikely.
#[test]
fn a_probe_id_can_never_be_a_customers() {
    let id = probe_vm_id(1);

    assert!(is_probe(id));
    assert!(id > u32::MAX as u64, "well past any real vm id");
    // A database issuing a billion VMs a year would need eighteen million years
    // to reach this range.
    assert!(!is_probe(1_000_000_000));
    assert!(!is_probe(u32::MAX as u64));
}

/// Every node's probe has its own id, so two probes running at once cannot name
/// the same domain — and a probe cannot delete another node's.
#[test]
fn each_node_has_its_own_probe_id() {
    assert_ne!(probe_vm_id(1), probe_vm_id(2));
    assert_eq!(probe_vm_id(9), probe_vm_id(9), "stable across runs");
}

/// The id is stable, which is what lets a probe left by a killed process be
/// cleaned up by the next one instead of accumulating.
#[test]
fn a_stale_probe_is_findable() {
    let first = probe_vm_id(3);
    let later = probe_vm_id(3);
    assert_eq!(first, later);
}

/// A probe is built from what the region actually sells. A dedicated probe
/// shape would be one more thing to keep in step, and a node could pass on it
/// while failing on everything a customer can buy.
#[tokio::test]
async fn a_probe_uses_what_customers_buy() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;

    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    let templates = db.list_vm_templates().await?;
    assert!(
        templates.iter().any(|t| t.id == spec.template.id),
        "the probe must use a real, sellable template"
    );
    assert!(db.get_os_image(spec.image.id).await.is_ok());
    // An image the template's architecture can actually run, even though a
    // newer one exists for another: an x86 image on an arm host does not boot,
    // and the probe would report the node broken.
    assert_eq!(spec.image.cpu_arch, spec.template.cpu_arch);
    // The cheapest of them: a probe is a cost we bear, and the smallest shape
    // still proves the machine can build, boot and serve a guest.
    let smallest = templates
        .iter()
        .filter(|t| t.enabled)
        .min_by_key(|t| (t.memory, t.disk_size, t.cpu))
        .unwrap();
    assert_eq!(spec.template.id, smallest.id);
    Ok(())
}

/// The VM the client is handed carries the probe's own address and MAC, which
/// are the two things the node's filter binds together. Getting either wrong
/// produces a VM that boots and cannot be reached, which looks exactly like a
/// broken node.
#[tokio::test]
async fn the_probe_vm_is_addressed_as_the_node_expects() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    let info = spec.vm_info();
    assert_eq!(info.vm.mac_address, probe_mac(node.id));
    assert_eq!(info.ips.len(), 1);
    // Bare, as the database stores it: the cloud-init renderer parses this as
    // an address and silently drops anything carrying a prefix, which boots a
    // guest with no network on a node that is perfectly fine.
    assert_eq!(info.ips[0].ip, spec.ip());
    assert_eq!(spec.address, format!("{}/128", spec.ip()));
    assert!(spec.address.contains(':'), "probes are IPv6 only");
    assert_eq!(info.vm.id, probe_vm_id(node.id));
    Ok(())
}

/// Cloud-init is rendered by the same code a customer's VM uses, from these
/// rows. A probe configured by a separate path would prove that path works.
#[tokio::test]
async fn a_probe_is_configured_like_a_customer() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;
    let info = spec.vm_info();

    let user_data = lnvps_api_common::host::cloud_init::user_data(&info)?;
    assert!(user_data.contains(KEY), "the probe must be able to log in");
    let network = lnvps_api_common::host::cloud_init::network_config(&info)?;
    assert!(network.yaml.contains(spec.ip()), "{}", network.yaml);
    assert!(
        network.yaml.contains(&probe_mac(node.id)),
        "addresses are matched to the NIC by MAC"
    );
    Ok(())
}

/// No firewall rules: the node's own filter is what isolates a guest. A probe
/// that installed extra rules would be measuring a machine configured unlike
/// the one customers get.
#[tokio::test]
async fn a_probe_adds_no_rules_of_its_own() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;

    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;
    assert!(spec.vm_info().firewall_rules.is_empty());
    Ok(())
}

/// A node with no tunnel cannot be probed, and is told so rather than being
/// given an address nothing routes.
#[tokio::test]
async fn a_node_with_no_tunnel_cannot_be_probed() -> Result<()> {
    let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::empty());
    let user_id = db.upsert_user(&[6u8; 32]).await?;
    let operator_id = db
        .insert_marketplace_operator(&MarketplaceOperator {
            user_id,
            enabled: true,
            ..Default::default()
        })
        .await?;
    let node_id = db
        .insert_marketplace_node(&MarketplaceNode {
            operator_id,
            name: "no tunnel".to_string(),
            ..Default::default()
        })
        .await?;
    let node = db.get_marketplace_node(node_id).await?;

    assert!(ProbeSpec::build(&db, &node, KEY.to_string()).await.is_err());
    Ok(())
}

/// A failure is a result. A node that never completes a probe looks identical
/// to one nobody probed unless the failures are written down.
#[tokio::test]
async fn a_failed_probe_is_still_recorded() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    record(&db, node.id, &spec, ProbeResult::failed("no route".into())).await?;

    let (rows, total) = db.list_marketplace_node_health(node.id, 10, 0).await?;
    assert_eq!(total, 1);
    assert!(!rows[0].passed);
    assert_eq!(rows[0].failure.as_deref(), Some("no route"));
    // The shape is recorded even for a failure: "it could not build a 2GB VM"
    // and "it could not build a 32GB one" are different facts about a machine.
    assert_eq!(rows[0].memory_bytes, spec.template.memory);
    Ok(())
}

/// A result carries the shape it was measured at, so a template edited later
/// cannot change what an old row appears to say.
#[tokio::test]
async fn a_result_records_what_it_measured() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    let result = ProbeResult {
        provision_ms: Some(42_000),
        memory_mb: Some(1900),
        disk_write_mb: Some(300),
        disk_read_mb: Some(900),
        failure: None,
    };
    assert!(result.passed());
    record(&db, node.id, &spec, result).await?;

    let (rows, _) = db.list_marketplace_node_health(node.id, 10, 0).await?;
    assert!(rows[0].passed);
    assert_eq!(rows[0].provision_ms, Some(42_000));
    assert_eq!(rows[0].memory_mb, Some(1900));
    assert_eq!(rows[0].cpu, spec.template.cpu);
    assert_eq!(rows[0].image, spec.image.url);
    Ok(())
}

/// The series is newest first and paged at the database: a node probed for a
/// year is thousands of rows and an admin reading a trend wants the last few.
#[tokio::test]
async fn the_series_is_newest_first() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    for ms in [1000u32, 2000, 3000] {
        record(
            &db,
            node.id,
            &spec,
            ProbeResult {
                provision_ms: Some(ms),
                ..Default::default()
            },
        )
        .await?;
    }

    let (rows, total) = db.list_marketplace_node_health(node.id, 2, 0).await?;
    assert_eq!(total, 3, "the count is of everything, not the page");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].provision_ms, Some(3000), "newest first");
    Ok(())
}

/// The dummy client, which `get_host_client` returns for a Dummy host and which
/// keeps its VMs in memory — enough to see whether the probe cleaned up.
fn dummy_cfg() -> lnvps_api_common::host::config::ProvisionerConfig {
    lnvps_api_common::host::config::ProvisionerConfig {
        proxmox: None,
        libvirt: None,
        marketplace: None,
    }
}

async fn dummy_spec(db: &Arc<dyn LNVpsDb>, node: &MarketplaceNode) -> Result<ProbeSpec> {
    let mut spec = ProbeSpec::build(db, node, KEY.to_string()).await?;
    spec.host.kind = VmHostKind::Dummy;
    Ok(spec)
}

/// The VM is destroyed when the measurement succeeds.
#[tokio::test]
async fn a_probe_cleans_up_after_itself() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = dummy_spec(&db, &node).await?;

    let result = with_probe_vm(&db, &dummy_cfg(), &spec, || async {
        Ok(ProbeResult {
            memory_mb: Some(1900),
            ..Default::default()
        })
    })
    .await;

    assert!(result.passed(), "{result:?}");
    assert_eq!(result.memory_mb, Some(1900));
    // Timed even though the measurement did not report one: what a customer
    // waits for is the whole thing, not the part that thought to measure itself.
    assert!(result.provision_ms.is_some());

    let client = lnvps_api_common::host::get_host_client(&spec.host, &dummy_cfg())?;
    assert!(
        client.get_vm_state(&spec.vm_info().vm).await.is_err(),
        "the probe VM outlived its probe"
    );
    Ok(())
}

/// ...and when it fails. A probe that leaked its VM on the failure path would
/// leave LNVPS squatting on the machines least able to cope with it.
#[tokio::test]
async fn a_failed_measurement_still_destroys_the_vm() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = dummy_spec(&db, &node).await?;

    let result = with_probe_vm(&db, &dummy_cfg(), &spec, || async {
        anyhow::bail!("could not log in")
    })
    .await;

    assert!(!result.passed());
    assert!(
        result
            .failure
            .as_deref()
            .unwrap()
            .contains("could not log in")
    );

    let client = lnvps_api_common::host::get_host_client(&spec.host, &dummy_cfg())?;
    assert!(client.get_vm_state(&spec.vm_info().vm).await.is_err());
    Ok(())
}

/// A probe left behind by a process that was killed is removed before the next
/// one starts. Otherwise a single crash would make every later probe on that
/// node fail for a reason that has nothing to do with the machine.
#[tokio::test]
async fn a_stale_probe_is_cleared_first() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = dummy_spec(&db, &node).await?;

    // A probe VM from a run that never finished.
    let client = lnvps_api_common::host::get_host_client(&spec.host, &dummy_cfg())?;
    client.create_vm(&spec.vm_info()).await?;
    assert!(client.get_vm_state(&spec.vm_info().vm).await.is_ok());

    let result = with_probe_vm(&db, &dummy_cfg(), &spec, || async {
        Ok(ProbeResult::default())
    })
    .await;

    assert!(result.passed(), "{result:?}");
    Ok(())
}

/// A node LNVPS cannot reach at all is a failed probe, not a panic — an
/// unreachable node is exactly what this is meant to detect.
#[tokio::test]
async fn an_unreachable_node_is_a_failed_probe() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    // A marketplace host with no libvirt configuration: get_host_client refuses
    // to build a client it cannot verify.
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    let result = with_probe_vm(&db, &dummy_cfg(), &spec, || async {
        panic!("the measurement must never run")
    })
    .await;

    assert!(!result.passed());
    assert!(result.failure.unwrap().contains("cannot reach the node"));
    Ok(())
}

/// A node nobody has probed comes first. It is the one LNVPS knows nothing
/// about and may already be placing customers on; a node measured last week is
/// a known quantity by comparison.
#[tokio::test]
async fn an_unprobed_node_is_probed_first() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;

    let measured = a_node(&db).await?;
    let never = {
        // A second node, so there is something to order against.
        let id = db
            .insert_marketplace_node(&MarketplaceNode {
                operator_id: measured.operator_id,
                name: "never probed".to_string(),
                status: MarketplaceNodeStatus::Approved,
                ..Default::default()
            })
            .await?;
        db.create_host(&lnvps_db::VmHost {
            kind: VmHostKind::MarketplaceNode,
            region_id: 1,
            name: "node-2".to_string(),
            marketplace_node_id: Some(id),
            ..Default::default()
        })
        .await?;
        db.get_marketplace_node(id).await?
    };

    let now = chrono::Utc::now();
    let spec = ProbeSpec::build(&db, &measured, KEY.to_string()).await?;
    record(&db, measured.id, &spec, ProbeResult::default()).await?;

    let due = probe_candidates(&db, now + PROBE_COOLDOWN + chrono::Duration::minutes(1)).await?;
    assert_eq!(due.len(), 2);
    assert_eq!(due[0].id, never.id, "the unknown node goes first");
    Ok(())
}

/// A node probed recently is left alone. A probe costs the operator a disk
/// clone, a boot and a few hundred megabytes of I/O on hardware they are barely
/// being paid for; doing it every few minutes would be indistinguishable from
/// abuse.
#[tokio::test]
async fn a_recently_probed_node_is_left_alone() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    record(&db, node.id, &spec, ProbeResult::default()).await?;

    let now = chrono::Utc::now();
    assert!(probe_candidates(&db, now).await?.is_empty());
    // ...and is due again once the cooldown has passed.
    let later = now + PROBE_COOLDOWN + chrono::Duration::minutes(1);
    assert_eq!(probe_candidates(&db, later).await?.len(), 1);
    Ok(())
}

/// A failed probe still starts the cooldown. Retrying a broken node every few
/// minutes would hammer the machine least able to cope with it, and the failure
/// is already recorded for anyone deciding what to do about it.
#[tokio::test]
async fn a_failure_also_starts_the_cooldown() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    record(&db, node.id, &spec, ProbeResult::failed("no route".into())).await?;

    assert!(probe_candidates(&db, chrono::Utc::now()).await?.is_empty());
    Ok(())
}

/// A node that is not approved is not probed: an unapproved node has no host,
/// and probing one would mean building VMs on hardware nobody has accepted.
#[tokio::test]
async fn only_approved_nodes_are_probed() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;

    let mut nodes = mock.marketplace_nodes.lock().await;
    nodes.get_mut(&node.id).unwrap().status = MarketplaceNodeStatus::Suspended;
    drop(nodes);

    assert!(probe_candidates(&db, chrono::Utc::now()).await?.is_empty());
    Ok(())
}

/// An approved node with no host yet is skipped rather than recorded as a
/// failure: it is a state every node passes through on the way in, and a
/// failure row would make a normal enrolment look like a broken machine.
#[tokio::test]
async fn a_node_with_no_host_is_skipped_quietly() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let user_id = db.upsert_user(&[8u8; 32]).await?;
    let operator_id = db
        .insert_marketplace_operator(&MarketplaceOperator {
            user_id,
            enabled: true,
            ..Default::default()
        })
        .await?;
    db.insert_marketplace_node(&MarketplaceNode {
        operator_id,
        name: "no host".to_string(),
        status: MarketplaceNodeStatus::Approved,
        ..Default::default()
    })
    .await?;

    assert!(probe_candidates(&db, chrono::Utc::now()).await?.is_empty());
    Ok(())
}

/// The guest is addressed from the pool's block, not from its own address.
///
/// Cloud-init widens a guest's prefix to the shorter of its range and its
/// gateway, so describing the range as the probe's own /128 gives the guest a
/// /128 whose gateway is not on-link — and a guest that cannot reach its
/// gateway has no network at all, on a node that is working perfectly. It looks
/// exactly like a broken machine.
#[tokio::test]
async fn a_probe_can_reach_its_gateway() -> Result<()> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();
    a_pool(&db, &mock).await?;
    a_catalogue(&mock).await;
    let node = a_node(&db).await?;
    let spec = ProbeSpec::build(&db, &node, KEY.to_string()).await?;

    let info = spec.vm_info();
    let network = lnvps_api_common::host::cloud_init::network_config(&info)?;

    // A host prefix: the guest's own address and nothing else is on-link, so
    // everything it sends goes to the node — the only thing on that bridge that
    // can route. A wider prefix would make the route server look on-link, and
    // the guest would resolve it on a link where nothing answers.
    assert!(
        network.yaml.contains(&format!("{}/128", spec.ip())),
        "{}",
        network.yaml
    );
    // ...which requires the gateway to be marked reachable anyway.
    assert!(
        network.yaml.contains("on-link: true"),
        "a gateway outside the guest's prefix is unusable without this:\n{}",
        network.yaml
    );
    Ok(())
}

/// A host client that records every delete, so a test can tell whether the
/// probe VM was actually destroyed. `DummyVmHost::new()` builds a fresh map per
/// instance, so asking a second client whether the VM is gone would pass
/// whether or not anything deleted it.
#[derive(Default)]
struct RecordingHost {
    deleted: Arc<std::sync::Mutex<Vec<u64>>>,
}

/// Every method a probe never calls answers "not supported by the test double"
/// rather than a plausible value, so a future change that starts calling one
/// fails loudly instead of measuring a fiction.
macro_rules! unsupported {
    () => {
        Err(lnvps_api_common::retry::OpError::Fatal(anyhow::anyhow!(
            "not supported by the test double"
        )))
    };
}

#[async_trait::async_trait]
impl lnvps_api_common::host::VmHostClient for RecordingHost {
    async fn delete_vm(&self, vm: &Vm) -> lnvps_api_common::retry::OpResult<()> {
        self.deleted.lock().unwrap().push(vm.id);
        Ok(())
    }

    async fn get_info(
        &self,
    ) -> lnvps_api_common::retry::OpResult<lnvps_api_common::host::VmHostInfo> {
        unsupported!()
    }
    async fn download_os_image(
        &self,
        _image: &lnvps_db::VmOsImage,
    ) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn generate_mac(&self, _vm: &Vm) -> lnvps_api_common::retry::OpResult<String> {
        unsupported!()
    }
    async fn start_vm(&self, _vm: &Vm) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn stop_vm(&self, _vm: &Vm) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn reset_vm(&self, _vm: &Vm) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn create_vm(
        &self,
        _cfg: &lnvps_api_common::host::FullVmInfo,
    ) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn unlink_primary_disk(&self, _vm: &Vm) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn import_template_disk(
        &self,
        _cfg: &lnvps_api_common::host::FullVmInfo,
    ) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn resize_disk(
        &self,
        _cfg: &lnvps_api_common::host::FullVmInfo,
    ) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn get_vm_state(
        &self,
        _vm: &Vm,
    ) -> lnvps_api_common::retry::OpResult<lnvps_api_common::VmRunningState> {
        unsupported!()
    }
    async fn get_all_vm_states(
        &self,
    ) -> lnvps_api_common::retry::OpResult<Vec<(u64, lnvps_api_common::VmRunningState)>> {
        unsupported!()
    }
    async fn configure_vm(
        &self,
        _cfg: &lnvps_api_common::host::FullVmInfo,
    ) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn patch_firewall(
        &self,
        _cfg: &lnvps_api_common::host::FullVmInfo,
    ) -> lnvps_api_common::retry::OpResult<()> {
        unsupported!()
    }
    async fn get_time_series_data(
        &self,
        _vm: &Vm,
        _series: lnvps_api_common::host::TimeSeries,
    ) -> lnvps_api_common::retry::OpResult<Vec<lnvps_api_common::host::TimeSeriesData>> {
        unsupported!()
    }
    async fn connect_terminal(
        &self,
        _vm: &Vm,
    ) -> lnvps_api_common::retry::OpResult<lnvps_api_common::host::TerminalStream> {
        unsupported!()
    }
}

fn a_probe_vm(node_id: u64) -> Vm {
    Vm {
        id: probe_vm_id(node_id),
        ..Default::default()
    }
}

/// The guard destroys the VM when the probe is abandoned rather than finished.
///
/// This is the case the inline delete cannot cover: the future is dropped
/// part-way — a `tokio::time::timeout`, a task abort, a shutdown mid-probe —
/// and without the guard an LNVPS VM keeps running on an operator's machine.
#[tokio::test]
async fn an_abandoned_probe_still_destroys_its_vm() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let deleted = host.deleted.clone();

    {
        let _guard = ProbeVmGuard {
            client: host.clone(),
            vm: a_probe_vm(7),
            node_id: 7,
            armed: true,
        };
        // Dropped here without ever being disarmed, exactly as it would be if
        // the probe future were dropped mid-measurement.
    }

    // The delete is spawned, so it lands on a later poll of the runtime.
    tokio::task::yield_now().await;
    assert_eq!(
        deleted.lock().unwrap().as_slice(),
        &[probe_vm_id(7)],
        "an abandoned probe left its VM running on the operator's node"
    );
    Ok(())
}

/// A disarmed guard does not delete again. The inline delete already ran and
/// reported its outcome; a second one would be a delete nothing is waiting for,
/// racing the next probe on that node.
#[tokio::test]
async fn a_completed_probe_is_not_deleted_twice() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let deleted = host.deleted.clone();

    {
        let mut guard = ProbeVmGuard {
            client: host.clone(),
            vm: a_probe_vm(7),
            node_id: 7,
            armed: true,
        };
        guard.disarm();
    }

    tokio::task::yield_now().await;
    assert!(deleted.lock().unwrap().is_empty());
    Ok(())
}

/// A panic during the measurement destroys the VM too.
///
/// The panic unwinds past the inline delete, so the guard is the only thing
/// that can clean up. Exercised on the guard directly because the panic has to
/// cross the drop, and `with_probe_vm` builds its own client from the host
/// kind — there is no way to hand it a double.
#[tokio::test]
async fn a_panicking_probe_still_destroys_its_vm() -> Result<()> {
    let host = Arc::new(RecordingHost::default());
    let deleted = host.deleted.clone();

    let outcome = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        let _guard = ProbeVmGuard {
            client: host.clone(),
            vm: a_probe_vm(7),
            node_id: 7,
            armed: true,
        };
        panic!("the measurement fell over");
    }))
    .await;

    assert!(outcome.is_err(), "the panic must reach the caller");
    tokio::task::yield_now().await;
    assert_eq!(
        deleted.lock().unwrap().as_slice(),
        &[probe_vm_id(7)],
        "a probe that panicked left its VM running on the operator's node"
    );
    Ok(())
}
