//! A probe VM, built on a real node, over a real tunnel.
//!
//! This is the only test in the marketplace that proves what the feature
//! claims. Everything else establishes that a node is *configured*: its tunnel
//! carries packets, its filter loads, its libvirtd answers, its pool exists.
//! None of it proves the machine can carry a customer, which is the one thing
//! LNVPS tells customers it has checked before taking their money.
//!
//! So this runs the production path end to end — `run_probe` against a node
//! built by the node's own daemon code — and asserts on what came back.
//!
//! It is slow and it downloads a cloud image. That is the cost of the claim.
//!
//! Requires root, systemd, libvirt and KVM; run with `scripts/tunnel-e2e.sh`.

use std::sync::Arc;

use anyhow::{Context, Result};
use lnvps_api_common::MockDb;
use lnvps_api_common::host::config::{
    LibVirtConfig, MarketplaceLibvirtConfig, ProvisionerConfig, QemuConfig,
};
use lnvps_db::{
    LNVpsDb, LNVpsDbBase, MarketplaceNode, MarketplaceNodeStatus, MarketplaceOperator, Router,
    RouterKind, TunnelPool, VmHost, VmHostKind,
};
use lnvps_e2e::stack::{Addrs, Stack};

/// The image a probe boots. Overridable, because a machine without outbound
/// access to the Debian mirror can point this at a local copy rather than
/// skipping the only test that proves anything.
fn boot_image_url() -> String {
    std::env::var("LNVPS_PROBE_IMAGE").unwrap_or_else(|_| {
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
            .to_string()
    })
}

/// A database holding one approved node with a tunnel, a template and an image:
/// the smallest arrangement LNVPS can probe.
async fn a_probeable_node(stack: &Stack) -> Result<(Arc<MockDb>, MarketplaceNode)> {
    let mock = Arc::new(MockDb::empty());
    let db: Arc<dyn LNVpsDb> = mock.clone();

    let router_id = {
        let mut routers = mock.router.lock().await;
        routers.insert(
            1,
            Router {
                id: 1,
                name: "rs".to_string(),
                enabled: true,
                kind: RouterKind::MockRouter,
                url: "mock://rs".to_string(),
                token: "t".into(),
            },
        );
        1
    };
    // The pool the harness actually built, so the addresses LNVPS derives are
    // the ones on the wire.
    let pool_key = lnvps_api_common::generate_wireguard_keypair()?;
    db.insert_tunnel_pool(&TunnelPool {
        router_id,
        region_id: 1,
        name: "pool".to_string(),
        listen_addr: Addrs::bare(&stack.addrs.rs_underlay).to_string(),
        listen_port: stack.addrs.listen_port,
        // Both halves of one key. The node is told the public half in its
        // document and encrypts to it; a placeholder here is a tunnel that comes
        // up and carries nothing.
        private_key: pool_key.private_key.clone().into(),
        public_key: pool_key.public_key.to_vec(),
        cidr4: Some(stack.addrs.pool_block.clone()),
        cidr6: Some(stack.addrs.pool_block6.clone()),
        keepalive: Some(25),
        mtu: 1420,
        enabled: true,
        ..Default::default()
    })
    .await?;

    mock.templates.lock().await.insert(
        1,
        lnvps_db::VmTemplate {
            // Matching the image's architecture, which is what ProbeSpec picks
            // on: an x86 image on an arm template does not boot.
            cpu_arch: lnvps_db::CpuArch::X86_64,
            ..MockDb::mock_template()
        },
    );
    mock.os_images.lock().await.insert(
        1,
        lnvps_db::VmOsImage {
            id: 1,
            distribution: lnvps_db::OsDistribution::Debian,
            flavour: "genericcloud".to_string(),
            version: "13".to_string(),
            enabled: true,
            release_date: chrono::Utc::now(),
            url: boot_image_url(),
            cpu_arch: lnvps_db::CpuArch::X86_64,
            // Debian's cloud images have no root login; a probe that assumed
            // one would fail on the image customers are actually sold.
            default_username: Some("debian".to_string()),
            sha2: None,
            sha2_url: None,
        },
    );

    let user_id = db.upsert_user(&[1u8; 32]).await?;
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
            name: "e2e".to_string(),
            status: MarketplaceNodeStatus::Approved,
            ..Default::default()
        })
        .await?;
    db.create_host(&VmHost {
        kind: VmHostKind::MarketplaceNode,
        region_id: 1,
        name: "e2e".to_string(),
        // Disabled, which is the point: a passing probe is what opens it.
        enabled: false,
        ip: Addrs::bare(&stack.addrs.node_inner).to_string(),
        marketplace_node_id: Some(node_id),
        cpu: 4,
        memory: 8 * 1024 * 1024 * 1024,
        ..Default::default()
    })
    .await?;

    let node = db.get_marketplace_node(node_id).await?;
    Ok((mock, node))
}

/// LNVPS's client identity, generated per run.
fn lnvps_pki(dir: &std::path::Path) -> Result<MarketplaceLibvirtConfig> {
    let mut ca_params = rcgen::CertificateParams::new(vec![])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "lnvps-e2e-ca");
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;

    let dn = lnvps_api_common::node_control::LIBVIRT_CLIENT_DN;
    let mut client_params = rcgen::CertificateParams::new(vec![])?;
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dn.trim_start_matches("CN="));
    let client_key = rcgen::KeyPair::generate()?;
    let client = client_params.signed_by(&client_key, &ca, &ca_key)?;

    std::fs::write(dir.join("ca.pem"), ca.pem())?;
    std::fs::write(dir.join("client.pem"), client.pem())?;
    std::fs::write(dir.join("client.key"), client_key.serialize_pem())?;

    Ok(MarketplaceLibvirtConfig {
        ca_cert: dir.join("ca.pem"),
        client_cert: dir.join("client.pem"),
        client_key: dir.join("client.key"),
        pki_dir: dir.join("pki"),
    })
}

/// Put the OS image where LNVPS's image cache expects it, before the probe runs
/// inside the route server's namespace.
///
/// In production LNVPS downloads images from wherever it runs; in here the
/// namespace it runs in has no route to the internet, which is the isolation
/// working. Fetching it first models the deployment that has already downloaded
/// this image for some other customer — the ordinary case — rather than
/// weakening the test: the node still receives, writes and boots the real
/// artefact.
async fn seed_image_cache(cache: &std::path::Path, image: &lnvps_db::VmOsImage) -> Result<()> {
    tokio::fs::create_dir_all(cache).await?;
    // The name the client's cache uses, which is `os-image-<id>-<file>`. Built
    // here rather than reaching into a private module: a harness that could see
    // internals would be free to disagree with them, and the point is that the
    // client finds this file on its own terms.
    let file = image.url.rsplit('/').next().unwrap_or("image");
    let target = cache.join(format!("os-image-{}-{}", image.id, file));
    if tokio::fs::metadata(&target)
        .await
        .map(|m| m.len())
        .unwrap_or(0)
        > 0
    {
        return Ok(());
    }

    let body = reqwest::get(&image.url)
        .await
        .with_context(|| format!("fetching {}", image.url))?
        .error_for_status()?
        .bytes()
        .await?;
    tokio::fs::write(&target, &body).await?;
    Ok(())
}

/// Kept outside the per-run temp directory: a cloud image is hundreds of
/// megabytes and re-downloading it on every run would make this test something
/// nobody runs.
fn image_cache() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("LNVPS_PROBE_CACHE").unwrap_or_else(|_| "/var/tmp/lnvps-probe-images".into()),
    )
}

fn provisioner(marketplace: MarketplaceLibvirtConfig) -> ProvisionerConfig {
    ProvisionerConfig {
        proxmox: None,
        libvirt: Some(LibVirtConfig {
            qemu: QemuConfig {
                machine: "q35".to_string(),
                os_type: "l26".to_string(),
                bridge: lnvps_node::net::GUEST_BRIDGE.to_string(),
                cpu: "host".to_string(),
                kvm: true,
                arch: "x86_64".to_string(),
                balloon_min_pct: None,
                firewall_config: None,
            },
            image_pool: Some(lnvps_node::libvirt::POOL.to_string()),
            image_cache_dir: Some(image_cache()),
            vlan_aware_bridge: false,
            secure_boot: false,
            shutdown_timeout_secs: None,
        }),
        marketplace: Some(marketplace),
    }
}

/// The whole claim: LNVPS builds a customer's VM on an operator's node, logs
/// into it, measures it, destroys it, and only then opens the node to customers.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root, systemd, libvirt and KVM; run with scripts/tunnel-e2e.sh"]
async fn a_probe_proves_a_node_can_carry_a_customer() -> Result<()> {
    if !Stack::requirements_met() {
        return Ok(());
    }

    let stack = Stack::new("probe", 5)?;
    let dir = tempfile::TempDir::new()?;
    let marketplace = lnvps_pki(dir.path())?;
    let cfg = provisioner(marketplace.clone());

    let (mock, node) = a_probeable_node(&stack).await?;
    let db: Arc<dyn LNVpsDb> = mock.clone();

    // Before entering the route server's namespace, which has no way out.
    seed_image_cache(&image_cache(), &db.get_os_image(1).await?).await?;

    // Both ends are configured from the database by production code. The node
    // generates its own key and LNVPS allocates it a tunnel; the route server is
    // then configured by plan_pool, and the node by the same document the API
    // would have served it. A harness that built either side by hand could
    // configure them more helpfully than the API does — which is how a probe
    // that fails in production passes in here.
    let state = tempfile::TempDir::new()?;
    let node_key = lnvps_node::wgkey::load_or_generate(state.path())?;
    lnvps_api::provisioner::allocate_node_tunnel(&db, &node, &node_key.public_bytes()).await?;
    let node = db.get_marketplace_node(node.id).await?;

    let pool = db.get_tunnel_pool(1).await?;
    stack.apply_pool(&db, &pool).await?;

    // The node applies exactly what the API serves it, carried across the wire
    // format both ends actually use. Serialising LNVPS's document and parsing
    // the node's is the only thing that proves those two types agree.
    let document = lnvps_api::provisioner::node_dataplane(&db, &node)
        .await?
        .context("the node has no data plane")?;
    let api_document: lnvps_api::api::marketplace::ApiNodeDataPlane = document.into();
    let desired: lnvps_node::net::DesiredDataPlane =
        serde_json::from_value(serde_json::to_value(&api_document)?)
            .context("LNVPS's document is not one the node can parse")?;

    let kernel = lnvps_node::net::Kernel::in_namespace(stack.open_dataplane()?)?;
    let firewall = lnvps_node::fw::SystemFirewall::new(stack.open_dataplane()?);
    lnvps_node::net::apply(&kernel, &firewall, &desired, &node_key).await?;

    // The node dials out first, which is the only direction that can start this:
    // nodes sit behind NAT, so the route server has no endpoint for a peer until
    // that peer's handshake arrives. LNVPS reaching a node it has never heard
    // from is not a thing that works, in the harness or in production.
    let rs_address = desired
        .tunnel
        .gateway4
        .clone()
        .context("the node was given no gateway")?;
    stack
        .in_dataplane(&["ping", "-c", "3", "-W", "5", &rs_address])
        .with_context(|| {
            format!(
                "the node cannot reach the route server over the tunnel\n\
                 node data plane:\n{}{}\nroute server:\n{}{}",
                stack.in_dataplane(&["ip", "addr"]).unwrap_or_default(),
                stack.in_dataplane(&["wg", "show"]).unwrap_or_default(),
                stack.in_rs(&["ip", "addr"]).unwrap_or_default(),
                stack.in_rs(&["wg", "show"]).unwrap_or_default(),
            )
        })?;

    // The tunnel carries before anything is asked of it. Without this, a
    // failure below reads as "libvirt is broken" when the truth is that no
    // packet ever reached the node.
    stack
        .in_rs(&[
            "ping",
            "-c",
            "3",
            "-W",
            "5",
            Addrs::bare(&stack.addrs.node_inner),
        ])
        .context("the route server cannot reach the node over the tunnel")?;

    // The node configures its own libvirtd from what LNVPS sent it, and
    // registers the certificate LNVPS will verify it against.
    let ca_pem = std::fs::read_to_string(&marketplace.ca_cert)?;
    // The address the node's own document told it to serve on.
    let _ = &desired;
    let libvirtd =
        stack.start_libvirtd(&ca_pem, lnvps_api_common::node_control::LIBVIRT_CLIENT_DN)?;
    let pki = lnvps_api_common::host::marketplace_pki::materialise(
        &marketplace,
        node.id,
        &libvirtd.ca_pem,
    )?;
    // The same URI LNVPS dials, for looking at the guest while it runs.
    let uri = lnvps_api_common::host::marketplace_pki::connection_uri(
        Addrs::bare(&stack.addrs.node_inner),
        &pki,
    );

    // A look inside while the guest is still alive. Everything so far has been
    // read after the probe tore its VM down, which is the one moment the
    // interesting state no longer exists.
    let probe_address = lnvps_api::provisioner::probe_address(
        &lnvps_api::provisioner::get_node_tunnel(&db, &node)
            .await?
            .context("the node has no tunnel")?
            .tunnel,
    )
    .context("the node has no probe address")?;
    let live = {
        let names = stack.names.clone();
        let images = libvirtd.paths.root.join("images");
        let console_uri = uri.clone();
        let domain = format!("VM{}", lnvps_api::provisioner::probe_vm_id(node.id));
        let node_id = node.id;
        let probe_ip = probe_address
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();
        tokio::task::spawn_blocking(move || {
            let run = |ns: &str, argv: &[&str]| -> String {
                let mut full = vec!["netns", "exec", ns];
                full.extend_from_slice(argv);
                std::process::Command::new("ip")
                    .args(&full)
                    .output()
                    .map(|o| {
                        format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        )
                    })
                    .unwrap_or_else(|e| e.to_string())
            };

            // Wait for the VM to exist before looking at it. The image has to
            // be uploaded and a disk cloned first, and every earlier attempt to
            // sample this on a timer looked at a node that had not been given a
            // VM yet.
            for _ in 0..60 {
                if run(&names.dataplane_ns, &["ip", "link", "show", "vnet0"]).contains("vnet0") {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            std::thread::sleep(std::time::Duration::from_secs(60));
            let console = String::new();
            let _ = &console_uri;
            let _ = &domain;

            // Is the guest executing at all? Two CPU samples answer it.
            let cpu1 = run(
                &names.dataplane_ns,
                &[
                    "virsh",
                    "-c",
                    &console_uri,
                    "domstats",
                    "--cpu-total",
                    &domain,
                ],
            );
            std::thread::sleep(std::time::Duration::from_secs(10));
            let cpu2 = run(
                &names.dataplane_ns,
                &[
                    "virsh",
                    "-c",
                    &console_uri,
                    "domstats",
                    "--cpu-total",
                    &domain,
                ],
            );
            let tap = run(&names.dataplane_ns, &["ip", "-s", "link", "show", "vnet0"]);
            let _ = images;
            let _ = node_id;
            format!(
                "console (attached during boot):\n{console}\n\
                 neighbours:\n{cpu1}\nping from the route server:\n{cpu2}\ntap:\n{tap}"
            )
        })
    };

    // LNVPS sits behind the route server, so the probe runs from there: the
    // node's inner addresses are not routable from the machine's own namespace,
    // which is the isolation the data plane exists to provide.
    let result = lnvps_e2e::stack::in_namespace(&stack.names.rs_ns, {
        let db = db.clone();
        let node = node.clone();
        move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(lnvps_api::provisioner::run_probe(&db, &cfg, &node))
        }
    })?;

    if !result.passed() {
        // What the guest itself said, which is the only place the answer can
        // be when a VM boots and never answers.
        let console = std::fs::read_to_string(
            libvirtd
                .paths
                .root
                .join("lib/qemu/log")
                .join(format!("probe-{}.log", node.id)),
        )
        .unwrap_or_else(|e| format!("(no console log: {e})"));
        let arp = stack
            .in_dataplane(&["ip", "-6", "neigh", "show"])
            .unwrap_or_default();
        let routes = stack
            .in_dataplane(&["ip", "-6", "route"])
            .unwrap_or_default();
        panic!(
            "the probe failed on a node that is working: {:?}\n\
             --- while the guest was alive ---\n{}\n\
             --- after teardown ---\nneighbours:\n{arp}\nroutes:\n{routes}\n\
             console tail:\n{}",
            result.failure,
            live.await.unwrap_or_else(|e| e.to_string()),
            console
                .lines()
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    assert!(
        result.provision_ms.unwrap_or_default() > 0,
        "a VM that took no time to build did not get built"
    );
    assert!(
        result.memory_mb.unwrap_or_default() > 0,
        "the guest reported no memory"
    );
    assert!(
        result.disk_write_mb.unwrap_or_default() > 0 && result.disk_read_mb.unwrap_or_default() > 0,
        "the guest could not use its disk: {result:?}"
    );

    // Recorded as a row, because a probe nobody can read afterwards decides
    // nothing.
    let (rows, total) = db.list_marketplace_node_health(node.id, 10, 0).await?;
    assert_eq!(total, 1);
    assert!(rows[0].passed);

    // And nothing of ours is left running on the operator's machine.
    let host = db
        .get_marketplace_node_host(node.id)
        .await?
        .context("the node has no host")?;
    // Checked from where LNVPS sits: a client built in the machine's own
    // namespace cannot route to the node at all.
    let probe_vm = lnvps_db::Vm {
        id: lnvps_api::provisioner::probe_vm_id(node.id),
        ..Default::default()
    };
    let cfg = provisioner(marketplace);
    let still_there = lnvps_e2e::stack::in_namespace(&stack.names.rs_ns, move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let client = lnvps_api_common::host::get_host_client(&host, &cfg)?;
                Ok(client.get_vm_state(&probe_vm).await.is_ok())
            })
    })?;
    assert!(!still_there, "the probe VM outlived its probe");

    drop(libvirtd);
    Ok(())
}
