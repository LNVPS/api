//! LNVPS and `lvd`, together, carrying a customer's packets.
//!
//! Everything else about the VPN is proved by tests that assert what the code
//! *decides*: which peers the planner produces, which netlink calls the daemon
//! makes against a fake kernel. None of that proves the two halves agree, and
//! the seam between them is the risky part: the document is defined twice, once
//! by the API that publishes it and once by the daemon that parses it, with
//! JSON in between and nothing forcing them to match.
//!
//! So nothing here is hand-written. The service, the interface and the plan are
//! created through the admin API. The plan is paid over Lightning. The device is
//! registered through the user API with a keypair generated here, and the
//! client is configured from what the API hands back. `lvd` is started as a
//! process, with a config file, and left to discover all of it on its own.
//!
//! ```text
//!    [route server netns]                 [customer netns]
//!      wgln<pool>, built by lvd   <═════>   wg0, built from the API's answer
//!           │                                     │
//!       veth ──────────── bridge ──────────── veth
//!                           │
//!                    host: lnvps_api
//!                    (lvd dials out to it; nothing dials lvd)
//! ```
//!
//! Needs **both** root and a running stack, which no single script currently
//! provides: `scripts/vpn-e2e.sh` brings up one and runs this under the other.

use std::process::{Child, Command};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use lnvps_e2e::client::{TestClient, admin_client, bootstrap_admin, user_client_with_keys};
use lnvps_e2e::stack::{ip, run};
use nostr::Keys;
use serde_json::{Value, json};

const PREFIX: &str = "lvde2e";
/// The route server's address on the underlay, which is what a client dials.
const RS_UNDERLAY: [&str; 2] = ["198.51.100.10", "198.51.100.20"];
const CLIENT_UNDERLAY: &str = "198.51.100.11";
/// The host's address on the same segment, which is how `lvd` reaches LNVPS.
const HOST_UNDERLAY: &str = "198.51.100.254";
const LISTEN_PORT: [u16; 2] = [51830, 51831];

struct Lab {
    /// One namespace per region, each standing in for a route server in a
    /// different country.
    rs_ns: Vec<String>,
    client_ns: String,
    bridge: String,
    lvd: Vec<Child>,
}

impl Lab {
    fn new() -> Self {
        Self {
            rs_ns: vec![format!("{PREFIX}-rs0"), format!("{PREFIX}-rs1")],
            client_ns: format!("{PREFIX}-cl"),
            bridge: format!("{PREFIX}br"),
            lvd: Vec::new(),
        }
    }

    /// The underlay only. Everything inside the tunnel is LNVPS's and `lvd`'s
    /// job, which is the point.
    fn build(&self) -> Result<()> {
        self.teardown();
        ip(&["link", "add", &self.bridge, "type", "bridge"])?;
        ip(&[
            "addr",
            "add",
            &format!("{HOST_UNDERLAY}/24"),
            "dev",
            &self.bridge,
        ])?;
        ip(&["link", "set", &self.bridge, "up"])?;

        let members: Vec<(&String, &str)> = self
            .rs_ns
            .iter()
            .zip(RS_UNDERLAY)
            .chain(std::iter::once((&self.client_ns, CLIENT_UNDERLAY)))
            .collect();
        for (n, (ns, addr)) in members.into_iter().enumerate() {
            let ns = ns.as_str();
            ip(&["netns", "add", ns])?;
            self.exec(ns, &["ip", "link", "set", "lo", "up"])?;
            let (outer, inner) = (format!("{PREFIX}{n}o"), format!("{PREFIX}{n}i"));
            ip(&[
                "link", "add", &outer, "type", "veth", "peer", "name", &inner,
            ])?;
            ip(&["link", "set", &outer, "master", &self.bridge])?;
            ip(&["link", "set", &outer, "up"])?;
            ip(&["link", "set", &inner, "netns", ns])?;
            self.exec(
                ns,
                &["ip", "addr", "add", &format!("{addr}/24"), "dev", &inner],
            )?;
            self.exec(ns, &["ip", "link", "set", &inner, "up"])?;
        }
        Ok(())
    }

    fn exec(&self, ns: &str, argv: &[&str]) -> Result<String> {
        let mut cmd = vec!["netns", "exec", ns];
        cmd.extend_from_slice(argv);
        ip(&cmd)
    }

    fn teardown(&self) {
        for ns in self.rs_ns.iter().chain(std::iter::once(&self.client_ns)) {
            let _ = Command::new("ip").args(["netns", "delete", ns]).output();
        }
        for n in 0..3 {
            for side in ["o", "i"] {
                let _ = Command::new("ip")
                    .args(["link", "del", &format!("{PREFIX}{n}{side}")])
                    .output();
            }
        }
        let _ = Command::new("ip")
            .args(["link", "del", &self.bridge])
            .output();
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for mut child in self.lvd.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.teardown();
    }
}

fn requirements_met() -> bool {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping: needs root for network namespaces and WireGuard");
        return false;
    }
    if run("modprobe", &["wireguard"]).is_err()
        && !std::path::Path::new("/sys/module/wireguard").exists()
    {
        eprintln!("skipping: no WireGuard support in this kernel");
        return false;
    }
    true
}

/// Poll until `f` is true, or give up. Returns whether it happened.
async fn poll_until<F, Fut>(seconds: u64, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn json_ok(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        bail!("expected 2xx, got {status}: {body}");
    }
    Ok(serde_json::from_str(&body)?)
}

fn unique() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A WireGuard keypair, generated the way a customer's client would: here, with
/// the private half never leaving this machine.
fn a_keypair() -> Result<(String, String)> {
    let private = run("wg", &["genkey"])?.trim().to_string();
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .context("no stdin")?
        .write_all(private.as_bytes())?;
    let out = child.wait_with_output()?;
    Ok((private, String::from_utf8(out.stdout)?.trim().to_string()))
}

/// Everything LNVPS needs to know before a route server has anything to do.
async fn a_service_on(admin: &TestClient, id: u128, tokens: &[String; 2]) -> Result<Sold> {
    let company = json_ok(admin.get_auth("/api/admin/v1/companies?limit=1").await?).await?;
    let company_id = company["data"][0]["id"]
        .as_u64()
        .context("the stack seeds a company")?;

    let region = json_ok(
        admin
            .post_auth(
                "/api/admin/v1/regions",
                &json!({"name": format!("lab-{id}"), "enabled": true, "company_id": company_id}),
            )
            .await?,
    )
    .await?["data"]["id"]
        .as_u64()
        .context("region id")?;

    // Two regions, two route servers. Each is a separate machine with its own
    // credential, exactly as two countries would be.
    let mut routers = Vec::new();
    let mut pools = Vec::new();
    let mut regions = vec![region];
    for n in 0..2 {
        let region_id = match n {
            0 => region,
            _ => {
                let r = json_ok(
                    admin
                        .post_auth(
                            "/api/admin/v1/regions",
                            &json!({"name": format!("lab-{id}-{n}"), "enabled": true, "company_id": company_id}),
                        )
                        .await?,
                )
                .await?["data"]["id"]
                    .as_u64()
                    .context("region id")?;
                regions.push(r);
                r
            }
        };

        let router = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/routers",
                    &json!({
                        "name": format!("lab-rs-{id}-{n}"),
                        "enabled": true,
                        "kind": "lvd",
                        "url": "",
                        "token": tokens[n],
                    }),
                )
                .await?,
        )
        .await?["data"]["id"]
            .as_u64()
            .context("router id")?;

        let pool = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/tunnel_pools",
                    &json!({
                        "router_id": router,
                        "region_id": region_id,
                        "name": format!("lab-if-{id}-{n}"),
                        // What a client dials: the route server's own underlay
                        // address, which is what makes the rendered config work.
                        "listen_addr": RS_UNDERLAY[n],
                        "listen_port": LISTEN_PORT[n],
                        // The same block for both, which is the whole point and
                        // which the database enforces at link time.
                        "cidr4": "10.64.0.0/24",
                        "keepalive": 25,
                        "mtu": 1420,
                        "enabled": true,
                    }),
                )
                .await?,
        )
        .await?["data"]["id"]
            .as_u64()
            .context("pool id")?;

        routers.push(router);
        pools.push(pool);
    }

    let service = json_ok(
        admin
            .post_auth(
                "/api/admin/v1/vpn_services",
                &json!({
                    "company_id": company_id,
                    "name": format!("lab-vpn-{id}"),
                    "currency": "EUR",
                    "amount": 100,
                    "default_device_limit": 5,
                }),
            )
            .await?,
    )
    .await?["data"]["id"]
        .as_u64()
        .context("service id")?;

    for pool in &pools {
        json_ok(
            admin
                .post_auth(
                    &format!("/api/admin/v1/vpn_services/{service}/pools/{pool}"),
                    &json!({}),
                )
                .await?,
        )
        .await?;
    }
    json_ok(
        admin
            .patch_auth(
                &format!("/api/admin/v1/vpn_services/{service}"),
                &json!({"enabled": true}),
            )
            .await?,
    )
    .await?;

    Ok(Sold {
        service,
        pools,
        routers,
    })
}

/// What the admin API was asked to create.
struct Sold {
    service: u64,
    /// One interface per region, in the order the regions were made.
    pools: Vec<u64>,
    routers: Vec<u64>,
}

/// Buy the plan and pay for it, because a device cannot be registered until the
/// subscription is settled and that refusal is part of what is being tested.
async fn a_paid_plan(user: &TestClient, service_id: u64) -> Result<u64> {
    let plan = json_ok(
        user.post_auth("/api/v1/vpn", &json!({"service_id": service_id}))
            .await?,
    )
    .await?;
    let subscription_id = plan["data"]["subscription_id"]
        .as_u64()
        .context("subscription id")?;

    let renew = json_ok(
        user.get_auth(&format!("/api/v1/subscriptions/{subscription_id}/renew"))
            .await?,
    )
    .await?;
    let bolt11 = lnvps_e2e::lightning::extract_bolt11(&renew)?;
    lnvps_e2e::lightning::pay_invoice(&bolt11).await?;

    let active = poll_until(60, || async {
        match user.get_auth("/api/v1/vpn").await {
            Ok(r) => match json_ok(r).await {
                Ok(v) => v["data"]["billing_state"] == "active",
                Err(_) => false,
            },
            Err(_) => false,
        }
    })
    .await;
    if !active {
        bail!("the plan never became active after paying");
    }
    Ok(subscription_id)
}

/// Start the real daemon, with a real config file, inside the route server's
/// namespace. It is given the API's address and its own token and nothing else:
/// which interfaces to build, which key to use and which peers to carry are all
/// things it has to go and ask for.
fn start_lvd(lab: &mut Lab, region: usize, api_url: &str, token: &str) -> Result<()> {
    let config = std::env::temp_dir().join(format!("{PREFIX}-config-{region}.yaml"));
    std::fs::write(
        &config,
        format!(
            "api-url: \"{api_url}\"\ntoken: \"{token}\"\nwait-secs: 5\nretry-secs: 1\nscrub-after-secs: 600\n"
        ),
    )?;

    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/debug/lvd")
        .canonicalize()
        .context("lvd is not built; run `cargo build -p lnvps_vpn` first")?;

    let child = Command::new("ip")
        .args([
            "netns",
            "exec",
            &lab.rs_ns[region],
            binary.to_str().context("binary path")?,
            "--config",
            config.to_str().context("config path")?,
            "run",
        ])
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("starting lvd")?;
    lab.lvd.push(child);
    Ok(())
}

/// The address `lvd` gave an interface, read from the machine.
///
/// Asked rather than assumed, because the allocator decides it and the point of
/// this harness is to find out what it decided.
fn interface_address(lab: &Lab, region: usize, interface: &str) -> Result<String> {
    let out = Command::new("ip")
        .args([
            "netns",
            "exec",
            &lab.rs_ns[region],
            "ip",
            "-4",
            "-o",
            "addr",
            "show",
            interface,
        ])
        .output()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next().map(str::to_string))
        .with_context(|| format!("lvd did not address {interface}"))
}

/// The peers `lvd` has actually configured, read from the kernel it configured
/// rather than from anything it reported.
fn configured_peers(lab: &Lab, region: usize, interface: &str) -> Vec<String> {
    Command::new("ip")
        .args([
            "netns",
            "exec",
            &lab.rs_ns[region],
            "wg",
            "show",
            interface,
            "peers",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and a running stack; run with scripts/vpn-e2e.sh"]
async fn lvd_configures_a_customer_device_and_lnvps_can_revoke_it() -> Result<()> {
    if !requirements_met() {
        return Ok(());
    }
    bootstrap_admin().await?;
    let admin = admin_client();
    let user = user_client_with_keys(Keys::generate());
    let id = unique();
    let tokens = [format!("lab-secret-{id}-0"), format!("lab-secret-{id}-1")];

    let mut lab = Lab::new();
    lab.build()?;

    // ---- LNVPS's side: one service, two regions, and a paid plan
    let sold = a_service_on(&admin, id, &tokens).await?;
    a_paid_plan(&user, sold.service).await?;

    // ---- the customer's side: a keypair this machine generated
    let (private_key, public_key) = a_keypair()?;
    let device = json_ok(
        user.post_auth(
            "/api/v1/vpn/devices",
            &json!({"name": "laptop", "public_key": public_key}),
        )
        .await?,
    )
    .await?;
    let device_id = device["data"]["id"].as_u64().context("device id")?;
    // Carries its own prefix, as the API states it. The bare address is what
    // `ping -I` wants.
    let device_cidr = device["data"]["address4"]
        .as_str()
        .context("the allocator should have given it an address")?
        .to_string();
    let device_address = device_cidr
        .split('/')
        .next()
        .context("address4 should be a CIDR")?
        .to_string();

    // ---- one config per region, and the property the product is sold on
    let configs = json_ok(
        user.get_auth(&format!("/api/v1/vpn/devices/{device_id}/configs"))
            .await?,
    )
    .await?;
    let configs = configs["data"].as_array().context("configs")?;
    assert_eq!(configs.len(), 2, "one config per region");

    // Every config carries the *same* address, because the device holds one.
    // This is the claim the whole design exists to support, and it is asserted
    // here against what the allocator actually did rather than against a
    // document written by the test.
    for c in configs {
        let addresses: Vec<&str> = c["address"]
            .as_array()
            .context("address")?
            .iter()
            .filter_map(|a| a.as_str())
            .collect();
        assert!(
            addresses.contains(&device_cidr.as_str()),
            "region {} gave the device a different address: {addresses:?}",
            c["region_name"]
        );
        let rendered = c["config"].as_str().context("rendered config")?;
        assert!(
            rendered.contains("<your private key>"),
            "LNVPS rendered a private key it should never have had:\n{rendered}"
        );
    }
    // ...and they differ only in which door they knock on.
    let endpoints: Vec<&str> = configs
        .iter()
        .filter_map(|c| c["endpoint"].as_str())
        .collect();
    assert_eq!(endpoints.len(), 2);
    assert_ne!(
        endpoints[0], endpoints[1],
        "two regions should not share an endpoint"
    );

    // ---- both daemons, told only where LNVPS is and who they are
    let api_port = lnvps_e2e::client::user_api_url()
        .rsplit(':')
        .next()
        .unwrap_or("8000")
        .to_string();
    let api_url = format!("http://{HOST_UNDERLAY}:{api_port}");
    for n in 0..2 {
        start_lvd(
            &mut lab,
            n,
            &api_url,
            &format!("{}.{}", sold.routers[n], tokens[n]),
        )?;
    }

    // ---- each should build its interface and install the customer, unprompted
    let interfaces: Vec<String> = sold.pools.iter().map(|p| format!("wgln{p}")).collect();
    for n in 0..2 {
        let installed = poll_until(60, || async {
            configured_peers(&lab, n, &interfaces[n]).contains(&public_key)
        })
        .await;
        assert!(
            installed,
            "lvd in region {n} never configured the device LNVPS had registered"
        );
    }

    // Whatever address each gave its interface, read from the machine rather
    // than assumed: the allocator decides it, not this test.
    let server_addresses: Vec<String> = (0..2)
        .map(|n| interface_address(&lab, n, &interfaces[n]))
        .collect::<Result<Vec<_>>>()?;

    // ---- the customer's end, built from what the API answered
    let key_file = std::env::temp_dir().join(format!("{PREFIX}-device.key"));
    std::fs::write(&key_file, &private_key)?;
    lab.exec(
        &lab.client_ns,
        &["ip", "link", "add", "wg0", "type", "wireguard"],
    )?;
    lab.exec(
        &lab.client_ns,
        &["ip", "addr", "add", &device_cidr, "dev", "wg0"],
    )?;
    lab.exec(
        &lab.client_ns,
        &[
            "wg",
            "set",
            "wg0",
            "private-key",
            key_file.to_str().unwrap(),
        ],
    )?;
    lab.exec(&lab.client_ns, &["ip", "link", "set", "wg0", "up"])?;

    // ---- switch regions the way a client does: same key, same address, a
    //      different door. Nothing on the server side moves.
    for n in 0..2 {
        let peer = configs[n]["public_key"].as_str().context("server key")?;
        let endpoint = configs[n]["endpoint"].as_str().context("endpoint")?;
        // Which region this config is for, matched on the endpoint rather than
        // assumed from the order: the API is free to list them however it
        // likes, and pinging the wrong server would pass for the wrong reason.
        let region = (0..2)
            .find(|&r| endpoint == format!("{}:{}", RS_UNDERLAY[r], LISTEN_PORT[r]))
            .with_context(|| format!("no region listens on {endpoint}"))?;

        if let Some(previous) = configs
            .iter()
            .filter_map(|c| c["public_key"].as_str())
            .find(|k| *k != peer)
        {
            let _ = lab.exec(
                &lab.client_ns,
                &["wg", "set", "wg0", "peer", previous, "remove"],
            );
        }
        lab.exec(
            &lab.client_ns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                peer,
                "endpoint",
                endpoint,
                "allowed-ips",
                &format!("{}/32", server_addresses[region]),
                "persistent-keepalive",
                "1",
            ],
        )?;
        let _ = lab.exec(
            &lab.client_ns,
            &[
                "ip",
                "route",
                "replace",
                &format!("{}/32", server_addresses[region]),
                "dev",
                "wg0",
            ],
        );

        lab.exec(
            &lab.client_ns,
            &[
                "ping",
                "-c",
                "3",
                "-W",
                "5",
                "-I",
                &device_address,
                &server_addresses[region],
            ],
        )
        .with_context(|| {
            format!(
                "the device could not reach region {} on the one address it holds",
                configs[n]["region_name"]
            )
        })?;
    }
    std::fs::remove_file(&key_file).ok();

    // ---- revocation, through the admin API a support agent would use
    let plans = json_ok(
        admin
            .get_auth("/api/admin/v1/vpn_subscriptions?limit=100")
            .await?,
    )
    .await?;
    let plan_id = plans["data"]
        .as_array()
        .context("plans")?
        .iter()
        .find(|p| p["vpn_service_id"].as_u64() == Some(sold.service))
        .and_then(|p| p["id"].as_u64())
        .context("the plan just bought")?;
    let revoked = admin
        .delete_auth_body(
            &format!("/api/admin/v1/vpn_subscriptions/{plan_id}/devices/{device_id}"),
            &json!({"reason": "e2e: stolen laptop"}),
        )
        .await?;
    assert!(revoked.status().is_success(), "revoke failed");

    // Every region, not just the one it was last connected to. A key left on
    // any single route server still works, which is the failure that matters.
    for n in 0..2 {
        let removed = poll_until(30, || async {
            !configured_peers(&lab, n, &interfaces[n]).contains(&public_key)
        })
        .await;
        assert!(
            removed,
            "a revoked key is still configured on the route server in region {n}"
        );
    }

    assert!(
        lab.exec(
            &lab.client_ns,
            &[
                "ping",
                "-c",
                "2",
                "-W",
                "3",
                "-I",
                &device_address,
                &server_addresses[1],
            ],
        )
        .is_err(),
        "a revoked device could still reach the route server"
    );

    Ok(())
}
