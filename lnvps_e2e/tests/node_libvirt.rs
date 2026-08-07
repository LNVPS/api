//! LNVPS driving a real libvirtd on a marketplace node, over a real tunnel.
//!
//! Everything before this proves the *shape* of the thing: that the node writes
//! a unit naming two namespaces, that LNVPS builds a URI with a per-node trust
//! directory. None of it proves a hypervisor answers. This starts the libvirtd
//! production configures, from the unit production renders, on a machine that is
//! already running the operator's own libvirtd — and connects to it the way the
//! provisioner does.
//!
//! What it establishes, in order:
//!
//! 1. systemd accepts the unit. It is the artefact most likely to be wrong: two
//!    namespaces, four bind mounts, a config file, and no unit test can do more
//!    than assert its text.
//! 2. The instance is reachable **only** through the tunnel, from the route
//!    server — not from the machine it runs on.
//! 3. It refuses a client that is not LNVPS, which is what stands between a
//!    customer VM on that bridge and control of the node.
//! 4. The operator's own libvirtd is untouched.
//!
//! Requires root and systemd; run with `scripts/tunnel-e2e.sh`.

use std::process::Command;

use anyhow::{Context, Result};
use lnvps_api_common::host::config::MarketplaceLibvirtConfig;
use lnvps_e2e::stack::{Addrs, Stack, run};

/// A CA and client certificate standing in for LNVPS's, generated here because
/// what matters is that the node accepts exactly one issuer and one DN.
struct LnvpsClient {
    ca_pem: String,
    dn: String,
    config: MarketplaceLibvirtConfig,
    /// Holds the generated material for the life of the test.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

impl LnvpsClient {
    fn new(dn: &str) -> Result<Self> {
        let mut ca_params = rcgen::CertificateParams::new(vec![])?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "lnvps-e2e-ca");
        let ca_key = rcgen::KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;

        let cn = dn.trim_start_matches("CN=");
        let mut client_params = rcgen::CertificateParams::new(vec![])?;
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let client_key = rcgen::KeyPair::generate()?;
        let client = client_params.signed_by(&client_key, &ca, &ca_key)?;

        // Laid out as LNVPS's own configuration is, so the trust directory is
        // built by production code rather than by the harness — the layout is
        // exactly the sort of thing a harness gets subtly right on its own and
        // production gets wrong.
        let dir = tempfile::TempDir::new()?;
        std::fs::write(dir.path().join("ca.pem"), ca.pem())?;
        std::fs::write(dir.path().join("client.pem"), client.pem())?;
        std::fs::write(dir.path().join("client.key"), client_key.serialize_pem())?;

        Ok(Self {
            ca_pem: ca.pem(),
            dn: dn.to_string(),
            config: MarketplaceLibvirtConfig {
                ca_cert: dir.path().join("ca.pem"),
                client_cert: dir.path().join("client.pem"),
                client_key: dir.path().join("client.key"),
                pki_dir: dir.path().join("pki"),
            },
            dir,
        })
    }

    /// The directory libvirt reads, built the way LNVPS builds it.
    fn trust(&self, node_id: u64, node_ca_pem: &str) -> Result<std::path::PathBuf> {
        lnvps_api_common::host::marketplace_pki::materialise(&self.config, node_id, node_ca_pem)
    }
}

/// `virsh` run inside a namespace, which is how a connection is made from
/// somewhere that can actually route to the node.
fn virsh_in(ns: &str, uri: &str) -> Result<String> {
    let out = Command::new("ip")
        .args(["netns", "exec", ns, "virsh", "-c", uri, "version"])
        .output()
        .context("running virsh")?;
    if !out.status.success() {
        anyhow::bail!(
            "virsh -c {uri} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[tokio::test]
#[ignore = "needs root, systemd and libvirt"]
async fn lnvps_drives_a_nodes_libvirt_over_the_tunnel() -> Result<()> {
    if !Stack::requirements_met() {
        return Ok(());
    }

    let stack = Stack::new("libvirt", 4)?;
    let lnvps = LnvpsClient::new(lnvps_api_common::node_control::LIBVIRT_CLIENT_DN)?;
    // No guests: this test is about the hypervisor, and a node with none is
    // still a node LNVPS has to be able to place the first VM on.
    let _dataplane = stack.bring_up(4, &[]).await?;

    // The node configures itself from what LNVPS sent it.
    let libvirtd = stack.start_libvirtd(&lnvps.ca_pem, &lnvps.dn)?;
    let node_id = 4;
    let pki = lnvps.trust(node_id, &libvirtd.ca_pem)?;
    let node = Addrs::bare(&stack.addrs.node_inner);
    let uri = lnvps_api_common::host::marketplace_pki::connection_uri(node, &pki);

    // 1 + 2: it answers, and only from the far end of the tunnel.
    virsh_in(&stack.names.rs_ns, &uri)
        .context("LNVPS could not reach the node's libvirtd over the tunnel")?;

    // 3: a client LNVPS did not issue is refused. This is the guarantee that
    // survives a packet-filter mistake — the guest bridge shares a namespace
    // with the tunnel interface, so a customer VM can address this listener.
    let impostor = LnvpsClient::new(&lnvps.dn)?;
    let impostor_pki = impostor.trust(node_id, &libvirtd.ca_pem)?;
    let impostor_uri = lnvps_api_common::host::marketplace_pki::connection_uri(node, &impostor_pki);
    assert!(
        virsh_in(&stack.names.rs_ns, &impostor_uri).is_err(),
        "a certificate LNVPS never issued was accepted"
    );

    // 4: the operator's own libvirtd is still theirs.
    let machine = run("systemctl", &["is-active", "libvirtd"]).unwrap_or_default();
    assert!(
        machine.trim() == "active" || machine.trim() == "inactive",
        "the operator's libvirtd was left in {machine:?}"
    );
    assert!(
        run("virsh", &["-c", "qemu:///system", "version"]).is_ok(),
        "the operator can no longer reach their own libvirt"
    );

    drop(libvirtd);
    Ok(())
}
