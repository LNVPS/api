//! Cloud-init document generation shared by the hypervisor backends.
//!
//! Proxmox delivers these through host snippets (`cicustom`), libvirt through a
//! NoCloud seed image. The *content* is identical either way, so the IP/gateway
//! handling in particular lives here rather than being reimplemented per
//! backend — it has enough edge cases (SLAAC, off-subnet gateways, multiple
//! ranges) that two copies would inevitably diverge.

use crate::host::FullVmInfo;
use crate::network::parse_gateway;
use anyhow::Result;
use ipnetwork::IpNetwork;
use lnvps_db::IpRangeAllocationMode;
use serde::Serialize;
use std::net::IpAddr;

/// DNS resolvers forced into every guest's `/etc/resolv.conf`.
pub const GUEST_DNS_SERVERS: &[&str] = &[
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    // IPv6 variants of the same providers (Cloudflare, Google, Quad9).
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2620:fe::fe",
];

/// Guest hostname for a VM.
///
/// Matches the Proxmox backend's VM name so a guest keeps the same identity
/// wherever it is hosted.
pub fn hostname(vm_id: u64) -> String {
    format!("VM{vm_id}")
}

/// A rendered netplan v2 document plus the address counts that produced it.
///
/// The counts let the Proxmox backend keep its existing rule of only writing a
/// network snippet when the simple `ipconfig` path cannot express the layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub yaml: String,
    pub v4_count: usize,
    pub v6_count: usize,
}

/// Build a cloud-init v2 (netplan) network configuration for a VM.
///
/// Addresses are matched to the NIC by MAC rather than by interface name,
/// because the guest's name for it depends on the distro's naming scheme.
pub fn network_config(value: &FullVmInfo) -> Result<NetworkConfig> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut gw4 = None;
    let mut gw6 = None;
    let mut accept_ra = false;

    for ip in &value.ips {
        let addr: IpAddr = match ip.ip.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let ip_range = match value.ranges.iter().find(|r| r.id == ip.ip_range_id) {
            Some(r) => r,
            None => continue,
        };
        if addr.is_ipv6() && matches!(ip_range.allocation_mode, IpRangeAllocationMode::SlaacEui64) {
            // The host hands out the address; what the database holds is
            // informational only.
            accept_ra = true;
            continue;
        }
        let range: IpNetwork = ip_range.cidr.parse()?;
        let range_gw: IpNetwork = parse_gateway(&ip_range.gateway)?;
        // Take the shorter prefix so an off-subnet gateway stays directly
        // reachable without needing an explicit on-link route.
        //
        // A guest whose prefix covers its gateway also treats everything else
        // in that prefix as on-link, and will resolve those addresses on the
        // link rather than sending them to the router. That is fine on a
        // customer range, where the node proxies for the addresses in it, and
        // wrong on a routed block, where the machine at the other end is up a
        // tunnel and nothing on the link answers for it.
        let prefix = range.prefix().min(range_gw.prefix());
        let cidr = IpNetwork::new(addr, prefix)?.to_string();
        if addr.is_ipv4() {
            // Only one default route per family is meaningful; addresses from a
            // second range stay reachable on-link through the widened prefix.
            gw4.get_or_insert_with(|| range_gw.ip());
            v4.push(cidr);
        } else {
            gw6.get_or_insert_with(|| range_gw.ip());
            v6.push(cidr);
        }
    }

    // Quoted, and this is not cosmetic. YAML 1.1 reads a colon-separated run of
    // digits as a base-60 integer, so a MAC with no hex letters in it —
    // `52:54:01:00:00:01` — is parsed as the number 41135256001. netplan then
    // refuses it ("Invalid MAC address"), cloud-init aborts its network stage,
    // and the guest boots with no network at all on a host that is working.
    //
    // It bites intermittently, which is worse than always: a MAC containing any
    // letter is a string and works, so roughly one VM in sixteen breaks and the
    // rest are fine.
    let mut cfg = String::from("version: 2\nethernets:\n  nic0:\n    match:\n      macaddress: \"");
    cfg.push_str(&value.vm.mac_address.to_lowercase());
    cfg.push_str("\"\n    dhcp4: false\n    dhcp6: false\n");
    if accept_ra {
        cfg.push_str("    accept-ra: true\n");
    }
    cfg.push_str("    addresses:\n");
    for a in v4.iter().chain(v6.iter()) {
        // Quoted for the same reason as the MAC: an address is a value with
        // colons in it, and the parser's opinion of those is not ours.
        cfg.push_str(&format!("      - \"{a}\"\n"));
    }
    // `on-link` when the gateway is not inside the guest's own prefix: without
    // it the guest has no way to reach the router at all, because the address
    // it is told to send everything to is one it believes is somewhere else.
    // netplan is explicit about this and silently produces an unusable
    // configuration otherwise.
    let on_link = |gw: IpAddr| {
        let covered = v4
            .iter()
            .chain(v6.iter())
            .filter_map(|a| a.parse::<IpNetwork>().ok())
            .any(|a| a.contains(gw));
        if covered {
            ""
        } else {
            "\n        on-link: true"
        }
    };
    let routes: Vec<String> = gw4
        .into_iter()
        .chain(gw6)
        .map(|gw| format!("      - to: default\n        via: \"{gw}\"{}", on_link(gw)))
        .collect();
    if !routes.is_empty() {
        cfg.push_str("    routes:\n");
        for r in &routes {
            cfg.push_str(r);
            cfg.push('\n');
        }
    }

    Ok(NetworkConfig {
        yaml: cfg,
        v4_count: v4.len(),
        v6_count: v6.len(),
    })
}

/// NoCloud `meta-data` document.
///
/// `instance-id` is derived from the VM id and stays stable for the life of the
/// VM: cloud-init re-runs its per-instance modules whenever it changes, which
/// would regenerate host keys and reset the hostname on every boot.
pub fn meta_data(value: &FullVmInfo) -> Result<String> {
    let data = MetaData {
        instance_id: format!("lnvps-vm-{}", value.vm.id),
        local_hostname: hostname(value.vm.id),
    };
    Ok(serde_yaml_ng::to_string(&data)?)
}

/// NoCloud `user-data` document.
pub fn user_data(value: &FullVmInfo) -> Result<String> {
    // NOTE: `EncryptedString`'s Display impl deliberately renders "[ENCRYPTED]"
    // so secrets cannot leak into logs. Using it here would authorise that
    // literal string as the customer's SSH key and lock them out of their VM.
    let key = value.ssh_key.key_data.as_str().to_string();
    if key.is_empty() {
        anyhow::bail!("VM {} has an empty SSH key", value.vm.id);
    }
    let mut users = vec![UserEntry::Default];

    // Cloud images ship a distro-specific unprivileged user (`debian`,
    // `ubuntu`, ...). Recreating it explicitly with the customer's key means
    // the key lands on the account they will actually try to log in as.
    if let Some(username) = value
        .image
        .default_username
        .as_ref()
        .filter(|u| !u.is_empty())
    {
        users.push(UserEntry::User(CloudInitUser {
            name: username.clone(),
            sudo: "ALL=(ALL) NOPASSWD:ALL".to_string(),
            // No password is ever set, so the account is key-only.
            lock_passwd: true,
            ssh_authorized_keys: vec![key.clone()],
        }));
    }

    let has_dns = !GUEST_DNS_SERVERS.is_empty();
    let data = UserData {
        hostname: hostname(value.vm.id),
        // The hostname must survive reboots and DHCP.
        preserve_hostname: false,
        manage_etc_hosts: true,
        users,
        // Also authorise the key for the image's default account, which is what
        // `ssh_authorized_keys` at the top level applies to.
        ssh_authorized_keys: vec![key],
        // Password auth stays off: these VMs are on public IPs from first boot.
        ssh_pwauth: false,
        disable_root: true,
        // Keep host keys stable so customers don't get MITM warnings after a
        // configuration change.
        ssh_deletekeys: false,
        manage_resolv_conf: has_dns.then_some(true),
        resolv_conf: has_dns.then(|| ResolvConf {
            nameservers: GUEST_DNS_SERVERS.iter().map(|s| s.to_string()).collect(),
        }),
        // Printed on the serial console when cloud-init finishes, which makes
        // "did personalisation actually run?" answerable from the console log.
        final_message: format!(
            "LNVPS {} ready after $UPTIME seconds",
            hostname(value.vm.id)
        ),
    };

    Ok(format!(
        "#cloud-config\n{}",
        serde_yaml_ng::to_string(&data)?
    ))
}

#[derive(Debug, Serialize)]
struct MetaData {
    #[serde(rename = "instance-id")]
    instance_id: String,
    #[serde(rename = "local-hostname")]
    local_hostname: String,
}

#[derive(Debug, Serialize)]
struct UserData {
    hostname: String,
    preserve_hostname: bool,
    manage_etc_hosts: bool,
    users: Vec<UserEntry>,
    ssh_authorized_keys: Vec<String>,
    ssh_pwauth: bool,
    disable_root: bool,
    ssh_deletekeys: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    manage_resolv_conf: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolv_conf: Option<ResolvConf>,
    final_message: String,
}

/// cloud-init's `users:` list mixes the literal string `default` with mappings.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum UserEntry {
    #[serde(serialize_with = "serialize_default_user")]
    Default,
    User(CloudInitUser),
}

fn serialize_default_user<S: serde::Serializer>(s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str("default")
}

#[derive(Debug, Serialize)]
struct CloudInitUser {
    name: String,
    sudo: String,
    lock_passwd: bool,
    ssh_authorized_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResolvConf {
    nameservers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::tests::mock_full_vm;

    #[test]
    fn hostname_matches_proxmox_naming() {
        assert_eq!(hostname(42), "VM42");
    }

    /// An all-digit MAC survives a YAML parser.
    ///
    /// YAML 1.1 reads `52:54:01:00:00:01` as a base-60 integer — 41135256001 —
    /// and netplan then rejects it as an invalid MAC, cloud-init aborts its
    /// network stage, and the guest boots with no network at all on a host that
    /// is working perfectly. A MAC containing any hex letter is a string and is
    /// unaffected, so this breaks about one VM in sixteen and looks like bad
    /// hardware. Found by a probe VM, whose MAC is derived from a node id and is
    /// therefore always all-digits.
    #[test]
    fn an_all_digit_mac_is_not_a_number() -> Result<()> {
        let mut vm = mock_full_vm();
        vm.vm.mac_address = "52:54:01:00:00:01".to_string();

        let cfg = network_config(&vm)?;

        // Asserted on the text, not by parsing it back. The parser in this
        // workspace is YAML 1.2, which dropped sexagesimal integers and so
        // reads this correctly whether or not it is quoted; the parser that
        // actually consumes this file is netplan's, which is 1.1. A test that
        // round-tripped through our own parser would pass with the bug present.
        assert!(
            cfg.yaml.contains(r#"macaddress: "52:54:01:00:00:01""#),
            "an unquoted MAC is a number to the parser that reads it:\n{}",
            cfg.yaml
        );
        Ok(())
    }

    #[test]
    fn network_config_sets_addresses_and_routes() -> Result<()> {
        let cfg = mock_full_vm();
        let net = network_config(&cfg)?;

        assert!(net.yaml.starts_with("version: 2"), "got {}", net.yaml);
        // Matched by MAC because the guest's interface name is distro-specific.
        assert!(
            net.yaml.contains(&cfg.vm.mac_address.to_lowercase()),
            "got {}",
            net.yaml
        );
        assert!(net.yaml.contains("dhcp4: false"), "got {}", net.yaml);
        assert!(net.yaml.contains("to: default"), "got {}", net.yaml);
        assert!(net.v4_count >= 1);
        Ok(())
    }

    #[test]
    fn network_config_skips_unparsable_ips() -> Result<()> {
        let mut cfg = mock_full_vm();
        cfg.ips[0].ip = "not-an-ip".to_string();
        // A bad row must not abort the whole config and leave the VM offline.
        let net = network_config(&cfg)?;
        assert!(!net.yaml.contains("not-an-ip"));
        Ok(())
    }

    #[test]
    fn meta_data_has_stable_instance_id() -> Result<()> {
        let cfg = mock_full_vm();
        let a = meta_data(&cfg)?;
        let b = meta_data(&cfg)?;
        // A changing instance-id makes cloud-init redo per-instance setup on
        // every boot, regenerating host keys.
        assert_eq!(a, b);
        assert!(a.contains("instance-id: lnvps-vm-1"), "got {a}");
        assert!(a.contains("local-hostname: VM1"), "got {a}");
        Ok(())
    }

    #[test]
    fn user_data_carries_the_ssh_key() -> Result<()> {
        let cfg = mock_full_vm();
        let out = user_data(&cfg)?;

        assert!(out.starts_with("#cloud-config\n"), "got {out}");
        assert!(
            out.contains(cfg.ssh_key.key_data.as_str()),
            "ssh key missing from user-data: {out}"
        );
        // Regression: `EncryptedString: Display` renders "[ENCRYPTED]", so
        // `to_string()` here would authorise that literal text as the key.
        assert!(
            !out.contains("[ENCRYPTED]"),
            "the placeholder Display value leaked into user-data: {out}"
        );
        assert!(out.contains("hostname: VM1"), "got {out}");
        // Public IPs from first boot: password auth must never be enabled.
        assert!(out.contains("ssh_pwauth: false"), "got {out}");
        assert!(out.contains("disable_root: true"), "got {out}");
        assert!(out.contains("nameservers:"), "got {out}");
        Ok(())
    }

    #[test]
    fn user_data_creates_the_image_default_user() -> Result<()> {
        let mut cfg = mock_full_vm();
        cfg.image.default_username = Some("debian".to_string());
        let out = user_data(&cfg)?;

        assert!(out.contains("name: debian"), "got {out}");
        assert!(out.contains("NOPASSWD"), "got {out}");
        assert!(out.contains("- default"), "got {out}");
        Ok(())
    }

    #[test]
    fn user_data_without_default_username_still_authorises_the_key() -> Result<()> {
        let mut cfg = mock_full_vm();
        cfg.image.default_username = None;
        let out = user_data(&cfg)?;

        assert!(out.contains("- default"), "got {out}");
        assert!(out.contains(cfg.ssh_key.key_data.as_str()), "got {out}");
        Ok(())
    }

    #[test]
    fn user_data_rejects_an_empty_ssh_key() {
        let mut cfg = mock_full_vm();
        cfg.ssh_key.key_data = "".to_string().into();
        // Silently shipping a keyless VM leaves the customer locked out with no
        // error to point at.
        assert!(user_data(&cfg).is_err());
    }

    #[test]
    fn rotating_the_key_changes_the_document() -> Result<()> {
        let mut cfg = mock_full_vm();
        let before = user_data(&cfg)?;
        cfg.ssh_key.key_data = "ssh-ed25519 AAAArotated user@host".to_string().into();
        let after = user_data(&cfg)?;
        assert_ne!(before, after);
        assert!(after.contains("AAAArotated"), "got {after}");
        Ok(())
    }

    #[test]
    fn user_data_is_valid_yaml() -> Result<()> {
        let cfg = mock_full_vm();
        let out = user_data(&cfg)?;
        // cloud-init silently ignores a document it cannot parse, which would
        // leave the VM unreachable with no error anywhere.
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(out.trim_start_matches("#cloud-config\n"))?;
        assert!(parsed.get("users").is_some());
        Ok(())
    }
}
