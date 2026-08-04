//! Integration tests against a **real** libvirt + QEMU/KVM daemon.
//!
//! The `test:///default` driver used by the other tests is a mock: it accepts
//! almost any domain XML, so it proves the code paths run but not that libvirt
//! and QEMU actually accept what this backend generates. Every historical bug
//! in this backend (memory units, Proxmox-style disk paths, runtime domain ids)
//! would have passed against the mock driver.
//!
//! These tests are `#[ignore]`d so a normal `cargo test` run — and CI without
//! KVM — skips them.
//!
//! # Running
//!
//! ```sh
//! sudo apt-get install libvirt-daemon-system qemu-system-x86 ovmf
//! sudo virsh net-start default                      # provides virbr0
//! sudo mkdir -p /var/lib/lnvps-test-pool
//! sudo virsh pool-define-as lnvps-test dir --target /var/lib/lnvps-test-pool
//! sudo virsh pool-build lnvps-test && sudo virsh pool-start lnvps-test
//! sudo usermod -aG libvirt,kvm "$USER"              # then re-login, or use `sg`
//!
//! sg libvirt -c "cargo test -p lnvps_api_common --features libvirt -- --ignored --test-threads=1"
//! ```
//!
//! Override the connection with `LNVPS_LIBVIRT_URI` and the pool with
//! `LNVPS_LIBVIRT_POOL`.

use super::*;
use crate::VmRunningStates;

fn boot_image_url() -> String {
    std::env::var("LNVPS_LIBVIRT_BOOT_IMAGE").unwrap_or_else(|_| {
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
            .to_string()
    })
}

fn boot_image_sums() -> String {
    std::env::var("LNVPS_LIBVIRT_BOOT_SUMS").unwrap_or_else(|_| {
        "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS".to_string()
    })
}
use crate::host::config::QemuConfig;
use crate::host::tests::mock_full_vm;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Pool that must exist on the test host (see module docs).
fn pool() -> String {
    std::env::var("LNVPS_LIBVIRT_POOL").unwrap_or_else(|_| "lnvps-test".to_string())
}

fn uri() -> String {
    std::env::var("LNVPS_LIBVIRT_URI").unwrap_or_else(|_| "qemu:///system".to_string())
}

/// Bridge that exists on a stock libvirt install once the default network is
/// started. A non-existent bridge makes domain *start* fail, which would
/// otherwise look like a bug in this backend.
fn bridge() -> String {
    std::env::var("LNVPS_LIBVIRT_BRIDGE").unwrap_or_else(|_| "virbr0".to_string())
}

/// VM ids are namespaced per process so concurrent runs don't fight over the
/// same domain name.
/// A real (throwaway) public key, so the guest-side fingerprint can be checked.
const BOOT_TEST_SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFTaMmFtv32MYxi84pWG07OUR16lDVvmwVqSBrHgS9Pf lnvps-boot-test@example";
/// Comment on [`BOOT_TEST_SSH_KEY`]. cloud-init prints the comment of every
/// authorised key in its first-boot `ci-info` table, which is a stabler thing
/// to match on than the fingerprint format (it logs SHA-256, not MD5).
const BOOT_TEST_SSH_KEY_COMMENT: &str = "lnvps-boot-test@example";

fn next_vm_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    900_000 + (std::process::id() as u64 % 1000) * 100 + n
}

/// Hardware virtualisation, unless the environment says otherwise.
///
/// Set `LNVPS_LIBVIRT_KVM=0` to fall back to TCG emulation (`<domain
/// type='qemu'>`), which lets the suite run where `/dev/kvm` is unavailable at
/// the cost of a much slower boot.
fn use_kvm() -> bool {
    !matches!(
        std::env::var("LNVPS_LIBVIRT_KVM").as_deref(),
        Ok("0") | Ok("false")
    )
}

fn qemu_cfg() -> QemuConfig {
    QemuConfig {
        machine: "q35".to_string(),
        os_type: "l26".to_string(),
        bridge: bridge(),
        // A custom model cannot be used without KVM on an emulated CPU.
        cpu: if use_kvm() { "host" } else { "qemu64" }.to_string(),
        kvm: use_kvm(),
        arch: "x86_64".to_string(),
        balloon_min_pct: None,
        firewall_config: None,
    }
}

fn host() -> Result<LibVirtHost> {
    LibVirtHost::new(&uri(), host_config())
}

fn host_config() -> LibVirtConfig {
    LibVirtConfig {
        qemu: qemu_cfg(),
        image_pool: Some(pool()),
        // Pointing this at a stable path lets CI cache the (large) OS image
        // between runs instead of re-downloading it every time.
        image_cache_dir: std::env::var("LNVPS_LIBVIRT_IMAGE_CACHE").ok().map(Into::into),
        secure_boot: false,
        vlan_aware_bridge: std::env::var("LNVPS_LIBVIRT_VLAN_AWARE").is_ok(),
        // The fake image has no OS to answer ACPI, so don't wait a minute
        // for a graceful shutdown that can never happen.
        shutdown_timeout_secs: Some(2),
    }
}

/// A VM config pointing at the test pool, with the fields a real hypervisor
/// cares about set to values that exist on this host.
fn vm_info(vm_id: u64) -> FullVmInfo {
    let mut info = mock_full_vm();
    info.vm.id = vm_id;
    info.disk.name = pool();
    // The shared fixture uses ff:ff:ff:ff:ff:fe, which is a multicast address —
    // libvirt rejects it. Production MACs come from `generate_mac`.
    info.vm.mac_address = format!(
        "52:54:00:{:02x}:{:02x}:{:02x}",
        vm_id & 0xff,
        (vm_id >> 8) & 0xff,
        (vm_id >> 16) & 0xff
    );
    // The mock host is VLAN-tagged, but `<vlan>` on a plain Linux bridge is
    // rejected by libvirt — covered separately by `vlan_tagging_is_rejected`.
    info.host.vlan_id = None;
    // 100 GB of qcow2 is sparse, but keep the test cheap and fast.
    if let Some(t) = info.template.as_mut() {
        t.disk_size = 2 * crate::GB;
        t.memory = 512 * 1024 * 1024;
        t.cpu = 1;
    }
    info
}

/// Publish a small fake OS image so `create_vm` doesn't try to download one.
async fn seed_os_image(host: &LibVirtHost, info: &FullVmInfo) -> Result<()> {
    let dir = std::env::temp_dir().join("lnvps-libvirt-it");
    tokio::fs::create_dir_all(&dir).await?;
    let file = dir.join(format!("fake-os-{}.img", info.image.id));
    // 16 MiB of zeroes: not bootable, but a real disk image as far as
    // libvirt/QEMU are concerned.
    tokio::fs::write(&file, vec![0u8; 16 * 1024 * 1024]).await?;

    let format = VolumeFormat::from_url(&info.image.url);
    let volume = os_image_volume(info.image.id, format);
    let pool_name = pool();

    host.conn
        .run(move |c| {
            let pool = storage::find_pool(c, &pool_name)?;
            if storage::find_volume(&pool, &volume)?.is_some() {
                return Ok(());
            }
            storage::upload_volume(c, &pool, &volume, &file, format)?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    Ok(())
}

/// Read a domain's XML back from libvirt *after* it has parsed and normalised
/// it — this is what actually catches unit and schema mistakes.
async fn live_xml(host: &LibVirtHost, vm_id: u64) -> Result<String> {
    domain_xml(host, vm_id, 0).await
}

/// The *persistent* definition, which is what survives a restart. A running
/// domain's live XML still reports the values it booted with, so config changes
/// have to be checked here.
async fn inactive_xml(host: &LibVirtHost, vm_id: u64) -> Result<String> {
    domain_xml(host, vm_id, virt::sys::VIR_DOMAIN_XML_INACTIVE).await
}

async fn domain_xml(host: &LibVirtHost, vm_id: u64, flags: u32) -> Result<String> {
    host.conn
        .run(move |c| {
            let domain = LibVirtHost::require_domain(c, vm_id)?;
            domain
                .xml_desc(flags)
                .map_err(|e| map_virt_error("xml_desc", e))
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))
}

async fn cleanup(host: &LibVirtHost, info: &FullVmInfo) {
    let _ = host.delete_vm(&info.vm).await;
}

#[tokio::test]
#[ignore]
async fn qemu_accepts_generated_domain_xml() -> Result<()> {
    let host = host()?;
    let info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let xml = live_xml(&host, info.vm.id).await?;

    // Regression: <memory> without a unit is read by libvirt as KiB. libvirt
    // always echoes the value back in KiB, so 512 MiB must appear as 524288.
    let expected_kib = info.resources()?.memory / 1024;
    assert!(
        xml.contains(&format!("<memory unit='KiB'>{expected_kib}</memory>")),
        "memory was not interpreted as bytes; got:\n{xml}"
    );

    // The disk must resolve to a real file in the pool, not a literal
    // "pool:volume" path.
    assert!(
        xml.contains(&primary_disk_volume(info.vm.id)),
        "disk source not resolved:\n{xml}"
    );
    assert!(!xml.contains(&format!("{}:vm-", pool())), "got:\n{xml}");

    // Deterministic UUID survived the round-trip.
    assert!(
        xml.contains(&xml::domain_uuid(info.vm.id).to_string()),
        "uuid missing:\n{xml}"
    );

    cleanup(&host, &info).await;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn full_vm_lifecycle_on_real_qemu() -> Result<()> {
    let host = host()?;
    let info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    // Create → the domain must actually be running, not just defined.
    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    let state = host
        .get_vm_state(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert_eq!(state.state, VmRunningStates::Running);

    // Creating twice must be safe: the provisioning pipeline retries.
    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // Stop. The fake image has no OS to answer ACPI, so this exercises the
    // graceful-then-forced path.
    host.stop_vm(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    let state = host
        .get_vm_state(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert_eq!(state.state, VmRunningStates::Stopped);

    // Stopping an already-stopped VM is a no-op, not an error.
    host.stop_vm(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // Start again.
    host.start_vm(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert_eq!(
        host.get_vm_state(&info.vm)
            .await
            .map_err(|e| anyhow!("{:?}", e))?
            .state,
        VmRunningStates::Running
    );

    // Reset a running domain.
    host.reset_vm(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // Delete removes both the domain and its disk.
    host.delete_vm(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let vm_id = info.vm.id;
    let pool_name = pool();
    let leftovers = host
        .conn
        .run(move |c| {
            let domain_gone = LibVirtHost::lookup_domain(c, vm_id)?.is_none();
            let pool = storage::find_pool(c, &pool_name)?;
            let disk_gone = storage::find_volume(&pool, &primary_disk_volume(vm_id))?.is_none();
            Ok((domain_gone, disk_gone))
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert!(leftovers.0, "domain still defined after delete");
    assert!(leftovers.1, "disk volume still present after delete");

    // And deleting again is still fine (rollback re-runs).
    host.delete_vm(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn disk_is_cloned_at_the_requested_size() -> Result<()> {
    let host = host()?;
    let mut info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.import_template_disk(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let vm_id = info.vm.id;
    let pool_name = pool();
    let capacity = host
        .conn
        .run(move |c| {
            let pool = storage::find_pool(c, &pool_name)?;
            let vol = storage::find_volume(&pool, &primary_disk_volume(vm_id))?
                .ok_or_else(|| OpError::Fatal(anyhow!("disk not created")))?;
            Ok(vol
                .info()
                .map_err(|e| map_virt_error("vol_info", e))?
                .capacity)
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert_eq!(capacity, info.resources()?.disk_size);

    // Grow it and confirm libvirt agrees.
    if let Some(t) = info.template.as_mut() {
        t.disk_size = 3 * crate::GB;
    }
    host.resize_disk(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let pool_name = pool();
    let grown = host
        .conn
        .run(move |c| {
            let pool = storage::find_pool(c, &pool_name)?;
            let vol = storage::find_volume(&pool, &primary_disk_volume(vm_id))?
                .ok_or_else(|| OpError::Fatal(anyhow!("disk missing")))?;
            Ok(vol
                .info()
                .map_err(|e| map_virt_error("vol_info", e))?
                .capacity)
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert_eq!(grown, 3 * crate::GB);

    host.unlink_primary_disk(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn get_all_vm_states_sees_real_domains() -> Result<()> {
    let host = host()?;
    let info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let states = host
        .get_all_vm_states()
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    let found = states.iter().find(|(id, _)| *id == info.vm.id);
    assert!(
        found.is_some(),
        "created VM {} missing from host state list",
        info.vm.id
    );
    assert_eq!(found.unwrap().1.state, VmRunningStates::Running);

    cleanup(&host, &info).await;
    Ok(())
}

/// Boot a **real** distribution cloud image end to end.
///
/// The other integration tests use a 16 MiB file of zeroes: QEMU accepts it and
/// the domain runs, but nothing ever boots, so they prove the control plane
/// works and say nothing about whether a customer's VM would actually start.
/// This test downloads a genuine Debian cloud image through the production
/// `download_os_image` path (HTTP fetch → SHA-512 verification against the
/// published SHA512SUMS → upload into the pool), clones it, boots the VM and
/// waits for kernel output on the serial console.
///
/// Downloads ~400 MB on first run (cached afterwards in the image pool), so it
/// is `#[ignore]`d like the rest and takes a couple of minutes.
#[tokio::test]
#[ignore]
async fn real_cloud_image_boots() -> Result<()> {
    let host = host()?;
    let mut info = vm_info(next_vm_id());

    // A real distro image, verified against the distro's own checksum file.
    info.image.id = 900;
    info.image.url = boot_image_url();
    info.image.sha2_url = Some(boot_image_sums());
    if let Some(t) = info.template.as_mut() {
        // Must exceed the image's virtual size, and give the guest enough RAM
        // to actually reach userspace.
        t.disk_size = 8 * crate::GB;
        t.memory = 1024 * 1024 * 1024;
    }
    // A real, well-formed public key so the guest's own view of it can be
    // checked: cloud-init prints the MD5 fingerprint of every authorised key.
    info.ssh_key.key_data = BOOT_TEST_SSH_KEY.to_string().into();

    cleanup(&host, &info).await;

    // Exercises download + checksum verification + upload for real.
    host.download_os_image(&info.image)
        .await
        .map_err(|e| anyhow!("image publish failed: {:?}", e))?;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("create failed: {:?}", e))?;

    assert_eq!(
        host.get_vm_state(&info.vm)
            .await
            .map_err(|e| anyhow!("{:?}", e))?
            .state,
        VmRunningStates::Running
    );

    // The real proof: firmware handed off to a bootloader, the kernel found the
    // virtio disk, and userspace came up.
    // Require evidence from *userspace*, not just a firmware banner. The final
    // message comes from our own cloud-init user-data, so seeing it proves the
    // whole chain: firmware → kernel → init → cloud-init found the NoCloud seed
    // → parsed our documents → applied them.
    let started = Instant::now();
    let output = read_console(
        &host,
        info.vm.id,
        &["LNVPS VM", "login:"],
        Duration::from_secs(240),
    )
    .await?;
    // Keep the console log around: when a boot regression happens this is the
    // only evidence of what the guest actually did.
    let log_path = std::env::temp_dir().join(format!("lnvps-console-{}.log", info.vm.id));
    let _ = tokio::fs::write(&log_path, &output).await;
    println!(
        "guest reached userspace in {:?}; {} bytes of console output ({})",
        started.elapsed(),
        output.len(),
        log_path.display()
    );

    // The kernel banner must appear too — proves the bootloader handed off and
    // the kernel found the virtio disk.
    assert!(
        output.contains("Linux version"),
        "no kernel banner on the console:\n{}",
        tail(&output, 2000)
    );
    assert!(
        output.contains("virtio"),
        "kernel never probed the virtio disk:\n{}",
        tail(&output, 2000)
    );

    // The `final_message` comes from our own user-data, so this alone proves
    // cloud-init found the seed, parsed it, and ran to completion.
    let hostname = crate::host::cloud_init::hostname(info.vm.id);
    assert!(
        output.contains(&format!("LNVPS {hostname} ready")),
        "cloud-init never applied our user-data:\n{}",
        tail(&output, 4000)
    );

    // The customer's key must be in the guest's authorized_keys. cloud-init
    // prints an MD5 fingerprint table for them at first boot.
    assert!(
        output.contains("Authorized keys from"),
        "cloud-init installed no authorized keys:\n{}",
        tail(&output, 4000)
    );
    assert!(
        output.contains(BOOT_TEST_SSH_KEY_COMMENT),
        "the customer's SSH key ({BOOT_TEST_SSH_KEY_COMMENT}) is not authorised in the \
         guest \u{2014} they would be locked out:\n{}",
        tail(&output, 4000)
    );

    // The hostname from meta-data reached the guest (its host keys are
    // generated with it as the comment).
    assert!(
        output.contains(&hostname),
        "guest never took the hostname {hostname}:\n{}",
        tail(&output, 4000)
    );

    // A VM that boots must also report real usage, not zeroes.
    let state = host
        .get_vm_state(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert!(
        state.disk_read > 0,
        "a booted guest must have read from its disk, got {}",
        state.disk_read
    );

    cleanup(&host, &info).await;
    Ok(())
}

/// Read the guest's serial console until one of `markers` appears.
///
/// Uses a non-blocking libvirt stream so a silent guest hits the deadline
/// instead of hanging the test runner forever.
async fn read_console(
    host: &LibVirtHost,
    vm_id: u64,
    markers: &[&str],
    timeout: Duration,
) -> Result<String> {
    let markers: Vec<String> = markers.iter().map(|m| m.to_string()).collect();
    let for_closure = markers.clone();

    let output = host
        .conn
        .run(move |c| {
            let markers = for_closure;
            let domain = LibVirtHost::require_domain(c, vm_id)?;
            let stream = virt::stream::Stream::new(c, virt::sys::VIR_STREAM_NONBLOCK)
                .map_err(|e| map_virt_error("new_stream", e))?;
            domain
                .open_console(None, &stream, 0)
                .map_err(|e| map_virt_error("open_console", e))?;

            let deadline = Instant::now() + timeout;
            let mut collected = String::new();
            let mut buf = [0u8; 4096];
            while Instant::now() < deadline {
                match stream.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        collected.push_str(&String::from_utf8_lossy(&buf[..n as usize]));
                        if markers.iter().any(|m| collected.contains(m)) {
                            return Ok(collected);
                        }
                    }
                    // -2 is libvirt's "would block" on a non-blocking stream.
                    Ok(_) => std::thread::sleep(Duration::from_millis(200)),
                    Err(e) => return Err(map_virt_error("stream_recv", e)),
                }
            }
            Ok(collected)
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let matched = markers.iter().any(|m| output.contains(m));
    assert!(
        matched,
        "guest never reached a booted state within {timeout:?}. Console output was:\n{}",
        tail(&output, 4000)
    );
    Ok(output)
}

fn tail(s: &str, n: usize) -> &str {
    if s.len() <= n { s } else { &s[s.len() - n..] }
}

/// The console proxy must carry bytes in both directions against a real guest.
///
/// Exercises the production `connect_terminal` path, not the test helper.
#[tokio::test]
#[ignore]
async fn terminal_proxy_reads_and_writes() -> Result<()> {
    let host = host()?;
    let mut info = vm_info(next_vm_id());
    info.image.id = 900;
    info.image.url = boot_image_url();
    info.image.sha2_url = Some(boot_image_sums());
    if let Some(t) = info.template.as_mut() {
        t.disk_size = 8 * crate::GB;
        t.memory = 1024 * 1024 * 1024;
    }
    info.ssh_key.key_data = BOOT_TEST_SSH_KEY.to_string().into();

    cleanup(&host, &info).await;
    host.download_os_image(&info.image)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let mut term = host
        .connect_terminal(&info.vm)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // Read side: boot output must arrive through the proxy's channel.
    let mut seen = String::new();
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), term.rx.recv()).await {
            Ok(Some(chunk)) => {
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if seen.contains("login:") {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    assert!(
        seen.contains("Linux version"),
        "no boot output through the terminal proxy:\n{}",
        tail(&seen, 2000)
    );

    // Write side: a newline at the login prompt must make the guest respond
    // with a fresh prompt, proving input reaches the guest.
    assert!(
        seen.contains("login:"),
        "guest never reached a login prompt:\n{}",
        tail(&seen, 2000)
    );
    term.tx
        .send(b"\n".to_vec())
        .await
        .map_err(|e| anyhow!("terminal write failed: {e}"))?;

    let mut echoed = String::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !echoed.contains("login:") {
        match tokio::time::timeout(Duration::from_secs(5), term.rx.recv()).await {
            Ok(Some(chunk)) => echoed.push_str(&String::from_utf8_lossy(&chunk)),
            Ok(None) => break,
            Err(_) => {}
        }
    }
    assert!(
        echoed.contains("login:"),
        "guest did not respond to console input:\n{}",
        tail(&echoed, 1000)
    );

    // Dropping the client must let the pump thread exit rather than leak.
    drop(term);
    cleanup(&host, &info).await;
    Ok(())
}

/// libvirt must accept the generated nwfilter and attach it to the interface.
#[tokio::test]
#[ignore]
async fn firewall_rules_are_applied_to_the_interface() -> Result<()> {
    use lnvps_db::{VmFirewallDirection, VmFirewallProtocol, VmFirewallRule, VmFirewallRuleAction};

    let host = host()?;
    let mut info = vm_info(next_vm_id());
    info.firewall_rules = vec![
        VmFirewallRule {
            id: 1,
            vm_id: info.vm.id,
            priority: 1,
            direction: VmFirewallDirection::Inbound,
            protocol: VmFirewallProtocol::Tcp,
            action: VmFirewallRuleAction::Accept,
            src_cidr: Some("10.9.0.0/16".to_string()),
            dst_port_start: Some(22),
            dst_port_end: Some(22),
            enabled: true,
            ..Default::default()
        },
        VmFirewallRule {
            id: 2,
            vm_id: info.vm.id,
            priority: 2,
            direction: VmFirewallDirection::Inbound,
            protocol: VmFirewallProtocol::Any,
            action: VmFirewallRuleAction::Drop,
            enabled: true,
            ..Default::default()
        },
    ];

    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // The domain must reference the filter...
    let xml = live_xml(&host, info.vm.id).await?;
    let filter = nwfilter::filter_name(info.vm.id);
    assert!(
        xml.contains(&filter),
        "interface does not reference {filter}:\n{xml}"
    );

    // ...and libvirt must have stored the rules we generated.
    let filter_xml: String = host
        .conn
        .run(move |c| {
            let f = c
                .lookup_nwfilter_by_name(&filter)
                .map_err(|e| map_virt_error("lookup_nwfilter", e))?;
            f.xml_desc(0).map_err(|e| map_virt_error("nwfilter_xml", e))
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    assert!(filter_xml.contains("dstportstart='22'"), "got {filter_xml}");
    assert!(filter_xml.contains("10.9.0.0"), "got {filter_xml}");
    assert!(filter_xml.contains("no-mac-spoofing"), "got {filter_xml}");
    assert!(filter_xml.contains("drop"), "got {filter_xml}");

    cleanup(&host, &info).await;
    Ok(())
}

/// A running guest must see a disk grow without being power-cycled.
#[tokio::test]
#[ignore]
async fn disk_resize_is_applied_to_the_running_guest() -> Result<()> {
    let host = host()?;
    let mut info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    if let Some(t) = info.template.as_mut() {
        t.disk_size = 4 * crate::GB;
    }
    // Fails if libvirt rejects the live block_resize on the running domain.
    host.resize_disk(&info)
        .await
        .map_err(|e| anyhow!("live resize failed: {:?}", e))?;

    let vm_id = info.vm.id;
    let pool_name = pool();
    let capacity = host
        .conn
        .run(move |c| {
            let pool = storage::find_pool(c, &pool_name)?;
            let vol = storage::find_volume(&pool, &primary_disk_volume(vm_id))?
                .ok_or_else(|| OpError::Fatal(anyhow!("disk missing")))?;
            Ok(vol
                .info()
                .map_err(|e| map_virt_error("vol_info", e))?
                .capacity)
        })
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert_eq!(capacity, 4 * crate::GB);

    cleanup(&host, &info).await;
    Ok(())
}

/// `configure_vm` must persist the new config and apply what it can live.
#[tokio::test]
#[ignore]
async fn configure_vm_updates_running_domain() -> Result<()> {
    let host = host()?;
    let mut info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // Shrink the balloon, which libvirt can do live on a running domain.
    let new_memory = 256 * 1024 * 1024u64;
    if let Some(t) = info.template.as_mut() {
        t.memory = new_memory;
    }
    host.configure_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    // Whatever libvirt could or couldn't do live, the persistent definition
    // must carry the new value so a restart applies it. (The *live* XML still
    // reports the memory the domain booted with, which is why this reads the
    // inactive definition.)
    let xml = inactive_xml(&host, info.vm.id).await?;
    assert!(
        xml.contains(&format!(
            "<memory unit='KiB'>{}</memory>",
            new_memory / crate::KB
        )),
        "persistent config not updated:\n{xml}"
    );

    // The running domain must be left alone and healthy.
    assert_eq!(
        host.get_vm_state(&info.vm)
            .await
            .map_err(|e| anyhow!("{:?}", e))?
            .state,
        VmRunningStates::Running
    );

    cleanup(&host, &info).await;
    Ok(())
}

/// Discovery must see the VMs on the host, including ones LNVPS doesn't manage.
#[tokio::test]
#[ignore]
async fn list_host_vms_reports_domains() -> Result<()> {
    let host = host()?;
    let info = vm_info(next_vm_id());
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    host.create_vm(&info)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    let vms = host.list_host_vms().await.map_err(|e| anyhow!("{:?}", e))?;
    let found = vms
        .iter()
        .find(|v| v.mapped_vm_id == Some(info.vm.id))
        .expect("created VM missing from discovery");

    assert_eq!(
        found.name.as_deref(),
        Some(domain_name(info.vm.id).as_str())
    );
    assert!(found.running, "VM should be reported as running");
    assert_eq!(found.cpu, info.resources()?.cpu);
    assert_eq!(found.memory, info.resources()?.memory);
    // Resolved back through the storage pool.
    assert_eq!(found.disk_storage.as_deref(), Some(pool().as_str()));
    assert_eq!(found.disk_size, info.resources()?.disk_size);
    assert_eq!(
        found.mac_address.as_deref(),
        Some(info.vm.mac_address.as_str())
    );
    // A running domain has a libvirt runtime id.
    assert!(found.host_vm_id >= 0);

    cleanup(&host, &info).await;
    Ok(())
}

/// A VLAN-tagged host must not silently produce an untagged VM.
///
/// libvirt **accepts** `<vlan>` on a bridge interface and QEMU starts happily,
/// but a Linux bridge without `vlan_filtering=1` ignores the tag completely —
/// verified on libvirt 11.3 against `virbr0`, where the guest joined the
/// untagged network with no error anywhere. For a multi-tenant VPS host that is
/// an isolation failure, so the backend refuses unless the operator has
/// explicitly declared the bridge VLAN-aware.
#[tokio::test]
#[ignore]
async fn vlan_requires_an_explicitly_vlan_aware_bridge() -> Result<()> {
    let mut cfg = host_config();
    cfg.vlan_aware_bridge = false;
    let host = LibVirtHost::new(&uri(), cfg)?;

    let mut info = vm_info(next_vm_id());
    info.host.vlan_id = Some(100);
    seed_os_image(&host, &info).await?;
    cleanup(&host, &info).await;

    let result = host.create_vm(&info).await;
    cleanup(&host, &info).await;

    let err = result.expect_err("a VLAN host on a non-VLAN-aware bridge must fail");
    assert!(matches!(err, OpError::Fatal(_)), "got {err:?}");
    let msg = format!("{err:?}");
    assert!(msg.contains("vlan") || msg.contains("VLAN"), "got {msg}");

    // No half-created VM may be left behind by the refusal.
    let vm_id = info.vm.id;
    let exists = host
        .conn
        .run(move |c| Ok(LibVirtHost::lookup_domain(c, vm_id)?.is_some()))
        .await
        .map_err(|e| anyhow!("{:?}", e))?;
    assert!(!exists, "domain was defined despite the VLAN refusal");
    Ok(())
}
