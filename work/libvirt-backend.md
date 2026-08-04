# LibVirt host backend implementation

**Status:** in-progress
**Started:** 2026-07-05
**Last updated:** 2026-07-05 (increments 1–4 complete; whole backend verified on real QEMU)

## Goal

Turn `lnvps_api_common`'s libvirt backend from a stub into a working
QEMU/KVM host client: full VM lifecycle, disk/image management, real state
reporting — with **no silent no-ops and no `todo!()` panics** anywhere.

Driven by `work/marketplace.md` (libvirt/QEMU chosen as the v1 VMM), but this is
useful independently: it is the second hypervisor backend alongside Proxmox.

## Findings

- The backend was a stub: only `get_info`, `generate_mac` and domain-XML
  generation were real. `create_vm` ended in `op_fatal!("Not implemented")`,
  seven methods were `todo!()` (panics), and `start_vm`/`stop_vm`/`reset_vm`
  **returned `Ok(())` without doing anything** while `get_vm_state` reported a
  hardcoded "Stopped".
- Bugs found in the pre-existing XML builder:
  - `<memory>` was emitted **without a unit**, and libvirt defaults to KiB —
    every VM would have been given 1024x its purchased RAM.
  - Disk source used the Proxmox-style `"pool:volume"` string in a `type="file"`
    disk; libvirt would have treated that as a literal file path.
  - `@id` (the *runtime* domain id, assigned by libvirt) was being sent.
  - No domain UUID, so a redefine changed guest-visible machine identity.
- `virt` 0.4.3 types (`Connect`, `Domain`, `StoragePool`, `StorageVol`) are all
  `Send + Sync`, so blocking calls can be dispatched with `spawn_blocking`.
- The libvirt **`test:///default` driver** supports domains and storage pools,
  so the backend is testable in CI without a hypervisor. Requires `libvirt-dev`
  (`pkg-config --modversion libvirt`) to link. **It is a mock and accepts almost
  any XML** — four real bugs passed its tests, see below.

### Bugs only a real *booting guest* caught

The first round of integration tests used a 16 MiB file of zeroes as the OS
image: QEMU accepts it and the domain runs, so the control plane looked correct
while **no VM could actually boot**. Booting a genuine Debian 13 genericcloud
image found three more:

5. **libvirt firmware autoselection picks the Microsoft secure-boot OVMF.**
   Given only `<os firmware='efi'>` with no constraints, libvirt chose
   `OVMF_CODE_4M.ms.fd` (`secure-boot` + `enrolled-keys` enabled). The guest
   then produced **no console output at all** — no firmware banner, no
   bootloader, no kernel — indistinguishable from a corrupt disk. Fixed by
   always emitting explicit `<firmware><feature .../></firmware>` constraints,
   which pins the plain `OVMF_CODE_4M.fd` build unless secure boot is asked for.
6. **A serde `rename` on a struct definition does not name the field's
   element.** The fix for (5) first serialized as `<firmware_features>`, which
   libvirt **silently ignored** — the wrong firmware kept being selected and the
   unit test still passed because it only asserted on the inner `<feature>`
   text. Needed `#[serde(rename = "firmware")]` on the field, and the test now
   asserts the wrapper element too.
7. **libvirt's event loop must be running for console streams.** Over
   `qemu:///system` (the remote driver), `virDomainOpenConsole` succeeds and
   then every read returns "would block" forever unless
   `virEventRegisterDefaultImpl` + a thread running `virEventRunDefaultImpl`
   are active. Now started once per process from `LibVirtConn::open` — required
   for `connect_terminal` in increment 3, not just for tests.

### Bugs only a real hypervisor caught (libvirt 11.3 + QEMU 10, Debian 13)

1. **`<loader secure="true">`** — libvirt wants `yes`/`no`, not `true`/`false`:
   *"Invalid value for attribute 'secure' in element 'loader'"*. **Pre-existing**
   in the original code, so no VM could ever have been defined. Fixed with a
   `YesNo` type; secure boot is now opt-in (`secure-boot`) and pulls in the
   `<smm state='on'/>` feature libvirt requires alongside it.
2. **`<disk type='volume'>` breaks DAC relabelling.** libvirt does not chown the
   backing file for volume-typed disks, so QEMU (running as `libvirt-qemu`) gets
   `Permission denied` on the root-owned image and the domain fails to start.
   Proven by defining the same disk both ways against the same file: `volume`
   fails, `file` starts. The backend now resolves the volume path via libvirt
   and emits `<disk type='file'>`.
3. **`VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA` is invalid for raw volumes**
   (*"metadata preallocation is not supported for raw volumes"*). The flag is
   now only passed for qcow2.
4. **VLAN tags are silently ignored on a non-VLAN-aware bridge.** libvirt
   *accepts* `<vlan><tag id='100'/></vlan>` on a bridge interface and QEMU starts
   normally, but a Linux bridge with `vlan_filtering=0` (verified on `virbr0`)
   drops the tag and the guest joins the **untagged** network — a tenant
   isolation failure with no error anywhere. Creation now fails unless the
   operator sets `vlan-aware-bridge: true`.

Also found: a guest that ignores ACPI (no OS, crashed, or hostile) left
`stop_vm` reporting success while the VM kept running. `stop_vm` now waits
`shutdown-timeout-secs` (default 60) then forces power off.

### Deployment findings

- **AppArmor**: `virt-aa-helper` only whitelists standard image paths. A storage
  pool outside e.g. `/var/lib/libvirt/images/**` is denied (`apparmor="DENIED"
  ... profile="virt-aa-helper"`), and the VM fails to start with a confusing
  `Permission denied`. Pools must live under a permitted path or need a local
  AppArmor override.
- The mock test fixture's MAC (`ff:ff:ff:ff:ff:fe`) is **multicast**; libvirt
  rejects it (*"expected unicast mac address"*). Production MACs come from
  `generate_mac` (52:54:00 OUI) so this only affects tests.
- Pre-existing unrelated failures on master: `capacity::tests::nan_load_*` (2).

## Tasks

### Increment 1 — module split, lifecycle, storage, state  ✅ DONE
- [x] Split `host/libvirt.rs` into `host/libvirt/{mod,conn,error,xml,storage,image,stats}.rs`
- [x] `conn.rs`: `spawn_blocking` dispatch + transparent reconnect on a dead connection
- [x] `error.rs`: libvirt error code → `OpError::Fatal`/`Transient` classification
- [x] `xml.rs`: fixed memory units, deterministic UUID (v5), volume-backed disks,
      virtio NIC + MTU, serial/console, `<features>`, CPU mode, `<iotune>` from
      template limits, bandwidth caps; live-XML device parser
- [x] `storage.rs`: pool/volume lookup with helpful errors, idempotent delete,
      clone-from-image, grow-only resize, streaming volume upload
- [x] `image.rs`: OS image download with SHA-256/384/512 verification + local cache
- [x] `stats.rs`: domain state mapping, CPU-time delta sampler
- [x] `mod.rs`: full `VmHostClient` impl — no `todo!()`, no silent `Ok(())`
- [x] Config: `image-pool`, `image-cache-dir`, `allow-unconfigured-guests`
- [x] 48 unit / mock-driver tests + **6 `#[ignore]`d integration tests against a
      real `qemu:///system`** (`qemu_tests.rs`): XML acceptance + memory-unit
      round-trip, full lifecycle (create/state/stop/start/reset/delete), disk
      clone + resize sizes, host state listing, VLAN refusal, and a **real
      Debian cloud image booting to userspace**. clippy + fmt clean
- [x] Fixed the seven real-hypervisor bugs listed under Findings
- [x] `real_cloud_image_boots`: downloads the actual Debian 13 genericcloud
      image through the production `download_os_image` path (HTTP → SHA-512
      against the published SHA512SUMS → upload to pool), clones it, boots the
      VM, and reads the serial console until `systemd[1]:` appears, asserting
      the kernel banner and virtio disk probe are present. Observed: userspace
      in ~2.8s, 43 KB of console output.

### Increment 2 — cloud-init guest personalisation  ✅ DONE
- [x] `host/cloud_init.rs` (**shared with Proxmox**): `user-data`, `meta-data`
      and netplan v2 `network-config`. The IP/gateway logic was *extracted from*
      `proxmox.rs::make_network_config` rather than reimplemented, so the two
      hypervisors cannot drift; Proxmox keeps its "only when >1 address per
      family" rule by checking the returned counts. Its existing tests pass
      unchanged.
- [x] `host/libvirt/iso9660.rs`: minimal ISO9660 writer producing a `cidata`
      labelled seed. Deterministic output (fixed timestamps) so an unchanged
      config yields identical bytes. No new dependency.
- [x] Seed published as a storage volume (`vm-<id>-seed.iso`) via a new
      `storage::upload_bytes`, attached read-only as a SATA CD-ROM.
- [x] Regenerated on `configure_vm` so key/IP changes reach the guest, and
      swept on `delete_vm`.
- [x] `allow-unconfigured-guests` removed — the backend can personalise guests,
      so the escape hatch is gone.
- [x] Verified end to end on real hardware (see below).

**Bug caught by the boot test — `EncryptedString` renders as `[ENCRYPTED]`.**
`UserSshKey.key_data` is an `EncryptedString` whose `Display` impl deliberately
returns the literal `[ENCRYPTED]` to keep secrets out of logs. The first draft
used `.to_string()`, which would have authorised the text `[ENCRYPTED]` as every
customer's SSH key — locking all of them out while looking perfectly healthy.
Fixed by using `.as_str()` (as `proxmox.rs` already did) plus an explicit
assertion that the placeholder never appears in a seed. Note the *shape* of the
test mattered: "user-data contains the key" passed happily, because both sides
rendered as `[ENCRYPTED]`; only "rotating the key changes the document" caught
it. `user_data` now also rejects an empty key outright.

**Verification on a real guest** (`real_cloud_image_boots`): a genuine Debian 13
cloud image boots and the console shows

- `cloud-init[502]: LNVPS VM968200 ready after 5.27 seconds` — the
  `final_message` from *our* user-data, proving the seed was found, parsed and
  applied;
- `Authorized keys from /home/debian/.ssh/authorized_keys for user debian` with
  the test key's comment in cloud-init's fingerprint table, proving the
  customer's key actually landed;
- host keys generated as `root@VM968200`, proving the meta-data hostname took.

(The ISO was also mounted directly with the kernel during development —
`blkid` reports `LABEL="CIDATA" TYPE="iso9660"` and the files appear as
`user-data` / `meta-data` / `network-config` — confirming the plain-ISO9660
approach needs neither Rock Ridge nor Joliet.)

### Increment 3 — console + firewall  ✅ DONE
- [x] `libvirt/console.rs`: `connect_terminal` proxies the serial console over
      `virDomainOpenConsole` into `TerminalStream` (`rx` = from guest, `tx` = to
      guest, matching the Proxmox backend). A single blocking pump thread
      services both directions — libvirt streams are not safe to use
      concurrently from two threads — and exits when either side hangs up, so a
      closed websocket doesn't leak the thread. Opening the console on a stopped
      VM fails immediately instead of returning a terminal that never emits a
      byte.
- [x] `libvirt/nwfilter.rs`: `patch_firewall` maps `VmFirewallRule` onto a
      per-VM libvirt nwfilter (`lnvps-vm-<id>`), preserving database priority
      order and always including `no-mac-spoofing`.
- [x] **The interface now references the filter.** Defining a filter that no
      interface references enforces nothing — caught while wiring it up, and
      pinned by a unit test asserting `<filterref filter="lnvps-vm-1"/>` is in
      the domain XML. The filter is also defined *before* the domain, since
      libvirt refuses a `filterref` to a filter that does not exist.
- [x] Rules libvirt cannot express are **rejected, not silently widened**:
      ports without a protocol (which would become `<all/>`, opening every
      port), ports on ICMP, and inverted ranges. An open-ended range is closed
      explicitly rather than becoming "all ports".
- [x] Verified against real QEMU: `terminal_proxy_reads_and_writes` reads boot
      output through the production `connect_terminal` path and confirms input
      reaches the guest; `firewall_rules_are_applied_to_the_interface` confirms
      libvirt accepted the generated filter, attached it to the interface, and
      stored the expected rules.

**Testing note:** asserting on a running domain's `xml_desc(0)` checks the
*live* definition, which still reports what the domain booted with. Config
changes have to be asserted against `VIR_DOMAIN_XML_INACTIVE` — an early version
of `configure_vm_updates_running_domain` failed for this reason while the code
was correct.

### Increment 4 — operational polish  ✅ DONE
- [x] `list_host_vms`: enumerates domains with CPU/memory from the domain info,
      and disk size + pool resolved by looking the disk path back up through the
      storage API. MAC comes from a new field on the live-XML parser.
      **Note:** this reports *every* domain on the host. That is correct for an
      LNVPS-owned hypervisor, but `lnvps_node` must never expose it — an
      operator's own VMs are not ours to enumerate. Recorded in
      `work/marketplace.md`.
- [x] Live disk resize — see the bug below.
- [x] Live CPU/memory in `configure_vm`: the persistent definition is always
      updated (so a restart is guaranteed to apply it), then `set_memory_flags`
      / `set_vcpus_flags` are attempted `LIVE|CONFIG`. Growing past the values
      the domain booted with needs a restart; libvirt says so and that is
      **logged, not swallowed and not treated as failure** — the config really
      did persist. Memory is converted bytes → KiB (libvirt's memory APIs are
      KiB, the same trap as the domain XML).
- [ ] `migrate_vm` between libvirt hosts — **deliberately not implemented.**
      It needs a second hypervisor to test, and local-disk migration requires
      `VIR_MIGRATE_NON_SHARED_DISK` plus a pre-created destination volume.
      Shipping an untested code path that moves customer data is exactly the
      risk this work has been eliminating; it stays an explicit "not supported"
      error until there is a two-host test rig. (Also still an open product
      question — see `work/marketplace.md` decision 9.)

**Two more bugs the real hypervisor caught:**

8. **nwfilters are not replaced by name.** Re-defining a filter fails with
   `filter 'lnvps-vm-N' already exists with uuid ...`, so `configure_vm` broke
   for any VM that already had one. (The increment-3 test passed only because
   its filter was always fresh.) Fixed by looking up the existing filter and
   carrying its UUID into the generated XML. Undefining first was rejected as a
   fix: it would leave a running VM briefly unfiltered.
9. **A running domain cannot have its volume resized.** `virStorageVolResize`
   shells out to `qemu-img resize`, which fails with `Failed to get "write"
   lock` because QEMU holds the image open. `resize_disk` now picks the path by
   state: `virDomainBlockResize` while running (QEMU grows its own disk, and the
   guest sees it immediately), the storage API while stopped.

## Running the real-hypervisor tests

```sh
sudo apt-get install libvirt-daemon-system qemu-system-x86 ovmf libvirt-dev
sudo virsh net-start default                      # provides virbr0
sudo mkdir -p /var/lib/libvirt/images/lnvps-test   # must be an AppArmor-permitted path
sudo virsh pool-define-as lnvps-test dir --target /var/lib/libvirt/images/lnvps-test
sudo virsh pool-build lnvps-test && sudo virsh pool-start lnvps-test
sudo usermod -aG libvirt,kvm "$USER"

sg libvirt -c "cargo test -p lnvps_api_common --features libvirt -- --ignored --test-threads=1"
```

Overrides: `LNVPS_LIBVIRT_URI`, `LNVPS_LIBVIRT_POOL`, `LNVPS_LIBVIRT_BRIDGE`,
`LNVPS_LIBVIRT_VLAN_AWARE`, `LNVPS_LIBVIRT_BOOT_IMAGE`, `LNVPS_LIBVIRT_BOOT_SUMS`.

`real_cloud_image_boots` downloads ~400 MB on first run (cached in the pool and
in the local image cache afterwards).

**Lesson for future work here: a domain that *runs* is not a VM that *boots*.**
Three of the seven bugs were invisible until a real guest image was booted and
its serial console read.

## Remaining before this can be merged

- [ ] **Document the new config keys** in `docs/config.md`: the `provisioner.libvirt` section
      there still shows only `qemu:`. Missing: `image-pool`, `image-cache-dir`, `secure-boot`,
      `vlan-aware-bridge`, `shutdown-timeout-secs`.
- [ ] **Function coverage** (`docs/agents-common/coverage.md` requires 100% on new/modified
      functions). Everything reachable through the libvirt *test driver* is covered by ordinary
      tests, but a set of functions can only run against a real hypervisor and is therefore only
      exercised by the `#[ignore]`d suite — which CI does not run: `console.rs` (all of it),
      `storage.rs::{upload_volume, upload_bytes, upload_stream, clone_volume}`,
      `image.rs::{download_to_cache, download, expected_checksum}`, and the `list_host_vms` /
      `write_seed` / `primary_disk_path` paths in `mod.rs`. Either accept this as a documented
      deviation, or stand up a libvirt-capable CI job and run `-- --include-ignored`.
- [ ] **Commit / PR.** Nothing is committed yet. Note `docker-compose.e2e.yaml` was already
      modified before this work started and is unrelated — keep it out of the commit.

## Notes

- **Deliberately failing loudly**: `get_time_series_data` (libvirt keeps no RRD
  history) and firewall rules libvirt cannot express both return
  `OpError::Fatal` with an explanation. This is the whole point of the rewrite —
  the previous code lied by returning success. Everything else in the
  `VmHostClient` trait is now genuinely implemented.
- `VmHostKind::LibVirt` still requires `provisioner.libvirt` config to be
  selectable, so nothing changes for existing Proxmox deployments.
- Building/testing this crate with `--features libvirt` needs `libvirt-dev`
  installed. If the linker reports undefined `vir*` symbols after installing it,
  run `cargo clean -p virt-sys` to rebuild the cached bindings.
