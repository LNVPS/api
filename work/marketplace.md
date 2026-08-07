# LNVPS Marketplace (operator-run compute nodes)

**Status:** planning
**Started:** 2026-07-05
**Last updated:** 2026-08-08 (increment 4a landed: tunnel pools, the allocator, and the node-facing tunnel endpoints)

## Goal

Let third parties run an LNVPS node daemon on their own hardware, list that capacity on the
LNVPS marketplace, and get paid in sats for VMs sold on it. All VM network traffic is
tunneled over WireGuard back to LNVPS route servers, so guests use **LNVPS IP space**
(`185.18.221.0/24` et al) behind the existing GSL→AVS scrubbing path, and the operator's
own IPs/ASN are never exposed or abused.

Done looks like: an operator installs `lnvps_node`, pairs it with a nostr key, gets approved
by an admin, and their host appears as a normal `VmHost` that the existing provisioner can
place VMs on — with automatic sat payouts, uptime accounting, and full traffic egress via WG.

## Non-goals (v1)

- Operator-supplied IP space / BYO-IP (all egress is LNVPS space).
- Operator-set pricing beyond a bounded multiplier on the LNVPS cost plan.
- Proxmox and any non-KVM hypervisor. **v1 is Linux + libvirt/QEMU/KVM only** (see
  "Hypervisor / VMM layer" — writing a VMM directly against KVM is explicitly out of scope).
- Nodes without hardware memory encryption (AMD SEV-SNP or Intel TDX) — hard requirement,
  see Trust model.
- Decentralised settlement or escrow contracts. Payouts are custodial from LNVPS.
- Nested marketplace resale (an operator node cannot itself be a marketplace client).
- GPU support on any hypervisor but libvirt/KVM, and any GPU the node has not explicitly
  enrolled into the marketplace pool.

## Findings (current codebase)

- `VmHost` / `VmHostKind {Proxmox=0, LibVirt=1, Dummy=MAX}` — `lnvps_db/src/model.rs:213,578`.
  Hosts are LNVPS-owned today: `api_token` (EncryptedString) + `ip` = control endpoint, and
  `lnvps_api` **dials into** the host. Marketplace nodes are behind NAT/untrusted → the
  control direction must invert.
- Provisioner + placement: `lnvps_api/src/provisioner/{mod.rs,vm.rs,vm_network.rs,ip_range.rs}`.
  Capacity/load factors already exist on `VmHost` (`load_cpu/memory/disk`).
- Networking: `IpRange` is region-scoped with gateway + DNS zone wiring
  (`lnvps_db/src/model.rs:991`). VLAN per host (`VmHost.vlan_id`), MTU field already present —
  needed for WG overhead.
- WireGuard is partly modelled: `TunnelRouter` trait, `WireguardConfig`, `WireguardPeer`,
  `TunnelKind`, plus Linux-SSH and Mikrotik backends — `lnvps_api/src/router/mod.rs`,
  `router/linux_ssh.rs`, `router/mikrotik.rs`. Route-server work: `work/route-server-management.md`.
  **But there was no source of truth for assignments.** `router_tunnel` is a *discovery cache*
  of what was last observed on a router (keyed by `router_id, name`, with `last_seen` and no
  key material); nothing recorded that a peer key and inner address belong to a given node or
  customer. Increment 1 adds a `tunnel` table for the desired state — deliberately generic, so
  it also carries plain WireGuard VPNs sold to users and infrastructure/BGP tunnels, rather
  than bolting WireGuard columns onto each consumer.
- Daemon precedent: `lnvps_fw` (separate workspace, eBPF/XDP, bearer-token HTTPS API,
  `.deb` via `lnvps_fw-deb.yml`, self-upgrade against `vX.Y.Z` GitHub releases) —
  `docs/agents/fw-api.md`. Reuse the packaging + self-upgrade design wholesale.
- Nostr identity/auth already available: `lnvps_agent/src/{identity.rs,nip98.rs}`,
  `lnvps_nostr` crate. NIP-98 is the natural node↔API auth.
- Money: `payments-rs`, `lnvps_api/src/payments/*`, `refund.rs`, `fee_estimate.rs`,
  referral payouts in `lnvps_api/src/referral/mod.rs` + `worker.rs` — closest existing
  analogue for *outbound* revenue share; extend rather than reinvent.
- Rev-share precedent to copy exactly: `Referral.referral_rate: Option<f32>`
  (`lnvps_db/src/model.rs:1459,1479`) falling back to the `company.referral_rate` default
  (`model.rs:1786`), a `ReferralPayout` ledger (`model.rs:1503`) and a `ReferralCostUsage`
  accrual view (`model.rs:1608`).
- Consumer auth already covers both required paths: NIP-98 nostr auth and a stateless session
  JWT (`lnvps_api/src/api/oauth.rs`, `issue_session_token`), revocable by bumping
  `User.session_version` (`lnvps_db/src/model.rs:69`).
- Health/SLA probing exists standalone: `lnvps_health` (MSS/DNS/PMTU, Prometheus, SMTP alerts).

## Architecture

### Components

| Component | New? | Role |
|---|---|---|
| `lnvps_node` (new workspace crate, deb-packaged) | new | Daemon on operator hardware. libvirt control, WG tunnel, telemetry, self-upgrade. |
| `lnvps_api` marketplace module | new module | Node registry, pairing, capacity intake, job dispatch, payouts, SLA. |
| `lnvps_api_admin` marketplace endpoints | new | Approve/suspend nodes, set trust tier, force-drain, view payouts. |
| Route server (existing WG concentrator) | extend | Terminates operator WG tunnels, hands out LNVPS IPs, applies firewall/scrubbing. |
| `lnvps_db` schema | extend | `marketplace_node`, `marketplace_operator`, `marketplace_payout`, `marketplace_uptime`, `vm_host.node_id`. |

### Control plane (inverted vs. existing hosts)

Node is a **client**, never a server:

1. Node holds credentials at `/etc/lnvps_node/identity`: the operator's nostr key (a dedicated
   key linked to the account is recommended) **or** a long-lived session token pasted in at
   install time.
2. Node opens an outbound WSS to `lnvps_api` `/api/v1/node/socket`, authenticating **as a normal
   consumer-API client** — NIP-98 (`lnvps_agent/src/nip98.rs`) or `Authorization: Bearer <jwt>`,
   the same `Nip98Auth`/JWT path as every other user endpoint. No bespoke node credential type;
   revocation is the existing `session_version` bump. No inbound ports, NAT-friendly.
3. `lnvps_api` sends **jobs** over that socket (create/start/stop/delete VM, resize, snapshot,
   reinstall); node replies with job results + periodic `telemetry` frames.
4. A `VmHostKind::MarketplaceNode` backend implements the existing host trait by enqueuing jobs
   on the socket and awaiting the correlated reply — so the provisioner is unchanged.
5. Node has **no DB and no authority**: LNVPS is the source of truth; node reconciles its local
   libvirt state against the desired state pushed each tick (same model as `lnvps_fw` rules).

### Data plane (all traffic over WireGuard)

```
guest VM ─ tap ─ br-lnvps (no operator uplink) ─ wgln0 ─┐
                                                       │  WG (UDP)
                         operator NAT / any ISP        │
                                                       ▼
                              LNVPS route server ── GSL → AVS → internet
                                    (owns 185.18.221.0/24)
```

- Node bridge has **no route to the operator's LAN or uplink**; default route for the guest
  bridge is inside the WG tunnel. Guest cannot reach RFC1918 on the operator's network
  (explicit drop rules) and cannot source-spoof (`wg` `AllowedIPs` + rp_filter).
- Each node gets a WG peer on a route server; LNVPS assigns the tunnel /31 (or /127) and routes
  the guests' public IPs to it. IPs still come from `IpRange` in the node's region — no code
  change to IPAM, only a new "delivery method".
- MTU: WG overhead → guest MTU 1420 (v4) / advertised via DHCP + RA. `VmHost.mtu` already exists;
  set it per marketplace host and verify with `lnvps_health` PMTU/MSS checks.
- Abuse handling is unchanged and stays LNVPS-side: the guest IP is LNVPS's, so existing
  `lnvps_fw` / AVS mitigation, null-routing and abuse workflows apply as-is.
- Failure mode: WG down ⇒ guest is offline but safe (fail-closed, never fall back to operator
  uplink). Node marks itself `degraded`; SLA clock starts.

### Hypervisor / VMM layer

"Do we need libvirt, or can we talk to KVM directly?" — these are different questions, because
libvirt is **not** in the guest's TCB. The stack is `KVM (kernel) ← VMM (QEMU) ← libvirt
(management daemon)`. Dropping libvirt only removes a control-plane convenience; dropping QEMU is
what would shrink the TCB, and "talking to KVM directly" means *writing your own VMM*.

⚠️ **The existing libvirt backend is a stub — there is no incumbent to reuse.**
`lnvps_api_common/src/host/libvirt.rs` implements only `get_info`, `generate_mac` and domain-XML
generation. `create_vm` ends in `op_fatal!("Not implemented")`; `delete_vm`,
`unlink_primary_disk`, `import_template_disk`, `resize_disk`, `configure_vm`,
`get_time_series_data` and `connect_terminal` are `todo!()` (panic — caught by
`CatchPanicLayer`, returned as a 500); `start_vm`/`stop_vm`/`reset_vm` **silently return `Ok(())`
without doing anything**, and `get_vm_state`/`get_all_vm_states` return hardcoded empty/stopped
values. So the VMM choice is effectively **greenfield**, and "it's already implemented" is *not*
a valid argument for libvirt. The only genuinely reusable asset is the `VmHostClient` trait
shape itself, which is VMM-agnostic.

| Option | Rust surface | Verdict |
|---|---|---|
| **libvirt** | `virt` crate (libvirt-rust C bindings, currently a **git dependency**, blocking C API → needs `spawn_blocking`) | **v1 (recommended, narrowly).** Not because it exists, but for arbitrary guest OS support, mature SEV-SNP, storage pools/snapshots for free, and `virsh` debuggability on someone else's hardware. |
| **QEMU direct via QMP** (no libvirtd) | `qapi`/`qmp` crates | Possible, but re-implements domain XML, storage, lifecycle and console for no CC benefit. Only worth it if libvirt itself becomes the blocker. |
| **Cloud Hypervisor** | Rust-native VMM; HTTP API over a unix socket (async-friendly) or embed as a library | **Now a real v1 contender.** v52.0 (2026) added KVM SEV-SNP with `guest_memfd` private memory, IGVM firmware and measured-boot parity with QEMU. Smaller TCB, reproducible measurement, no C bindings. Costs: UEFI-only boot, no storage/image management (you build it), narrower device set, and KVM SEV-SNP support is only months old. |
| **Firecracker** | Rust-native | **No.** No SEV-SNP (open since 2019), no PCI/UEFI, microVM-only — wrong shape for general VPS. |
| **rust-vmm crates** (`kvm-ioctls`, `kvm-bindings`, `vm-memory`, `linux-loader`, `virtio-*`) | Direct KVM ioctls | **No.** This is building a VMM: virtio-blk/net/console, UEFI/ACPI, boot protocols, snapshots, migration, *plus* the SEV-SNP launch sequence. Years of work to reach what CH already ships. |

**Decision (locked): libvirt/QEMU for v1.** Chosen on merit, not sunk cost — guest-OS breadth
(customers bring arbitrary images incl. Windows/BSD, which CH's UEFI-only path complicates) and
the maturity of QEMU's SEV-SNP flow outweigh the downsides. Accepted costs, to be managed
explicitly: a C-binding git dependency shipped to every operator node (pin the revision, vendor
if needed), a large management daemon, and a QEMU+OVMF launch measurement that churns with
distro updates — which pushes open decision 7 toward pinning platform+signer rather than exact
guest measurements.

Either way the node's VM control goes behind a `VmBackend` trait from day one, so the job
protocol and provisioner are insulated from the choice and a `CloudHypervisor` backend can land
later (or first).

**Sizing consequence:** because the backend is a stub, "implement the executor" is a full host
backend build — image download + checksum verification, storage-pool/qcow2 provisioning,
lifecycle, state polling, timeseries, console proxying — not a thin wrapper. It is split across
two increments below.

**Cleanup debt:** the current stubs are a latent production hazard independent of marketplace
work — a configured `LibVirt` host would silently no-op `start_vm`/`stop_vm` and panic on
delete/resize. **Decision: disable the backend now** (increment 0), and build the real
implementation in increments 6a/6b.

**Caveat on TDX:** libvirt `<launchSecurity type='tdx'/>` only landed recently (2025–2026 patch
series) and availability is distro/kernel dependent. SEV-SNP is the safe v1 target; treat TDX as
best-effort and gate node eligibility on what the node actually reports.

**Attestation is VMM-independent** — the verification crates work either way:
`sev` (virtee, SEV-SNP report + cert-chain verification) and `dcap-qvl` (pure-Rust Intel
SGX/TDX quote verification, fetches collateral from a PCCS).

### Trust model

Operator hardware is **untrusted and assumed hostile**. Customer confidentiality is enforced
cryptographically, not contractually — **disk encryption and memory encryption are hard
requirements**, so an operator with physical access and root on the host still cannot read a
guest's data.

**Memory encryption (mandatory).** A node is only eligible if the CPU supports AMD SEV-SNP or
Intel TDX, and libvirt launches every marketplace guest with the corresponding launch-security
domain config. Guest RAM is encrypted with a key held in the CPU/PSP, not accessible to the
hypervisor. Node telemetry reports CPU model, firmware version and SEV/TDX capability; the API
**verifies an attestation report** (SEV-SNP `ATTESTATION_REPORT` / TDX quote) against AMD/Intel
root certs plus a measurement allow-list before the node is marked eligible. No valid
attestation ⇒ no placement, no payout.

**Disk encryption (mandatory).** Every guest volume is LUKS2-encrypted. The key is **never**
stored on the node in cleartext:

- LNVPS runs a key-broker endpoint on the consumer API. At guest boot, the guest's early-boot
  stage produces a fresh attestation report and exchanges it for the LUKS key over a channel
  terminated *inside* the confidential guest (via the WG tunnel).
- The key is released only if the attestation is valid and the measurement matches the expected
  image — so a modified/cloned guest, or a disk copied off the node, is undecryptable.
- The node daemon never sees the key; a stolen disk image is inert.

**Blast radius.** No LNVPS secrets on the node beyond its own credential and WG private key. The
node cannot read other nodes' data, mint invoices, or allocate IPs.

**The operator's privacy is protected too — the trust boundary runs both ways.** The machine is
theirs and may run their own unrelated VMs, so `lnvps_node` must **not** expose host-wide
enumeration. Concretely: the libvirt backend's `list_host_vms` (which reports *every* domain on
the hypervisor, for importing untracked VMs) is legitimate on an LNVPS-owned host but must not be
reachable through the node's job protocol. The node answers only for domains whose names map to
an LNVPS VM id — which is how `get_all_vm_states` already behaves, and is pinned by the
`get_all_vm_states_ignores_foreign_domains` test. Same rule for storage: report capacity, not a
listing of the operator's volumes.

**Trust tiers** still gate *placement policy* (persistent vs. ephemeral workloads, capacity caps,
staged upgrade rings), but they are no longer the confidentiality control: `Untrusted` →
`Verified` (identity-checked operator) → `Partner`. Attestation state is surfaced to customers
as a badge on the offer.

### GPU capacity (passthrough and vGPU)

Marketplace nodes should be able to sell GPU-backed VMs, not just CPU. This is where the
operator's hardware is most differentiated (and most expensive), so it is a large part of why
an operator would join. It also collides with the locked decision on memory encryption in a
way that has to be resolved deliberately rather than discovered later.

**What already exists:** `lnvps_host_util/src/gpu.rs` detects the *first* GPU via NVML/AMD
sysfs and reports **video-encode features** (NVENC/NVDEC), feeding `GpuMfg` and the host
feature list. That is a capability probe, not an inventory: there is no per-device record, no
PCI address, no IOMMU group, no VRAM figure, and nothing that allocates a GPU to a VM. All of
that is new work.

#### The confidentiality problem

The plan's whole trust model is that the operator is hostile and cannot read guest memory
(decision 4). A GPU breaks that assumption unless specific hardware is used, because the
device DMAs into guest memory:

- **SEV-SNP/TDX + ordinary passthrough:** guest memory is encrypted, but device DMA cannot
  target encrypted pages. The guest marks buffers **shared** and traffic crosses via SWIOTLB
  bounce buffers, which are plaintext to the host. Everything moving between CPU and GPU —
  model weights, frames, inputs — is visible to the operator, as is everything resident in
  VRAM, which is outside the CPU's encryption domain entirely. **Memory encryption without
  trusted I/O does not protect a GPU workload.**
- **NVIDIA Confidential Computing mode (Hopper/Blackwell — H100/H200/B200):** the GPU has its
  own root of trust, the CPU↔GPU link is encrypted, VRAM is protected from the host, and the
  GPU emits **its own attestation report** which must be verified *alongside* the CPU's.
  Needs a specific stack (recent OVMF, QEMU ≥ 9.2 — 9.1 has a VFIO/SEV-SNP regression —
  kernel ≥ 6.11, guest driver 580.x+). This is the only configuration where a GPU VM keeps
  the promise the rest of the plan makes.
- **SEV-TIO / TDX Connect / PCIe TDISP:** removes the bounce-buffer tax and extends the TEE
  over the link properly. Early/RFC status. **Not a v1 foundation**; revisit later.

Consequence: **"GPU" and "confidential" are the same decision.** Either GPUs are restricted to
CC-capable datacenter parts, or GPU VMs are a product tier that explicitly does *not* carry
the confidentiality guarantee — which must be stated to the customer at order time, never
silently degraded. See open decision 10.

#### The three virtualisation paths

There is no single GPU virtualisation stack: consumer and datacenter cards differ, NVIDIA and
AMD differ, and NVIDIA's own stack has several overlapping paths. A marketplace taking
whatever hardware operators own will have to implement and maintain all three. (Field report
from CloudRift, who run exactly this in production:
<https://kernelspace.substack.com/p/gpu-virtualization-with-vfio-nvai>.)

| Path | Hardware | Fractional? | Licence | Notes |
|---|---|---|---|---|
| **VFIO passthrough** | Any GPU, any vendor | No — whole card | None | Simplest and cheapest. What consumer rigs (RTX 4090/5090/PRO 6000) and whole-card datacenter rentals use. |
| **NVIDIA MIG + AI Enterprise vGPU** | A100/H100/H200/B200 | Yes, hardware-partitioned | **~$4,500 per GPU per year** | ~$36k/yr for an 8-GPU server; roughly +50% TCO over a 4-year life. **Ruled out — see decision 9.** |
| **AMD SR-IOV (GIM)** | Instinct MI300X/MI350X | Yes, natively (SPX/DPX/QPX/CPX) | **None** | Plain PCIe SR-IOV; VFs are ordinary PCI devices, `managed="yes"`, no vendor CLI. Reported as by far the easiest of the three. |

**The licensing asymmetry decided the design.** Fractional NVIDIA costs ~$4.5k/GPU/yr;
fractional AMD costs nothing. In a marketplace the hardware belongs to the *operator*, so that
licence would be a per-GPU annual toll on joining — which is not a viable onboarding story.
Decision 9 therefore rules NVIDIA vGPU out: **NVIDIA is whole-card passthrough only, and
fractional capacity comes from AMD.**

**A side benefit of dropping MIG: the scheduler stays simple.** MIG profiles must tile across
the GPU's GPC slices without overlap, and only specific combinations are valid per model (an
H100 80GB has 7 GPCs and 19 valid placement configurations), so scheduling it would have been
constrained bin-packing against a per-model placement table rather than "seven slots free".
AMD's partition mode is set once at driver/firmware level, so free capacity is a plain count
of unused VFs — at the cost of granularity (no mixed partition sizes on one card).

#### Domain XML and host prerequisites

The libvirt backend already emits `q35` and `host-passthrough`, and already pins the
non-secure-boot OVMF build — all prerequisites. What GPU support adds:

- `<pcihole64 unit="G">…</pcihole64>` on `pcie-root`, **computed from actual BAR sizes**.
  H100/B200 BARs can exceed 128 GB and QEMU's built-in estimate is not always enough; getting
  it wrong gives `BAR X: can't assign mem` inside the guest.
- `<rom bar="off"/>` on every passthrough device — newer GPU firmware makes OVMF hang or crawl
  when it tries to load the option ROM, and cloud VMs use serial/VNC anyway.
- PCIe topology: **flat** (all GPUs on bus 0, differing slots) for consumer cards, which also
  need `multifunction="on"` to carry the companion HDA audio function at `0x1`; **deep** (one
  `pcie-root-port` per GPU) for datacenter cards, which have no audio function and are more
  reliable behind dedicated ports.
- `managed="no"` plus an explicit `<driver name="vfio"/>` for NVIDIA, because the teardown
  sequence needs more control than libvirt's managed mode; `managed="yes"` for AMD VFs.
- Version floors: QEMU ≥ 9.2 (9.0 for GPUs generally, but 9.1 has a VFIO/SEV-SNP regression),
  OVMF 2024.02+, libvirt 10.6+, and a 6.11+ kernel. Node eligibility must check these, not
  assume them.

#### The NVIDIA driver lifecycle is the operational hazard

Claiming an NVIDIA GPU for VFIO is a stateful, host-wide, failure-prone sequence: stop
whatever holds the device (DCGM exporter, `nvidia-persistenced`, stray `nvidia-smi`), unload
`nvidia-uvm`/`nvidia-drm`/`nvidia-modeset`/`nvidia`, unbind the GPU and its audio function,
bind to `vfio-pci`, wait for `/dev/vfio` nodes. Returning it reverses all of that and then
needs a CUDA init to "warm up" the device, or containers report *no CUDA-capable device*.

**This is dangerous on hardware we do not own.** The trust model says the operator's own
workloads are private and coexist with ours — but unloading the NVIDIA kernel modules is
host-wide and would kill the operator's own inference jobs. Two hard rules for the node
daemon:

1. **Never touch a GPU that is not explicitly enrolled** in the marketplace pool, and never
   perform host-wide module unloads on a node whose other GPUs are in use. Mixed
   host-use + passthrough is only supported on the **open-source** NVIDIA driver; NVIDIA AI
   Enterprise does not support that mixed mode.
2. **Enrolment is an operator decision, per device**, made once at setup — not something the
   scheduler infers from what it can see.

#### What is actually sellable (consequence of decisions 8 and 9)

Ruling out NVIDIA vGPU licensing and requiring CC hardware for confidentiality leaves two of
four cells filled:

| | **Whole card** | **Fractional** |
|---|---|---|
| **Confidential** | ✅ NVIDIA CC mode (H100/H200/B200), passthrough — no vGPU licence needed | ❌ empty in v1: fractional is AMD-only, and AMD has no confidential-computing story |
| **Non-confidential** | ✅ any card, any vendor — consumer RTX included | ✅ AMD Instinct SR-IOV partitions (MI300X/MI350X) |

Two things follow, and both are product facts rather than implementation details:

- **The cheapest GPU offers will be AMD and non-confidential.** Small, affordable slices come
  only from AMD partitioning, which cannot carry the confidential badge.
- **Confidential GPU capacity is whole-card and therefore expensive.** There is no small
  confidential GPU offer in v1, and pretending otherwise by slicing a CC card is not
  available — the licensing path that would allow it is ruled out.

If a small *confidential* GPU offer turns out to be the thing customers want, the options are
BYO-licence operators, or waiting for SEV-TIO/TDISP to make non-CC hardware viable. Neither is
v1.

#### Multi-tenancy hazards specific to GPUs

- **VRAM residue between tenants.** Frame-buffer memory is not reliably zeroed when a device
  is reassigned. NVIDIA's vGPU stack scrubs via copy engines on device open/close; raw
  passthrough depends on reset behaviour, which varies by card and firmware. A GPU handed
  from one customer to the next without a verified scrub leaks the previous tenant's data.
  **Requirement: an explicit scrub-and-verify step between allocations, and a card is not
  returned to the pool until it passes.**
- **Reset reliability.** Not every GPU survives FLR/bus reset cleanly; some need a host
  reboot. A card that fails reset must be cordoned, not silently reissued.
- **A GPU VM is pinned to its node.** The device is local and cannot be tunnelled, so drain,
  migration and offboarding (increments 7 and 10) cannot relocate it. GPU VMs need their own
  drain policy: expire-and-refund rather than move.
- **Power, heat and abuse.** GPUs draw far more power than the rest of the plan assumes, on
  hardware LNVPS does not own, and are the obvious target for mining abuse. Per-node power
  and thermal telemetry, and a mining stance in the operator ToS.
- **Attestation gains a second half.** Node eligibility must verify the GPU's attestation
  report as well as the CPU's, and bind them: a valid CPU report plus an unattested GPU is
  not a confidential VM.

#### What this adds to the increments

- **Increment 1 (done):** no GPU columns were added, correctly — GPU inventory is per-device
  and belongs with the code that allocates it.
- **Increment 2 (node daemon):** telemetry must enumerate *every* GPU — PCI address, IOMMU
  group, model, VRAM, driver, CC capability, vGPU/MIG capability — not just probe the first
  card for video features. Extend `lnvps_host_util`'s detection into a real inventory.
- **Increment 5 (attestation):** verify and bind the GPU attestation report alongside the
  CPU's; refuse CC placement when the GPU cannot attest.
- **Increment 7 (placement):** a GPU is a **countable, non-oversubscribable** resource, unlike
  CPU and memory which use load factors. Templates need GPU requirements (count, model class,
  minimum VRAM, CC required yes/no) and placement needs exact matching plus exclusive
  allocation with no overcommit.
- **Increment 11 (new, below):** the GPU work itself.

### Economics

- LNVPS keeps pricing/billing. Operator earns a **revenue share** of the invoice value of VMs
  running on their node, prorated per hour of *healthy* uptime.
- **Rate resolution mirrors referrals exactly**: `marketplace_operator.rate: Option<f32>`
  (per-account override, admin-settable) falling back to a new `company.marketplace_rate`
  default. Same nullable-override + company-default pattern as
  `Referral.referral_rate` → `company.referral_rate`, so admin UI, reporting and
  reconciliation all follow known shapes.
- Payout rail: Lightning to an operator-registered address (NWC / LNURL-pay / BOLT12), reusing
  the referral payout worker pattern (`lnvps_api/src/referral/mod.rs`, `worker.rs`) and the
  `ReferralPayout` ledger shape.
- Payouts accrue daily, settle on a schedule with a minimum threshold; held (not slashed) while
  a node is in SLA breach, released once resolved. Forfeited after a defined breach window.
- SLA accounting from two sources: node heartbeat + independent probes (`lnvps_health`) so an
  operator cannot fake availability by lying in telemetry.

## Decisions

**Locked:**

1. **Hypervisor** — libvirt/KVM only in v1.
2. **VMM** — libvirt/QEMU/KVM (decided on merit; the backend was greenfield). Node VM control
   goes behind a `VmBackend` trait to keep Cloud Hypervisor viable later.
3. **Node auth** — normal consumer-API auth: operator's nostr key (NIP-98) or a long-lived
   session token. No separate node credential system.
4. **Revenue share** — per-account rate with company-wide default, identical mechanism to
   referrals (`Option<f32>` override → `company.*_rate`).
5. **Payout rail** — shared with referrals. `marketplace_operator` mirrors `referral` column
   for column (`address` + `mode` + `payout_threshold`), and the payout-mode enum is one
   shared `PayoutMode` type (`ReferralPayoutMode` remains an alias). Operators get Lightning
   address, NWC and on-chain, and both ledgers reconcile the same way.
6. **Operator KYC** — none in v1. Operators are not identity-checked; confidentiality is
   enforced by attestation and guest encryption, not by knowing who the operator is. The
   `marketplace_operator` table deliberately carries no identity columns, so there is no store
   of documents to protect. Trust tiers still gate placement policy, and a future tier can add
   checks without changing what v1 stores.
7. **Encryption** — disk encryption *and* memory encryption (SEV-SNP/TDX) are mandatory
   eligibility requirements, with remote attestation gating both placement and LUKS key
   release. **One deliberate exception: GPU VMs, per decision 8.**
8. **GPU offers are two-tiered.** A GPU cannot keep the confidentiality promise on ordinary
   hardware: device DMA crosses plaintext bounce buffers and VRAM sits outside the CPU's
   encryption domain. So there are two distinct products:
   - **Confidential GPU VM** — CC-capable parts only (H100/H200/B200-class, NVIDIA CC mode),
     with CPU *and* GPU attestation verified and bound together.
   - **GPU VM (non-confidential)** — any card, including consumer RTX. The customer is told at
     order time, in plain words, that the node operator can read GPU memory and CPU↔GPU
     traffic. An explicit, visible product choice: **never a silent downgrade**, and never
     shown with the same badge as a confidential VM.
   This opens the marketplace to the large pool of consumer-GPU operators without quietly
   weakening the guarantee made everywhere else.
9. **Fractional GPUs are in scope for v1, but only on AMD.** Sharing is what makes GPU
   capacity sellable in small units, and AMD SR-IOV provides it with no licence, standard
   PCIe semantics and driver-level partition modes. **NVIDIA AI Enterprise licensing
   (~$4,500/GPU/yr) is ruled out**, and without it there is no supported path to hand a
   MIG/vGPU instance to a VM — the guest needs the NVAI driver and a `nvidia-gridd` licence
   checkout. So:
   - **NVIDIA → whole-card VFIO passthrough only.** No licence required, and it is the mode
     the confidential tier needs anyway.
   - **AMD → whole-card or fractional** (SPX/DPX/QPX/CPX) via SR-IOV.
   Revisit only if NVIDIA's licensing changes, or later as a bring-your-own-licence option
   for operators who already hold NVAI.
10. **Stubbed libvirt backend** — superseded: the backend was fully implemented instead
   (`work/libvirt-backend.md`, merged), so nothing needs disabling.
11. **Control plane: LNVPS dials the node over the tunnel, using HTTP.** Commands are
   request/response with a result to report (start a VM, stop a VM), which is what HTTP
   already is; a persistent websocket would mean rebuilding correlation ids, in-flight replay
   and reconnect semantics to arrive back at the same thing. The usual reason to prefer an
   outbound socket — NAT traversal — does not apply, because the WireGuard tunnel gives
   direct reachability and a node without a working tunnel cannot serve guests anyway. This
   also matches `lnvps_fw`, so there is one daemon operational model rather than two.
   Outbound calls remain for the two things that precede or outlive the tunnel: registration
   and heartbeat.
12. **Control auth is NIP-98 against a pubkey compiled into the node binary** — not a bearer
   token. A shared token must be generated, delivered, stored on the operator's disk, rotated
   and revoked: five chances to leak a secret that grants control of every guest on the
   machine. A public key is not a secret, so none of those steps exist, and forging a command
   needs LNVPS's private key. Verification binds URL, method, body hash and timestamp, and
   keeps a replay cache — replaying a captured stop is a second outage.
   Consequences: the release workflow **must** inject `LNVPS_CONTROL_PUBKEY` at build time;
   a binary built without it refuses to serve the control API rather than serving it to
   everyone. Self-hosted deployments rebuild with their own key.
15. **A node authenticates with a node-scoped token, not a nostr key, and registration is
   signed by the operator's account.** Registration returns a token (shown once) carrying the
   node's id and its own `token_version`; the node presents it as a Bearer credential.
   Consequences that had to be built rather than assumed:
   - **Revocation is per node.** Bumping `marketplace_node.token_version` invalidates that
     node's tokens and nothing else. Reusing the operator's `users.session_version` would turn
     "one node was compromised" into "the operator is locked out of everything".
   - **Node tokens and user sessions are the same HS256 construction over the same secret**,
     so they are separated by an explicit `typ` claim, checked in both directions. Without it
     the only thing keeping them apart is which fields serde happens to require — an accident,
     not a decision, and one that disappears the day someone gives those fields defaults.
   - **Expiry is not the revocation mechanism.** Node tokens are long-lived on purpose:
     expiry buys little against an attacker who has the token now, while a short lifetime
     guarantees an eventual fleet-wide outage on unattended hardware.
   - **`nostr_pubkey` was dropped from `marketplace_node`**, since nothing would set it.
   - **Registration refuses when no session secret is configured**, rather than registering a
     node whose token could never be issued.
14. **Control calls run over HTTPS with a certificate pinned at registration.** NIP-98
   authenticates requests *to* the node, but nothing authenticated the node's *replies*:
   anything able to answer on the tunnel address — a guest on the same machine that grabbed
   the IP, a route-server misconfiguration — could report that a VM started when it did not.
   The node self-signs, LNVPS records the SHA-256 fingerprint at registration, and every
   later call checks the presented certificate against that pin. No CA is involved: a public
   CA would add a third party able to issue for a name we already control out-of-band.
   Consequences: the identity is **persisted**, because a certificate minted on each restart
   would break the pin and make the node unreachable; a corrupt certificate is a hard failure
   rather than a silent regeneration, for the same reason; and registration (increment 3)
   must carry the fingerprint, with a re-registration path for rotation. Note the node does
   not currently verify that a persisted certificate still covers its tunnel address as a SAN:
   under a fingerprint-pinning verifier that does not matter, but it is a loose end for the
   rotation path to close.
13. **The tunnel is not by itself a trust boundary.** Guests run on the node, so a guest that
   can route to the node's tunnel address could otherwise stop its neighbours. Two independent
   defences, both required: the listener binds **only** the tunnel interface address (enforced
   at startup, not documented), and every request is authenticated per decision 12.

**Still open:**

a. **Cloud Hypervisor as a second `VmBackend`** — worth doing once measurement pinning is in
   place (smaller TCB, smaller measurement), or stay on QEMU indefinitely?
b. **Attestation strictness** — pin exact guest measurements (strongest, but every image or
   kernel update needs a re-measure and allow-list bump) vs. pin platform + signer only.
c. **Backups** — operator-local storage only, or optional LNVPS-side backup egress (costly
   over WG, and must stay encrypted end to end)?
d. **Migration** — is offline migration off a misbehaving node required in v1? Note GPU VMs
   cannot be migrated at all.

## Increments

Each increment is ≤ L (≤2500 LOC) and lands as its own PR.

### Increment 0 — Stubbed libvirt backend  ✅ SUPERSEDED
Originally "disable the stub so it cannot lie". Overtaken by events: the backend was **fully
implemented** instead — see `work/libvirt-backend.md`. Nothing is disabled, because nothing is
stubbed any more: full lifecycle, storage/image handling, cloud-init personalisation, serial
console and nwfilter firewalling, verified against a real QEMU/KVM host.

This also removes most of the work originally scheduled for increments 6a/6b — what remains
there is the node-side job protocol and the `VmBackend` trait, not the hypervisor work.

### Increment 1 — Schema + operator/node registry (S/M)  ✅ DONE
Migration `20260805120000_marketplace_node_registry.sql`:
- `marketplace_operator` (user_id, `address`/`mode`/`payout_threshold` mirroring `referral`,
  `rate` override, `enabled`, created). No KYC columns — see decision 7.
- `marketplace_node` (operator_id, name, nostr_pubkey, status, trust_tier, last_seen,
  created), unique key so it identifies exactly one node. **No region** — that lives on the
  backing `vm_host`, and a second copy would be free to drift. **No WireGuard fields** — the
  data-plane identity lives in `tunnel`.
- `tunnel`: the source of truth for what LNVPS has *assigned* — owner, peer key, inner
  addresses, route server — and nothing else. **What a tunnel is for is decided by whichever
  table links to it**: `marketplace_node.tunnel_id` today, a VPN or BGP table later. There is
  no `purpose` column, and `user_id` (NOT NULL) is ownership, not type: every allocation
  belongs to a real customer account — the operator's merchant account for a node, the
  requesting user for a BGP tunnel or VPN. `router_tunnel` remains the observed state.
- `vm_host.marketplace_node_id` NULLABLE UNIQUE FK, `company.marketplace_rate` default 0.
- `VmHostKind::MarketplaceNode = 2`, `MarketplaceNodeStatus`, `MarketplaceTrustTier`,
  `PayoutMode` (shared with referrals), `lnvps_db` CRUD, mock impl, tests.

Deliberately **not** included, to be added by the increment that first uses them:
capacity caps (increment 7), attestation state (increment 5), WG peer id (increment 4).
Unused columns are just untested assumptions.

Two guards worth remembering:
- `MarketplaceNodeStatus::accepts_placement()` is the *only* placement state check, so a
  status added later cannot become eligible by default.
- Admin host creation rejects `kind = marketplace_node`: the backing host row is created by
  node approval, which is what supplies `marketplace_node_id`. A host of that kind with no
  node would accept placements and then fail every operation.

### Increment 2 — Node daemon skeleton (`lnvps_node`)

**2a — crate, config, credentials, inventory (done):**
- `lnvps_node` workspace member with `lnvps-node inventory` / `check`.
- Credential loading (nostr key **or** session token) with owner-only file permissions
  enforced, NIP-98 signing for outbound calls, secrets kept out of `Debug` output.
- `control_auth`: NIP-98 verification of inbound commands against the pinned LNVPS key
  (decision 12) — signature, pubkey, URL, method, body hash, clock window, replay cache.
- `tls`: persisted self-signed identity whose fingerprint LNVPS pins (decision 14), verified
  against `openssl x509 -fingerprint -sha256`.
- `config`: control listener address validated against the tunnel interface (decision 13).
- Inventory (memory, kernel, os, uptime, disks, SEV-SNP/TDX/nested-virt) built on
  `lnvps_host_util`, which became a lib + bin so the daemon and the operator's
  `lnvps-host-info` pre-flight check cannot disagree about the same machine. Its feature
  flags were fixed in passing: `--no-default-features` did not compile, which is exactly the
  configuration the daemon needs (a node has neither libva nor NVML installed).

**2b — control listener (done):**
- Axum listener over HTTPS bound to the tunnel address, with `GET /api/v1/status`.
- NIP-98 authentication layered over the *whole* router rather than per route, so a route
  added later cannot forget it — proven by an unauthenticated request to a path that does not
  exist returning 401 rather than 404.
- The `u` tag is checked against the node's **own** address, never the `Host` header;
  otherwise a request captured from one node could be replayed against another by setting
  `Host` to the first node's address.
- Startup refuses, with a specific message, when: the binary has no `LNVPS_CONTROL_PUBKEY`,
  the tunnel interface has no addresses, the listen address is a wildcard, or the listen
  address belongs to some other interface. All four verified against a real machine.
- Integration tests speak real TLS to a real socket: the certificate presented on the wire is
  the one whose fingerprint is registered, a client pinned to a different certificate fails
  the handshake, plain HTTP is refused, and reaching the node over TLS still authorises
  nothing.

**2c — VM lifecycle + heartbeat (next, with increments 3 and 4):**
- start/stop/status handlers over the existing `VmBackend`.
- Outbound registration and heartbeat frames (telemetry: cpu/mem/disk/net, libvirt version,
  firmware version).
- `.deb` packaging + GitHub release workflow + self-upgrade, copied from `lnvps_fw`
  (`upgrade.rs`, `lnvps_fw-deb.yml`). Version must move in lockstep with `vX.Y.Z`, and the
  workflow must inject `LNVPS_CONTROL_PUBKEY`.
- GPU inventory lands with increment 11a's eligibility probe, so PCI address, IOMMU group
  cleanliness, BAR sizes and CC capability are collected once, against real hardware.

### Increment 3 — Pairing + admin approval flow (M)  ✅ DONE

**3a — registration (done):** `POST /api/v1/marketplace/nodes` registers hardware under the
operator's account and returns the node's token, shown once (decision 15). Enrolment as an
operator is implicit. Nodes land in `pending`. `PATCH /api/v1/marketplace/nodes/{id}` re-pins a
rotated certificate — without it a node that regenerates one is unreachable for good — and
`POST /api/v1/marketplace/nodes/{id}/token` issues a replacement token, revoking the previous.
A duplicate certificate — the signature of a cloned machine image — is reported as such rather
than as a unique-index violation. Another operator's node answers "not found" rather than
"forbidden", so ids cannot be probed. `GET /api/v1/node/self` is the node-authenticated
endpoint that proves the token works end to end.

16. **Listing a node costs a one-off, non-refundable, per-node fee, and the gate sits at
   approval.** An operator registers and is reviewed for free, then pays before an admin can
   approve — so hardware is vetted before money changes hands and rejected hardware costs its
   operator nothing. Per node, because one payment unlocking an unlimited fleet prices spam
   only once. Non-refundable, so LNVPS never custodies operator money and needs no return or
   slashing procedure. Consequences that had to be built:
   - **The fee is a `SubscriptionType::MarketplaceNodeFee`, not a new payments table.**
     `subscription_payment` is the only table the Lightning settlement listener resolves
     against, and its resume cursor is `last_paid_subscription_invoice`. A parallel table
     would have to extend both, and a paid fee that missed either would settle into a
     "not found" log line and be lost.
   - **A one-off must never acquire an expiry.** No path through `subscription_payment_paid`
     left `expires` NULL, so a paid fee would have been dunned by `check_subscriptions`.
     One-offs are now recognised from the data — no recurring amount *and* a setup fee — and
     keep `expires` NULL, which every expiry query already filters on. The rule is narrow on
     purpose: a free or fully-discounted subscription has neither, and must keep lapsing.
   - **The same UPDATE sets `is_active`/`is_setup`**, so the one-off branch sets them
     explicitly rather than leaving a paid fee looking unpaid.
   - **The company comes from a region the operator names when paying**, since a fresh node
     belongs to no region and every other product derives its company from what is bought.

**3b — admin approval (done):** approve/reject/suspend/drain, trust tier and the per-operator
rate override, with the backing `VmHost` created by approval. `AdminResource::MarketplaceNode`
(28) covers placement state and `MarketplaceOperator` (29) covers payout and revenue share, so
suspending a node and changing what someone is paid are separately grantable. What the build
settled beyond the plan:
- **Approval is the only way into `approved`.** The status endpoint refuses it, because the fee
  and certificate gates live in the approval path and a second door into the same state is a
  way past both.
- **The fee must have been paid to the company that will sell the capacity.** Regions carry the
  company, so without this check an operator could pay whichever company charges least and list
  the hardware anywhere. The per-node gate would have quietly become a per-cheapest-company one.
- **Suspend and drain disable the backing host.** Placement reads the host row, not node status
  (that arrives in increment 7), so leaving the host enabled would mean a suspended node kept
  taking VMs.
- **Re-approval reuses the existing host** rather than creating a second one, and does not
  re-charge: a node that was suspended and reinstated is one listing, not two. `region_id` is
  therefore required only on a first approval — moving a host between regions would move its IP
  space with it.
- **Capacity is not guessed.** The host is created with `cpu = 0` / `memory = 0` unless an admin
  supplies figures; real numbers arrive with telemetry, and a guess here oversells hardware
  nobody has measured. Overcommit factors default to 1.0 — untrusted hardware is a poor place to
  oversubscribe. Per-tier capacity caps remain deferred to increment 7, which is what will read
  them.
- The host is created `enabled = false` with an empty `ip`, filled in by increment 4 when the
  tunnel is allocated; a blank ip must be a hard error wherever a host is dialled.
- Reject deletes the registration (no `Rejected` state), so an operator may re-register the same
  hardware, and is refused while the node still backs a host.
- `MockDb::admin_create_region` and `admin_create_company` were stubs returning `Ok(1)`. A test
  that created a second company to check the cross-company fee rule passed against the seeded
  one instead, which is the failure mode a stub like that always has: the check appears to hold
  because the setup silently did nothing.

Three bugs the increment surfaced, none of them in new code:
- **`create_host` never wrote `marketplace_node_id`.** The column was added by increment 1, but
  the INSERT was not extended, so approval would have created a host that looked LNVPS-owned and
  was bound to no node — and `get_marketplace_node_host` would never have found it. It is
  written on insert and deliberately absent from the UPDATE: a host cannot change which machine
  backs it.
- **Enrolment created a *disabled* operator.** `MarketplaceOperator::default()` has
  `enabled = false` and the insert binds the field rather than taking the column's `DEFAULT
  TRUE`, so every operator registering hardware looked like one an admin had stopped.
- **`MockDb::update_host` wrote only `enabled`, `cpu` and `memory`**, silently discarding every
  other change; it now writes the same columns the real UPDATE does.

Loose end for increment 10 (offboarding): there is no `delete_host` anywhere in the schema
layer, so a node that has been approved can never be deleted — the guard refusing to delete a
node that still backs a host is correct, but there is currently no way to satisfy it.

**Original scope:**
- `POST /api/v1/node/register` under standard consumer auth → node bound to the calling user,
  lands in `pending`. Carries the node's TLS fingerprint (decision 14), stored on
  `marketplace_node`; plus a re-registration path for when the certificate is rotated, or a
  node that regenerates one becomes permanently unreachable. The authenticated user *is* the operator; no pairing code needed for the
  nostr/session-token path (keep a code only for headless installs).
- Operator-facing user API: list own nodes, set payout address, view earnings.
- Admin API: list/approve/reject/suspend/drain node, set trust tier, set capacity caps, set the
  per-operator rate override.
- On approval, create the backing `VmHost` row (disabled until networking is up).

### Increment 4 — WireGuard data plane (XL — split into 4a/4b/4c)

Sized as one increment it is XL: it spans a new addressing schema, an allocator, live
route-server I/O, drift reconciliation, real Linux networking on somebody else's machine, and
an end-to-end health gate. Split so each piece lands with its own tests.

**Where the addresses come from.** `router` carries no region, no endpoint, no server key and
no address block, so there was nothing to allocate *from*. A `tunnel_pool` supplies all four:
which route server terminates the peers, which region's nodes it serves, the endpoint and
server public key a node needs to dial it, and the inner blocks the /31 and /127 are carved
out of — the same shape `ip_range` has for guest addresses, and `allocate_subnet` from
`provisioner/ip_range.rs` does the carving in both cases.

**Who presents the key.** The node generates its own WireGuard keypair and asks for a data
plane after approval, presenting the public half; the private half never leaves the operator's
machine. That is why there is no WireGuard column on `marketplace_node`: the key belongs on the
`tunnel` row, which does not exist until the node asks, and `uk_tunnel_peer_pubkey` then makes
it unique fleet-wide for free.

#### 4a — Addressing + allocation (L)  ✅ DONE

What the build settled beyond the plan:
- **A pool configures its own interface.** The first cut recorded a public key an admin had
  pasted in, which described an interface somebody had already built by hand: it could never
  create one, could not rebuild it after a reinstall, and made standing up a route server a
  manual job with a database row bolted on afterwards. LNVPS now generates the keypair, stores
  the private key encrypted (`EncryptedString`, like every other credential in the schema) and
  pushes the interface to the route server over the existing `TunnelRouter`. An existing
  interface can still be adopted by handing over its private key; the public half is always
  **derived**, never accepted, so a pool cannot be stored holding a pair that disagrees with
  itself — and the sync refuses to configure one that does.
- **The interface name is derived, not stored.** `wgln<id>`, from the pool's own id. The route
  server is not LNVPS-exclusive — it carries interfaces nobody here configured — so a fixed
  prefix keeps a managed interface from being confused with, or clobbering, one of those; ids
  are unique, so two pools cannot be named the same thing; and a stored name could be edited to
  point at an interface the pool does not own, which the next sync would rewrite. There is no
  `interface` column and no way to set one.
- **The listening socket is stated in full and pinned per pool.** A route server carries several
  interfaces, and a WireGuard interface listens on *every* local address at its port — so the
  port, not the address, is what two interfaces collide over. `uk_tunnel_pool_router_port`
  enforces it, verified against a real MariaDB. `endpoint` is derived from `listen_addr` +
  `listen_port` (IPv6 bracketed) rather than stored, so what a peer is told to dial cannot
  disagree with what was configured.
- **Sync is a push that leaves working interfaces alone.** Re-applying recreates the interface
  on the Linux backend and takes every peer with it, so it only happens when the key or port has
  actually drifted; a pool that merely changed name is not a reason to cut live nodes. Enable
  and disable go through `set_tunnel_enabled` instead.
- **Deleting a pool tears the interface down**, addressed by router and interface because the
  row it came from is already gone by then. A queue that is down still deletes the row and logs
  loudly that an interface was left behind — a pool nobody can delete while Redis is down would
  be worse.
- **The composite foreign key works and is worth having.** `tunnel (pool_id, router_id)` →
  `tunnel_pool (id, router_id)` is enforced by MariaDB, verified against a real server: a tunnel
  claiming a pool on another router is rejected by the database, and a NULL `pool_id` skips the
  constraint, which is exactly the pool-less case. The mock mirrors it.
- **A node takes one address, not a link** (revised during 4b; 4a shipped /31s and /127s).
  WireGuard is layer 3 and point-to-point, with no ARP and no on-link requirement, so the node
  needs no gateway of its own — `ip route add default dev wgln0` is enough. A /31 therefore spent
  two addresses describing something that needs one, and worse, forced the route server to hold
  one address per node on a single interface: a /16 pool with a thousand nodes meant a thousand
  addresses on `wgln<id>`, re-parsed out of `ip addr show` on every reconcile. The route server
  now holds **one** address per pool, carrying the block's own prefix so every node in it is
  on-link. The block's network address, that address, and (on IPv4) the broadcast address are
  reserved, so a /24 places 253 nodes.
- **A dual-stack pool's capacity is the smaller block's**, because a link of each family is
  handed out together. Reporting the roomier one would promise capacity that cannot be
  allocated.
- **Pools are tried in order and the first with room wins**, rather than balancing across them.
  A second pool in a region exists because the first filled up or is being migrated away from;
  spreading nodes over both would leave neither drainable.
- **A block cannot be shrunk or removed under a live allocation.** Otherwise the tunnel sits
  outside its own pool and the allocator hands its addresses to somebody else.
- **A pool cannot be moved between route servers.** Every tunnel carved from it would point at
  an interface that is not there, so there is no `router_id` in the update request at all.
- Allocation fills the host's blank `ip` with the node's inner address and leaves the host
  disabled — 4b realises the peer, 4c brings the link up and enables it.

Known gap, matching increment 3a: the two node-facing axum handlers are thin wrappers with no
test, because `lnvps_api`'s `RouterState` has no test harness. Their bodies are covered through
the allocator; the admin pool handlers *are* covered end to end.

#### 4a — original scope
- `tunnel_pool` (router, region, listen socket, generated key material, inner v4/v6 blocks,
  keepalive, enabled) + `tunnel.pool_id`; the interface name is derived from the id. A **composite** FK `(pool_id, router_id)` →
  `tunnel_pool (id, router_id)` so the tunnel's router cannot drift from its pool's — the two
  copies exist because a pool-less tunnel (a customer VPN later) still has a router.
- Allocator on the `tunnel` table: pick an enabled pool in the node's region, carve the first
  free /31 and /127 against what is already allocated, record the node-supplied peer key.
- Node-facing `POST`/`GET /api/v1/node/tunnel`: the node presents its public key and receives
  its addresses, the server key, the endpoint and the MTU. Idempotent — a node that retries
  gets the allocation it already has, never a second one.
- Fills the backing host's blank `ip` with the node's inner address. The host stays disabled:
  an allocation is not a working tunnel.
- Admin CRUD for pools, with utilisation.

#### 4b — Route-server realisation + drift (M/L)  ✅ DONE

What the build settled beyond the plan:
- **Peers are pushed one at a time, not through the interface.** `update_tunnel` recreates the
  interface on the Linux backend and takes every peer with it, so one node getting a guest
  address would cut every other node on the route server. `TunnelRouter` grew `set_tunnel_peer`
  / `remove_tunnel_peer`, which are `wg set peer` — additive, idempotent, and leaving the rest
  of the interface alone.
- **`AllowedIPs` narrows as well as widens**, which is what makes it usable as the anti-spoof
  boundary rather than a routing hint: `wg set peer allowed-ips` *replaces* the list, so a guest
  address that was released stops being accepted from that node on the next reconcile.
- **AllowedIPs is not a route.** It picks which peer a packet already headed down the tunnel
  belongs to; without `ip route` the guest's return traffic reaches the route server and is
  dropped as unroutable. Hence `sync_tunnel_routes` alongside `sync_tunnel_addresses`, both
  declarative — the caller knows the desired set, working out the difference is the backend's
  job.
- **A sync must not touch what the kernel owns.** The IPv6 link-local address and the /31 link
  route are put there by the kernel; a reconcile that deleted everything it did not add would
  fight the kernel on every poll. Both are excluded explicitly.
- **Both address families have to be queried separately.** `ip route show` is IPv4 only, so a v6
  guest prefix would look absent on every sync and be re-added forever.
- **Drift is reported, not just repaired.** `missing`, `changed` and `unclaimed` are kept apart
  because they mean different things: a peer that is gone was configured and vanished, a changed
  one is carrying the wrong anti-spoof list, and an unclaimed one is a key on an LNVPS interface
  that no allocation accounts for. Unclaimed peers are **removed** — `wgln*` is ours outright.
- **Allowed IPs are compared as a set.** `wg` reports them in its own order; treating that as a
  difference would rewrite a working peer's security boundary on every single poll.
- **Reconcile refuses to create the interface.** Peers are configured *on* an interface, and
  creating it here would duplicate `SyncTunnelPool` and hide the fact that it never ran.
- **Guest addressing is corrected by the existing router poll**, not by wiring a route-server
  call into the VM provisioning path. `SyncNodeTunnel` exists for promptness when a node asks
  for its tunnel; correctness does not depend on it firing.
- **A Mikrotik route server refuses peer operations rather than ignoring them.** The four new
  methods default to an error, so a pool put on a backend that cannot carry it fails loudly
  instead of accepting the pool and configuring nothing.

Testing note: `LinuxSshRouter` gained a `#[cfg(test)]` command hook. These methods run commands
as root on somebody else's route server, so what is worth asserting is the exact command issued
— which needs the transport replaced, not mocked around. The rest of that file remains untested
for want of a real box, as before.

#### 4b — original scope
- Push the peer to the route server through the existing `TunnelRouter`: `AllowedIPs` is the
  node's inner addresses **plus** the guest IPs assigned to it, which is also the anti-spoof
  boundary.
- Reconcile desired (`tunnel`) against observed (`router_tunnel`); a peer that has vanished
  from a router is drift to report, not an allocation to forget.
- Route the guest prefixes at the route server towards the peer.

#### 4c — Node data plane + health gate (XL — split into 4c1/4c2/4c3)

Sized as one increment it is XL. Three decisions taken before starting made it so, each
deliberately:

- **The daemon applies the configuration itself**, with `ip` and `wg`, rather than writing
  `wg-quick` files for something else to read. A marketplace node runs on hardware LNVPS does
  not own, so a data plane that depends on the operator having wired it up correctly is one
  whose mistakes surface as a customer's VM having no network. The daemon re-converges instead.
- **nftables only, spoken as JSON through the `nftables` crate** — not `iptables`, and not `nft`
  syntax this codebase formats and then parses back. Rules go to the kernel as typed objects and
  come back the same way, so what the daemon reports is what the kernel holds rather than what a
  scraper made of `nft list` output on whichever version the operator has. `iptables` was in the
  first draft and dropped: it cannot express the layer 2 rule at all (that is `ebtables`, a third
  tool), it has no typed exchange, and a second code path enforcing "the same" policy is a second
  code path to get subtly wrong. Debian has shipped `nftables` by default since Buster (2019);
  a machine without it is refused, which is the correct answer for a machine that cannot filter.
- **The health gate spawns a real guest and pings it** rather than asking the node how it
  thinks it is doing. The node self-reporting "bridge up, forwarding on" cannot catch a bridge
  with no path to the tunnel, which is exactly the mistake worth catching before a customer
  finds it.

The node also has no outbound API client yet (that was 2c, still pending), so 4c1 builds the
one call it needs rather than waiting.

#### 4c1 — Node data plane (L)  ✅ DONE

What the build settled beyond the plan:
- **The data plane is applied before the listener binds.** The control API binds an address of
  the tunnel interface, and on a fresh machine that interface does not exist until the daemon
  has fetched and applied its document — so the startup order is apply, then check, then serve.
  A failure to fetch is a warning rather than a fatal error: a node whose tunnel is already up
  from a previous run must keep serving through an LNVPS outage, or an API blip takes every node
  on the platform dark at once.
- **The gateway a guest uses belongs to its range, not to the node.** The guest is configured
  with the range's gateway and believes it is on-link, so the node holds that address on the
  bridge as a **host** address and turns on proxy ARP/NDP. Holding the whole range instead would
  make the node believe every other node's guests were local, and their traffic would disappear
  into the bridge instead of going up the tunnel.
- **The bridge takes the tunnel's MTU.** A guest sending 1500 bytes into a 1420-byte tunnel gets
  a connection that opens and then hangs on the first large transfer — the worst failure shape
  there is, because everything looks fine until it does not.
- **A peer that is not the route server is removed from the tunnel interface**, most likely a stale key left by
  a re-key, which would otherwise still be able to send traffic the node treats as LNVPS's.
- **Routes for departed guests are swept**, since a released address goes straight back in the
  pool and may already be somebody else's; the bridge's own gateway addresses are excluded from
  that sweep so tidying up after a guest cannot take the bridge's addressing with it.
- **Observation reads the machine, never a cache.** `/api/v1/status` runs the queries on
  demand: a cached answer reports that the tunnel was up once, which is exactly what the health
  gate must not accept. A tunnel that has never handshaken is reported as configured but not
  working, because WireGuard comes up perfectly happily with a peer that never answers.
- **The node generates its key in-process** rather than shelling out to `wg genkey`, so a
  missing `wg` fails when the interface is configured, with that error. The private key reaches
  `wg` as a **path**, never an argument: arguments are visible in `ps` to every user on the
  machine, and a marketplace node usually has more than one login.
- **`lnvps-node dataplane observe` deliberately needs no credential**, because "what does this
  machine actually have?" is the question asked when something is already broken.

Reworked during review, before merge:
- **Netlink, not `ip`.** The daemon speaks to the kernel directly (`rtnetlink` for links,
  addresses and routes; the WireGuard netlink interface for the tunnel; `/proc/sys` for the
  forwarding knobs). `ip` is a program that formats netlink messages and formats the answers
  back into text for us to parse; going direct removes a dependency on iproute2's presence and
  version, the output parsing that changes between releases, and gives kernel error codes
  instead of a line of English on stderr.
- **The data plane lives in its own network namespace.** The first cut configured the
  *machine's* network: it took the operator's default route and turned on forwarding
  machine-wide, on hardware that is often not only an LNVPS node. Now `wg0` and `br-lnvps` live
  in an `lnvps` namespace, so their default route stays theirs, the forwarding and proxy-ARP
  knobs are ours alone, and guests cannot reach the operator's network — not because a rule
  forbids it, but because no interface leads there. A tunnel that is down means no path at all,
  rather than customer traffic leaking out the operator's uplink sourced from LNVPS addresses,
  which looks like spoofing to their upstream. `wg0` is created in the machine's namespace and
  *moved*, because a WireGuard interface keeps its UDP socket where it was created — that is
  what lets the encrypted outer traffic still use the operator's uplink.
- **The node's tunnel is `wgln0`, not `wg0`.** It is created in the *machine's* namespace
  before being moved into the data plane's, so the name has to be one an operator is not
  already using — a VPN, a mesh, anything called `wg0` would either fail the creation or, worse,
  be adopted and moved out from under them. The `wgln` prefix is the same one the route server
  uses, so a managed interface is recognisable as LNVPS's wherever it appears. The harness
  proves it by putting an operator's own `wg0` on the machine first and checking it survives.
- **The bridge name is no longer sent.** Both sides hold it as a constant, because the daemon
  needs the name before it has ever spoken to LNVPS (`dataplane observe` takes no credential),
  and a document that could name a different one would leave the node holding two answers. The
  harness asserts the two constants agree.

Testing note: the orchestration is tested against a fake kernel behind a `NetOps` trait — what
is worth asserting is what the node *decides*. Whether those decisions work is proven by
`lnvps_e2e/tests/tunnel_netns.rs`, which builds both ends in network namespaces and pings
across the tunnel, including to a guest behind the node. It found four bugs nothing else did:
a namespace pinned from `/proc/self/ns/net` (the *process's* namespace in a threaded program,
so every "isolated" interface silently landed in the operator's network), WireGuard netlink
calls made outside the namespace the interface had been moved into, local-table routes being
mistaken for strays and deleted — and, in already-merged 4b code, **the route server never
routing the pool's own block**, so a route server holding `10.66.0.1/16` answered "network is
unreachable" for every node in the pool.

#### 4c1 — original scope
- `GET /api/v1/node/dataplane` (node token): the desired state in one document — the tunnel
  (key, addresses, endpoint, MTU, keepalive), the bridge, and the guest addresses assigned to
  this node. One call rather than three: the node applies these together or not at all, and a
  document that can be half-fetched is a data plane that can be half-applied.
- Node keypair: generated on first use into the state directory, `0600`, public half presented
  to `POST /api/v1/node/tunnel`. The private half never leaves the machine.
- `net.rs`: `wg0`, `br-lnvps`, the default route into the tunnel, MTU, and IP forwarding —
  idempotent, applied on startup and on every refresh, through a command runner that tests can
  record. These commands run as root on somebody else's machine; the exact command is the thing
  worth asserting.
- `lnvps-node dataplane show|apply` so an operator can see and re-drive it without the daemon.
- `/api/v1/status` reports the observed data plane, which 4c3's gate reads as its first check.

#### 4c2 — Anti-spoof + guest isolation (M/L)  ✅
Re-scoped after 4c1: the namespace already did the anti-LAN half. There is no path from
`br-lnvps` to the operator's network to block, so the rules that remain are the ones no
topology can enforce.

- **Anti-spoof, bound to the MAC where there is one.** A guest may source only the addresses
  LNVPS assigned it. The route server's `AllowedIPs` stops node A pretending to be node B; this
  stops guest A pretending to be guest B *on the same node*, which `AllowedIPs` cannot see
  because both addresses legitimately belong to that node's peer.
- **Guests may not reach each other at L2.** They share one bridge, and with proxy ARP they
  believe every address is on-link, so without this a tenant can ARP-poison, ND-poison or
  DHCP-spoof their neighbours — attacks that never reach the IP layer where the rest of the
  ruleset lives. Dropping the bridge's forward hook leaves guest-to-guest traffic to be
  *routed* by the node, which is exactly where it can be filtered. It is also what they would
  get if the two guests were on different nodes, so it is the consistent answer, not a
  restriction.
- **MSS clamped to the path MTU** on forwarded SYNs, so a guest that ignores path MTU discovery
  gets a connection that works rather than one that opens and hangs.
- **The ruleset is owned wholesale and replaced atomically.** The daemon does not add rules to
  the operator's chains: it renders a complete table and swaps it in one transaction, so there
  is no window in which a guest is unfiltered and no way for a half-applied set to persist.
- **nftables only, and typed.** The ruleset is built as `nftables` crate schema objects and
  exchanged with the kernel as JSON in both directions — never as text this codebase formats and
  the machine parses back. A node whose nftables does not work is refused rather than configured
  without a filter.
- The guest list comes from 4c1's document, so the boundary is LNVPS's, not something the node
  infers from what it happens to see on the bridge.

Deferred to increment 5, where the daemon starts creating taps: per-port `isolated` flags and
per-tap filtering. Binding an address to a *port* is stronger than binding it to a MAC, which a
guest chooses. Until the daemon owns the ports it cannot do this, and MAC binding plus L2
isolation is what is available in the meantime.

Built as `lnvps_node/src/fw.rs`, and two decisions are worth recording:

- **The machine states which ruleset it is running, and the daemon believes it.** The tag is
  carried in a rule comment and read back out of the kernel's own JSON, so an
  operator who flushes the table by hand gets it rebuilt on the next refresh. A daemon that
  remembered what it last applied would go on reporting a filter that no longer existed —
  which is the failure this whole increment exists to prevent, arrived at from the other side.
- **Nothing is reloaded when nothing has changed.** Reloading would be harmless, since every
  backend swaps atomically, but a daemon that reported a change on every poll produces a log
  in which nothing can be noticed.

The end-to-end harness proves the drop rather than the ping: a spoofed packet fails to get a
reply anyway for want of a return route, so a failed ping proves nothing. What proves it is the
drop counter moving — the packet stopped on the node, before the tunnel, LNVPS's network, or an
upstream that would attribute it to the operator.

#### 4c3 — Health gate (L — split into 4c3a/4c3b)
Re-sized once the code was read: the gate needs LNVPS to *call* a node, and LNVPS has never
called one. Nothing dials the control API — there is no client, no signing key in settings, and
no pinned-certificate verifier. That is an increment of its own, and useful on its own.

The original wording said the gate provisions "a probe guest through the ordinary path". There
is no ordinary path yet: `get_host_client` has no arm for `VmHostKind::MarketplaceNode`, so a
node cannot start a VM at all until its hypervisor backend lands. The probe therefore stands in
for the guest, on the same address it would have had.

##### 4c3a — LNVPS can call a node (M)
- A control client: NIP-98 signed with **LNVPS's own nostr identity** — the account customers
  DM for support, `npub1lnvps32qq2nvg75cqwflq4y6cmnzn55d26ypzjakpkp3khqcx2ns7t7vjj` — over
  HTTPS pinned to the certificate fingerprint the node registered. One identity rather than a
  control key of its own: a separate secret would have to be generated, handed to whoever
  builds the node binaries, and kept in step with the value compiled into them, while this one
  is already published. An operator can check the key their node obeys against an account that
  publicly answers, which is not a check anyone could make against a key held only by LNVPS. Both directions authenticated — the node already
  verifies the signature against a key compiled into its binary, and this is the other half.
- `GET /api/v1/status` read into typed LNVPS-side structs. Deliberately *not* by depending on
  `lnvps_node`: that would pull netlink, nftables and WireGuard into the API binary, and the
  wire format is the contract, not the Rust type.
- Surfaced as an admin endpoint, because "what does this node say about itself right now" is
  the first question anyone asks about hardware they cannot see.
- Dialled at the node's tunnel address, port 8890 fleet-wide. Not stored per node: the control
  API exists only inside the tunnel, where every node has an address to itself and nothing
  competes for the port. An operator who changes it makes their own node unreachable, which the
  gate reports as unreachable — self-correcting, and cheaper than a column.

##### 4c3b — Reachability gate (built, rejected, not landed)
Written and closed unmerged (#369). It took an address from a customer range, had the node hold
it on the bridge, and pinged it from the route server. That proves the tunnel handshook, the
route server routes and admits the address, the node's bridge route and filter binding exist,
forwarding is on, and proxy ARP answers.

It does not prove the node can build and run a VM, which is the first thing a customer touches —
so it was a data-plane reachability check wearing the health gate's name. It also spent an IPv4
address per run, on the platform's scarcest resource, to check the cheapest of the properties
worth checking.

##### 4c3c — Probe VMs (L, blocked on the node VM lifecycle)
A probe is a **real VM**, built by the node through exactly the path a customer's VM takes, run
for a few minutes, measured over SSH, and destroyed. It looks like a regular VM to the node
because it is one — which means the probe tests provisioning, the thing a customer hits first
and the thing a ping says nothing about.

- **IPv6 only.** There is plenty of it and none to spare of v4, and a node that cannot carry a
  v6 guest cannot carry a dual-stack one either.
- **Nothing about a probe VM is stored.** It lives in LNVPS's memory and in the node's desired
  state, nowhere else. That is the failure model, not a shortcut: if the API restarts mid-probe
  the VM is simply absent from the next document the node fetches, and the node tears it down as
  it would any guest LNVPS no longer lists. A row in a table would need a reaper, and a reaper
  is another thing that can fail — leaving somebody's hardware running our VM indefinitely.
- **Chosen at random, when a node polls.** The node already fetches its data plane on a timer;
  LNVPS decides on that request whether this is a node worth looking at. No scheduler, no push,
  no queue. A fleet-wide cap keeps a large fleet from spawning a hundred probes at once, and a
  per-node cooldown keeps anyone's hardware from running our VMs continuously.
- **Built from the region's cheapest sellable template and an existing image**, so a probe runs
  the same artefacts a customer would get and proves those work on this node — rather than a
  bespoke image that only proves the bespoke image works. The cost is that node A may be
  measured at 1 GB and node B at 4 GB, so the **shape and image are recorded with every result**
  and the measurements normalised where they can be (MB/s, MB/s per GB). A raw number with no
  shape beside it is not a series anybody can read.
- **Measured over SSH**, with an ephemeral keypair generated per probe and never stored:
  - **login works at all** — the customer-visible failure a reachability check misses;
  - **memory actually allocates and is touched** — a node selling 8 GB that pages at 3 is the
    most profitable lie an operator can tell, and asking for the memory is the only way to catch
    it;
  - **disk read and write speed** — the second most profitable lie;
  - **time from asked to answering**, which is what a customer experiences as provisioning.
- **Results stored as a series** (`marketplace_node_health`), not a latest verdict: one bad run
  is a bad afternoon, a trend is a node to suspend, and the trust tier and SLA accounting in
  increment 12 both want the history.

**Blocked on:** the node cannot build a VM. Its document describes addresses, not machines
(`ApiNodeGuest` is an address, a gateway and a MAC), and `get_host_client` has no arm for
`VmHostKind::MarketplaceNode`. That is increment 5 either way, and doing it first means LNVPS's
own probes exercise the provisioning path before a customer is the first VM a node ever builds.

### Increment 4d — VMs on a marketplace node, over the tunnel (L) ✅ **done**

The node stays dumb. It brings up the tunnel, the data plane and the firewall — and runs a
**libvirtd that LNVPS drives directly** over the tunnel with the existing `LibVirtHost` client.
No VM document, no node-side reconciler, no marketplace host client: `get_host_client` gains an
arm and every existing worker flow works, because a marketplace node becomes just another
libvirt host.

Two facts from the code decide the shape, and neither is optional:

- **libvirtd's network namespace decides where VM taps land.** Guests have to be on `br-lnvps`
  inside `/run/netns/lnvps`; a libvirtd in the machine's own namespace creates taps where that
  bridge does not exist. So libvirtd must run *inside* the namespace — which is why it is a
  **dedicated instance** (`lnvps-libvirtd`, its own config, socket and unit with
  `NetworkNamespacePath=`) rather than the machine's. Moving the operator's libvirtd into our
  namespace would take the networking off every VM they already run, and would hand LNVPS
  control of their domains; a separate instance means LNVPS sees only its own.
- **Guests can reach the node's tunnel address.** They are on `br-lnvps`, which is in the same
  namespace as `wgln0`. The nft input chain drops everything from the bridge except ICMP, but
  a listener there means one firewall regression would hand a customer VM control of the node
  and every other customer on it. Hence **TLS client certificates**: a guest that gets past the
  filter still cannot authenticate.

#### The PKI
- The node generates a libvirt server key and certificate, and **registers the certificate**
  with LNVPS. LNVPS already pins the node's control certificate by fingerprint; this is the same
  idea for the other direction, except the *certificate* is needed rather than a hash, because
  libvirt verifies a chain rather than a pin.
- LNVPS holds one **client certificate** for the fleet, signed by an LNVPS CA. The node is sent
  that CA in its data-plane document — it is public, and the document is already authenticated,
  so there is nothing to distribute out of band and nothing compiled into the binary that a
  rotation would strand.
- LNVPS connects with `qemu+tls://<tunnel address>/system?pkipath=…`, materialising a per-node
  directory from the certificate the node registered. `no_verify` is never used: the whole point
  is that the machine answering is the node LNVPS registered.

#### What landed
- `lnvps_node/src/libvirt.rs` — the dedicated instance: identity, `libvirtd.conf`, `qemu.conf`,
  the systemd unit with both namespaces, and `systemctl` handling. 16 tests.
- `lnvps_api_common/src/host/marketplace_pki.rs` — per-node trust directories and the connection
  URI. 7 tests.
- `MarketplaceLibvirtConfig` on `ProvisionerConfig`; `VmHostKind::MarketplaceNode` arm in
  `get_host_client`, which refuses a node that has not registered a certificate.
- `POST /api/v1/node/libvirt` (node token) and `libvirt{}` in the data-plane document.
- `marketplace_node.libvirt_cert` (migration `20260812120000`).

#### What only a real run found

The design survived review, unit tests and a full workspace suite. Starting an actual libvirtd
found five things, three of them in code that had already merged:

1. **Two system libvirtds cannot share `/var/lib/libvirt`.** The dedicated instance needs a
   private *mount* namespace as well as the network one. That in turn made `virtlogd` unreachable
   (its socket lives in `/run/libvirt`, which we replace), so the instance writes logs directly.
2. **The pid file.** libvirtd defaults to `/run/libvirtd.pid` — in `/run`, which we do *not*
   replace — so the operator's daemon holds the lock and ours refuses to start, naming a path
   neither appears to configure.
3. **libvirt will not serve a CA certificate as its own leaf** ("basic constraints show a CA, but
   we need one for a server"). The original design — one self-signed, CA-capable certificate, so
   LNVPS could pin it directly — was unstartable. The node now roots a one-certificate chain.
4. **Both ends validate the certificate they present against the file they verify the peer with.**
   Each side's trust file therefore carries two CAs, and each error names the complainant's own
   certificate rather than anything about the peer, which is why it bit once per side.
5. **The node's filter accepted only ICMP.** Every TCP call LNVPS makes to a node was dropped —
   the libvirt connection and the **control API** alike. A node in that state pings, handshakes,
   reports itself healthy and answers nothing, and it had been that way since 4c2 landed.

The last one is the lesson worth keeping: 4c2 and 4c3a each shipped with tests that asserted the
right ruleset and the right client, and the combination was inert. Nothing asserted a packet.

#### Work
- **Node**: generate and persist the libvirt identity; present it at registration; write
  `libvirtd.conf` (listen on the tunnel address only, `tls_allowed_dn_list` naming LNVPS's client
  DN) and a systemd unit with `NetworkNamespacePath=/run/netns/lnvps`; keep it running and
  report it in `/status`. Storage pool comes from the node's own config — LNVPS does not know
  what storage the machine has.
- **LNVPS**: store the node's libvirt certificate; settings for the client certificate, key and
  CA; materialise `pkipath` per node; `get_host_client` arm for `VmHostKind::MarketplaceNode`.
- **Then**: probe VMs (4c3c) are just VMs LNVPS creates and deletes through that client.

### Increment 5 — Confidential computing: attestation + encrypted disks (L)
- Verify SEV-SNP attestation reports (`sev` crate) / TDX quotes (`dcap-qvl` crate) against
  AMD/Intel roots + measurement allow-list; store attestation state on `marketplace_node`;
  gate eligibility on it.
- libvirt domain XML `<launchSecurity type='sev-snp'/>` for every marketplace guest
  (extend `create_domain_xml` in `lnvps_api_common/src/host/libvirt.rs`); refuse to start a
  guest if the option is unavailable.
- Key-broker endpoint + guest-side early-boot LUKS2 unlock over the WG tunnel; key rotation,
  revocation on VM deletion, and "disk is inert off-node" test.
- Tests: reject forged/replayed attestation, reject mismatched measurement, reject key release
  to a non-attested guest.

### Increment 6a — Job channel + `VmBackend` trait + lifecycle (L)
- [ ] **Do not expose `list_host_vms`** (or any other host-wide enumeration) through the node job
      protocol — see Trust model. Add a test asserting the job dispatcher rejects it.
- Job protocol (create/start/stop/reboot/delete/reinstall/resize/console) with correlation ids,
  idempotency keys, and desired-state reconciliation.
- `VmBackend` trait on the node; `MarketplaceNode` host backend in `lnvps_api` implementing the
  existing host trait over the socket.
- Implement the real libvirt lifecycle in `lnvps_api_common/src/host/libvirt.rs`
  (create/start/stop/reset/delete/state), replacing the increment-0 error stubs and re-enabling
  the backend. Blocking C API → wrap calls in `spawn_blocking`. **No silent no-ops.**

### Increment 6b — Storage, images and console (S — mostly done)
The hypervisor-side work is **already implemented and tested** in `lnvps_api_common`'s libvirt
backend (image download + SHA-2 verification, qcow2 provisioning, resize, cloud-init seed,
per-VM IOPS/bandwidth caps, real stats, serial console). What is left is exposing it through the
node job protocol:
- Route these operations over the node socket rather than a direct libvirt connection.
- Proxy `connect_terminal` back through the control channel (the local implementation exists).
- Decide how OS images reach an operator's machine: the API currently uploads over the libvirt
  connection, which for a marketplace node means over the WG tunnel.

### Increment 7 — Placement, capacity and templates (M)
- Feed node telemetry into the existing load factors; overcommit policy per trust tier.
- Marketplace-eligible templates/regions; user-visible "community compute" flag on offers.
- Drain/cordon: stop new placements, optionally migrate or expire existing VMs.

### Increment 8 — SLA, uptime accounting and enforcement (M)
- `marketplace_uptime` samples from heartbeat **and** independent `lnvps_health` probes.
- Breach states → alerting (SMTP, existing notification module), auto-cordon, payout hold.
- Operator dashboard data: uptime %, VMs hosted, earnings accrued.

### Increment 9 — Payouts (M/L)
- `marketplace_payout` ledger with idempotent settlement; accrual worker in `worker.rs`,
  rate resolved as override → company default (mirrors `ReferralCostUsage`).
- Lightning send via the chosen rail; retry/backoff, failure quarantine, admin manual release.
- Reporting endpoints + CSV export; reconciliation tests with mocked wallet.

### Increment 10 — Abuse, offboarding and docs (M)
- Operator offboarding: cordon → expire/migrate VMs → tear down WG peer → final payout.
- Abuse path: guest IP blocks/null-routes flow through existing `lnvps_fw`/AVS controls.
- Docs: `docs/agents/marketplace.md`, operator install guide, `API_CHANGELOG.md` entries,
  E2E tests in `lnvps_e2e` with a mock node.

### Increment 11a — GPU inventory + whole-card passthrough (L, depends on 5 + 7)
- `marketplace_node_gpu` inventory (node, PCI address, IOMMU group, vendor, model, VRAM,
  driver/QEMU/OVMF versions, CC-capable, MIG/SR-IOV-capable, **enrolled** flag, allocation
  state) and `vm_gpu_assignment` — mirroring IP assignment: a countable resource with an
  explicit assignment row, never a load factor.
- **Enrolment is per device and operator-initiated.** The node never claims a GPU the operator
  has not offered, and never performs host-wide NVIDIA module unloads while the operator's own
  GPUs are in use (only the open-source driver supports mixed host/passthrough use at all).
- Domain XML: `<hostdev>` with `<rom bar="off"/>`, computed `<pcihole64>`, flat topology plus
  `multifunction="on"` for consumer cards, deep topology (one `pcie-root-port` per GPU) for
  datacenter cards. `managed="no"` + explicit `<driver name="vfio"/>` for NVIDIA.
- Host driver lifecycle on the node: full teardown/rebind sequence with a hard failure when
  something still holds the device, and the post-return CUDA warm-up.
- Eligibility checks for QEMU ≥ 9.2 / OVMF 2024.02+ / libvirt 10.6+ / kernel 6.11+ and a clean
  IOMMU group; refuse rather than produce a VM that fails to map BARs.
- Scrub-and-verify between allocations; cordon any card that fails reset instead of reissuing.
- Two-tier product plumbing (decision 8): `confidential` vs `non-confidential` GPU offers, the
  order-time disclosure, and a hard rule that a non-CC GPU can never satisfy a confidential
  template.
- Pricing: GPU line items in cost plans and rev-share accounting for them.
- Drain policy for GPU VMs — they cannot move, so expire-and-refund rather than relocate.

### Increment 11b — Fractional GPUs, AMD SR-IOV (M/L, depends on 11a)
- GIM driver partition modes (SPX/DPX/QPX/CPX) on Instinct MI300X/MI350X; VFs are ordinary
  PCI devices passed with `managed="yes"`, so libvirt handles the VFIO binding — none of
  NVIDIA's teardown sequence applies.
- The PF stays bound to `amdgpu` at all times; no runtime driver switching, which also means
  no risk of disturbing the operator's other workloads.
- Partition mode is a **node-level, operator-set** property (it is driver/firmware level and
  cannot be mixed per card), so it belongs in node enrolment, not in per-VM scheduling.
  Scheduling is then a simple count of free VFs per mode.
- Guest images with ROCm + an HWE kernel (Ubuntu 24.04's 6.8 is too old for the ROCm DKMS
  module) baked in.
- **Explicitly not included: NVIDIA MIG/vGPU.** Decision 9 rules out AI Enterprise licensing,
  and there is no supported way to hand a MIG instance to a VM without it. NVIDIA remains
  whole-card passthrough from 11a.

## Risks

| Risk | Mitigation |
|---|---|
| Operator reads guest data | SEV-SNP/TDX memory encryption + attestation-gated LUKS keys; node never holds the disk key. |
| Attestation bypass (spoofed/replayed report, emulated platform) | Verify against vendor root certs with a fresh nonce per boot; measurement allow-list; no key release without a passing check. |
| CC hardware requirement shrinks the operator pool / raises cost | Accept: confidentiality is non-negotiable. Publish a supported-CPU list up front. |
| QEMU+OVMF measurement churn makes the allow-list unmaintainable | Pin platform+signer initially; evaluate Cloud Hypervisor + IGVM for a small reproducible measurement. |
| libvirt TDX support immature/distro-dependent | SEV-SNP is the v1 target; TDX best-effort, gated on reported node capability. |
| Executor work underestimated because the libvirt backend looked complete | Recognised: it is a stub. Split into increments 6a/6b and sized as greenfield. |
| `virt` crate is a git dependency with C bindings shipped to operator hardware | Pin the revision, vendor if needed, or prefer a pure-Rust VMM (decision 4a). |
| GPU DMA leaks guest data past memory encryption | Only CC-capable GPUs (NVIDIA CC mode) may back a confidential VM; anything else is a labelled non-confidential tier, never a silent downgrade. |
| VRAM residue leaks between GPU tenants | Mandatory scrub-and-verify between allocations; a card that fails reset is cordoned, not reissued. |
| GPU VMs cannot be drained or migrated off a failing node | Separate drain policy: expire and refund rather than relocate; price and advertise accordingly. |
| GPU mining abuse / power draw on operator hardware | Power and thermal telemetry per node, ToS stance, per-node reputation. |
| Node daemon breaks the operator's own GPU workloads by unloading NVIDIA modules host-wide | Only enrolled devices are ever touched; refuse host-wide teardown while unenrolled GPUs are in use; mixed use requires the open-source driver. |
| NVIDIA vGPU licensing (~$4.5k/GPU/yr) blocks operator onboarding | Ruled out entirely (decision 9): NVIDIA is whole-card passthrough only, which needs no licence; fractional capacity comes from AMD SR-IOV. |
| No small confidential GPU offer exists (fractional is AMD, confidential is NVIDIA) | Accepted and documented as a product fact, not hidden; revisit via BYO-licence operators or SEV-TIO/TDISP. |
| Customer misreads a non-confidential GPU VM as confidential | Separate product tier with order-time disclosure in plain words; a non-CC GPU can never satisfy a confidential template. |
| Operator abuses LNVPS IPs (spam/DDoS from a rogue node) | Route-server-side egress filtering + rate limits per node, existing `lnvps_fw`, instant peer teardown. |
| Guest abuse damages `185.18.221.0/24` reputation | Same abuse workflow as owned hosts; per-node reputation score gating capacity. |
| WG throughput/latency ceiling on cheap operator links | Advertise link speed in offers, measure per-node, cap bandwidth in `VmTemplate`. |
| Node offline with customer data on it | SLA holds + payout forfeiture, backup policy decision (open item 5), clear ToS. |
| Payout fraud (fake capacity/uptime) | Independent probing, synthetic canary VMs, payout only on invoiced VMs actually running. |
| Node self-upgrade breaks a fleet | Staged rollout by trust tier, version pinning, same lockstep versioning rule as `lnvps_fw`. |

## Notes

- Reuse over rebuild: WG is already modelled (`TunnelRouter`), the daemon shape is already
  proven (`lnvps_fw`), payout/rate mechanics already exist (referral), and node auth is just the
  existing consumer auth. The genuinely new pieces are the **inverted control channel**, the
  **confidential-computing attestation + key broker**, and the **SLA engine**.
- Keep `AGENTS.md` release rules in mind: if `lnvps_node` becomes a separate workspace, its
  version must be bumped in lockstep with `vX.Y.Z` like `lnvps_fw`, or self-upgrade will loop.
