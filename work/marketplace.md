# LNVPS Marketplace (operator-run compute nodes)

**Status:** planning
**Started:** 2026-07-05
**Last updated:** 2026-08-05 (increment 1 landed; GPU capacity scoped — two-tier offers, fractional in v1; increments 11a/11b)

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
guest VM ─ tap ─ br-lnvps (no operator uplink) ─ wg0 ─┐
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

### Increment 2 — Node daemon skeleton (`lnvps_node`) (M/L)
- New crate (own workspace if it needs a special toolchain; otherwise workspace member).
- Config, credential loading (nostr key **or** session token), NIP-98 signing, outbound WSS
  client with reconnect/backoff, `telemetry` frames (cpu/mem/disk/net, libvirt version, kernel,
  uptime, **CPU model + SEV-SNP/TDX capability + firmware version**).
- `.deb` packaging + GitHub release workflow + self-upgrade, copied from `lnvps_fw`
  (`upgrade.rs`, `lnvps_fw-deb.yml`). Version must move in lockstep with `vX.Y.Z`.

### Increment 3 — Pairing + admin approval flow (M)  ⬅ NEXT (with increment 2)
- `POST /api/v1/node/register` under standard consumer auth → node bound to the calling user,
  lands in `pending`. The authenticated user *is* the operator; no pairing code needed for the
  nostr/session-token path (keep a code only for headless installs).
- Operator-facing user API: list own nodes, set payout address, view earnings.
- Admin API: list/approve/reject/suspend/drain node, set trust tier, set capacity caps, set the
  per-operator rate override.
- On approval, create the backing `VmHost` row (disabled until networking is up).

### Increment 4 — WireGuard data plane (L)
- Allocator on top of the `tunnel` table from increment 1: pick a route server, assign the
  inner /31 (and/or /127), record the node-generated peer key. The schema already enforces
  that an inner address or peer key belongs to exactly one tunnel.
- Reconcile desired state (`tunnel`) against observed state (`router_tunnel`); a peer that has
  vanished from a router is drift to report, not an allocation to forget.
- Route-server side: push the peer and routes for the guest IPs assigned to that node via the
  existing `TunnelRouter` trait (`router/mod.rs`).
- Node side: create `wg0` + `br-lnvps`, default route into the tunnel, anti-spoof and
  anti-LAN-access rules, MTU/MSS clamp.
- Health gate: node is only marked `online` after an end-to-end reachability probe from the
  route server through the tunnel to a test guest IP.

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
