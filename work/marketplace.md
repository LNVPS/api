# LNVPS Marketplace (operator-run compute nodes)

**Status:** planning
**Started:** 2026-07-05
**Last updated:** 2026-08-05 (increment 1 landed; decisions locked: no operator KYC in v1, payout rails shared with referrals)

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
- WireGuard is already modelled: `TunnelRouter` trait, `WireguardConfig`, `WireguardPeer`,
  `TunnelKind`, plus Linux-SSH and Mikrotik backends — `lnvps_api/src/router/mod.rs`,
  `router/linux_ssh.rs`, `router/mikrotik.rs`. Route-server work: `work/route-server-management.md`.
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
2. **Revenue share** — per-account rate with company-wide default, identical mechanism to
   referrals (`Option<f32>` override → `company.*_rate`).
3. **Node auth** — normal consumer-API auth: operator's nostr key (NIP-98) or a long-lived
   session token. No separate node credential system.
4. **Encryption** — disk encryption *and* memory encryption (SEV-SNP/TDX) are mandatory
   eligibility requirements, with remote attestation gating both placement and LUKS key release.
5. **VMM** — libvirt/QEMU/KVM for v1 (decided on merit; the existing backend is a stub, so this
   is greenfield). Node VM control still goes behind a `VmBackend` trait to keep Cloud
   Hypervisor viable later.
6. **Stubbed libvirt backend** — superseded: the backend was fully implemented instead
   (`work/libvirt-backend.md`, merged), so nothing needs disabling.
7. **Operator KYC** — none in v1. Operators are not identity-checked; confidentiality is
   enforced by attestation and guest encryption, not by knowing who the operator is. The
   `marketplace_operator` table deliberately carries no identity columns, so there is no
   store of documents to protect. Trust tiers still exist for placement policy, and a
   future tier can add checks without a schema change to what v1 stores.
8. **Payout rail** — shared with referrals. `marketplace_operator` mirrors `referral`
   column for column (`address` + `mode` + `payout_threshold`), and the payout-mode enum is
   now one shared `PayoutMode` type (`ReferralPayoutMode` remains as an alias). Operators
   get Lightning address, NWC and on-chain, and both ledgers reconcile the same way.

**Still open:**

4b. **Cloud Hypervisor as a second `VmBackend`** — worth doing once measurement pinning is
   in place (smaller TCB, smaller measurement), or stay on QEMU indefinitely?
7. **Attestation strictness**: pin exact guest measurements (strongest, but every image/kernel
   update needs a re-measure + allow-list bump) vs. pin platform + signer only.
8. **Backups**: operator-local storage only, or optional LNVPS-side backup egress (costly over
   WG, and must stay encrypted end-to-end).
9. **Migration**: is offline migration off a misbehaving node required in v1?

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
- `marketplace_node` (operator_id, name, region_id, pubkey, status, trust_tier, last_seen,
  created), unique pubkey so a key identifies exactly one node.
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
- Route-server side: allocate tunnel subnet + WG peer via the existing `TunnelRouter` trait
  (`router/mod.rs`), push routes for the guest IPs assigned to that node.
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
