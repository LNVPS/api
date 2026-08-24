# Per-day VM traffic accounting and monthly transfer quotas

**Status:** complete
**Started:** 2026-08-24
**Last updated:** 2026-08-24

## Goal

Record per-VM, per-day network traffic (bytes in/out) in the database, and add a
monthly outbound transfer quota to VM templates and custom VM specs, so that
usage is visible to customers and admins and customers are warned as they
approach the quota. No automatic enforcement in this pass.

## Design decisions (confirmed with user 2026-08-24)

- **Source:** hypervisor counters already polled by the worker
  (`VmRunningState { net_in, net_out }` from `get_all_vm_states()`), accumulated
  as deltas into a daily row. Counter resets (reboot, migration, host restart)
  are detected as `new < last` and the new value is taken as the delta baseline
  (i.e. contribute `new`, not `new - last`).
- **Limit shape:** monthly transfer quota in GB, **outbound (`net_out`) only**.
  Ingress is free. Field name `transfer_gb: Option<u32>` (None = unmetered),
  mirroring the existing optional-limit convention of `network_mbps` /
  `firewall_rule_limit`.
- **Enforcement:** record + expose + notify only. Email the customer at 80% and
  100% of quota. No throttle, no suspend, no overage billing.
- **Period:** calendar month, UTC.

## Findings

Relevant existing code:

- `lnvps_api_common/src/status.rs` — `VmRunningState` carries `net_in`/`net_out`
  (cumulative byte counters from the hypervisor) and is cached in Redis/memory
  with a TTL. The cache is **not** durable, so the last sample used for delta
  computation must live in the database, not the cache.
- `lnvps_api/src/worker.rs`
  - `check_vms_on_host()` (~line 1700) — the only sweep that visits every VM;
    calls `get_all_vm_states()` once per host and then `handle_vm_state()` per
    VM. This is where traffic sampling hooks in.
  - `handle_vm_state()` (~line 1384) — writes the state into `vm_state_cache`.
- `lnvps_db/src/model.rs`
  - `VmTemplate` (~1287), `VmCustomTemplate` (~1326), `VmCustomPricing` (~1359)
    all already carry `network_mbps: Option<u32>` and (templates only)
    `firewall_rule_limit: Option<u16>` — the precedent to mirror for
    `transfer_gb`.
- `lnvps_api_common/src/host/mod.rs:421` — `VmResourceLimits`-ish struct built
  from templates (lines 384/393); transfer quota is *not* a host-enforced limit
  so it should **not** be added there.
- Precedent migration for an optional per-template limit:
  `lnvps_db/migrations/20260624123544_vm_firewall_rule.sql`.
- Precedent for a usage-recording feature:
  `lnvps_db/migrations/20260728120000_app_deployment_usage.sql` and
  `list_app_deployment_usage_breakdown` in `lnvps_db/src/lib.rs:1589`.
- `firewall_rule_limit` resolution helper `vm_firewall_rule_limit()` in
  `lnvps_api/src/api/routes.rs:2504` — the pattern for resolving a limit from
  either the standard or custom template of a VM. `transfer_gb` needs the same.

Schema sketch:

```sql
create table vm_traffic_daily (
    vm_id      integer unsigned not null,
    day        date             not null,
    bytes_in   bigint unsigned  not null default 0,
    bytes_out  bigint unsigned  not null default 0,
    primary key (vm_id, day),
    constraint fk_vm_traffic_daily_vm foreign key (vm_id) references vm(id)
);

-- last raw counter sample, for delta computation across worker passes
create table vm_traffic_sample (
    vm_id           integer unsigned not null primary key,
    last_bytes_in   bigint unsigned  not null,
    last_bytes_out  bigint unsigned  not null,
    sampled         timestamp        not null,
    constraint fk_vm_traffic_sample_vm foreign key (vm_id) references vm(id)
);

alter table vm_template        add column transfer_gb integer unsigned null default null;
alter table vm_custom_template add column transfer_gb integer unsigned null default null;
alter table vm_custom_pricing  add column transfer_gb integer unsigned null default null;
```

`vm_traffic_sample` is separate from `vm_traffic_daily` because the sample is
transient per-VM state (one row, overwritten) while the daily rows are an
append-only history that must survive VM deletion policy decisions.

## Tasks

### Increment 1 — schema + db layer (M) ✅

- [x] Migration `20260824103500_vm_traffic.sql`: `vm_traffic_daily`,
      `vm_traffic_sample`, `transfer_gb` on `vm_template` /
      `vm_custom_template` / `vm_custom_pricing`
- [x] `lnvps_db/src/model.rs`: `VmTrafficDaily`, `VmTrafficSample` structs;
      `transfer_gb` on the three template/pricing structs
- [x] `LNVpsDbBase` trait methods: `get_vm_traffic_sample`,
      `upsert_vm_traffic_sample`, `add_vm_traffic`, `list_vm_traffic`,
      `get_vm_traffic_total`
- [x] MySQL impl, including `transfer_gb` in every existing template/pricing
      insert/update/select (both the user-side and admin-side statements)
- [x] Mock DB impl in `lnvps_api_common/src/mock.rs`
- [x] Admin request/response models carry `transfer_gb` (folded in from
      increment 4: the create/clone call sites had to be touched anyway)
- [x] Unit tests in `mock::vm_traffic_tests`; migration and both upsert
      statements verified against the real MariaDB container

### Increment 2 — worker sampling (M) ✅

- [x] `TrafficRecorder` in `lnvps_api_common/src/traffic.rs` rather than in
      `worker.rs`: the differencing rules are the interesting part and testing
      them should not need a worker
- [x] Hooked into `Worker::handle_vm_state`, which is the single funnel both
      `check_vm` (customer action) and `check_vms_on_host` (periodic sweep) go
      through — hooking the sweep alone would have missed half the readings
- [x] Counter-reset detection: a reading below its baseline contributes the new
      reading itself, not an underflowing subtraction
- [x] First reading sets the baseline and records nothing
- [x] Implausible-jump clamp at 4 GB/s of elapsed time (see below)
- [x] Recording is best-effort — it must never abort a sweep and leave the VMs
      behind it unchecked
- [x] Tests: `traffic::tests` (11) + `worker::tests::test_handle_vm_state_
      records_traffic`; `traffic.rs` at 100% function coverage

No state filter was added. A stopped VM reads zero on both counters, which the
reset rule already handles as "contributes nothing", and a frozen counter
differences to zero — so filtering on `VmRunningStates` would only add a way to
lose the last sample before a shutdown.

### Increment 3 — user API (M) ✅

- [x] `GET /api/v1/vm/{id}/traffic?start=&end=` returning daily rows plus the
      current month's quota totals
- [x] `transfer_gb` on `ApiVmTemplate`, so the allowance shows on the offer
      (`GET /api/v1/vm/templates`) and on the VM, rather than only in a usage
      call
- [x] `vm_transfer_quota_gb()` helper (standard vs custom template), mirroring
      `vm_firewall_rule_limit()`
- [x] `resolve_traffic_range()` in `traffic.rs` — range defaulting and
      validation kept out of the handler so it is unit-testable; 400-day cap
- [x] Traffic rows are cleared on VM hard-delete and user purge (MySQL and
      mock). They hold an FK to `vm`, so without this every hard delete fails
- [x] `API_DOCUMENTATION.md`, `API_CHANGELOG.md`, `ADMIN_API_ENDPOINTS.md`
- [x] Lifecycle e2e coverage: quota period always reported, recorded traffic
      surfaces, out-of-range returns no rows but still reports the month,
      inverted range and unbounded span rejected

### Increment 4 — admin API (M) ✅

- [x] `transfer_gb` on admin template / custom-pricing create/update/list models
      (done in increment 1)
- [x] `traffic` summary on `AdminVmInfo`, same object as the customer-facing
      `VmStatus.traffic`
- [x] `GET /api/admin/v1/vms/{id}/traffic` (`virtual_machines::view`)
- [x] `GET /api/admin/v1/reports/traffic` (`analytics::view`) — fleet ranked by
      outbound bytes, backed by a new `list_vm_traffic_totals` aggregate with
      database-level pagination; `total` counts VMs, not daily rows
- [x] `ADMIN_API_ENDPOINTS.md` + `API_CHANGELOG.md`
- [x] Mock tests for the aggregate (ranking, summing, paging, purged VMs) and
      lifecycle e2e assertions on all three admin surfaces

**Traffic is on the main VM detail responses, not only the traffic endpoints**
(user instruction, 2026-08-24). `vm_to_status` and
`AdminVmInfo::from_vm_with_admin_data` each cost one extra aggregate query per
VM; both already issue a dozen, and the quota itself rides free on the template
they already load. The traffic endpoints exist for the day-by-day breakdown and
arbitrary ranges, and their `summary` field is the identical object, so there is
one shape to render rather than two.

### Increment 5 — notifications (S) ✅

- [x] `Worker::check_transfer_quotas` warns at 80% and 100% of the monthly
      allowance, through the existing notification channels
- [x] Thresholds are checked highest-first, so a VM that jumps from 50% to 105%
      between passes is told it is over, not that it is at 80%
- [x] Suppression via a KV key scoped to `(vm, quota month, threshold)`. Month
      scoping means a new month starts clean with nothing to expire or sweep;
      threshold scoping means the 80% warning does not suppress the later 100%
      one. The key is written **after** the notification is queued, so a queue
      failure retries rather than being silently swallowed.
- [x] Hourly cadence, not per 30-second VM sweep: the figures move slowly and
      the check costs an aggregate query per metered VM. Standard-template
      allowances are pre-loaded once per pass (there are far fewer templates
      than VMs); custom templates are 1:1 with their VM so they are fetched
      only for VMs that have one.
- [x] Both messages state plainly that nothing has been done to the VM
- [x] Tests: below threshold, warn-once, highest-threshold-wins, unmetered
      plans ignored, cadence gate

Deliberately **not** done: a `VmHistoryActionType::TransferWarning` audit entry.
It would be a nice admin-visible record, but it needs a new enum variant plus
admin model mapping, and the KV key already answers "has this been sent". Worth
revisiting if support needs to see warnings in the VM history.

## Status

All five increments are complete. What exists now: per-day per-VM byte counters
sampled from hypervisor interface counters, a monthly outbound allowance on
templates and custom specs, usage on the customer and admin VM detail responses,
day-by-day and fleet-ranked endpoints, and 80%/100% courtesy warnings. Nothing
is enforced.

## Notes

- **Migration between hosts is the known inaccuracy.** The counter belongs to
  the hypervisor, not the guest, so a VM migrated onto a host where it had run
  before can read *above* its baseline and book the difference as traffic. The
  4 GB/s clamp (`MAX_SAMPLE_BYTES_PER_SEC`) bounds the damage to something a
  real link could have carried, which stops a bogus terabyte from silently
  exhausting a quota — it does not eliminate the error. Set well above 25
  Gbit/s (~3.1 GB/s) so a saturated NIC is never clamped.
- **Day attribution.** A delta is booked to the UTC day of the *reading*, so
  traffic either side of midnight lands on the later day. Worst case is one
  sweep interval (30s) of traffic on the wrong day, which is immaterial against
  a monthly quota.
- **Both directions are recorded; only outbound is metered.** `bytes_in` is
  stored and returned everywhere but never counted against `transfer_gb`. It
  costs nothing extra (same reading) and is the signal that distinguishes a VM
  being flooded from a VM abusing its allowance — relevant given the AVS/GSL
  scrubbing path in front of this network.
- **These are hypervisor NIC counters**, so `bytes_out` includes inter-VM and
  LAN-local egress, not just billable internet egress. Fine while the number is
  informational; **this gap must be closed before any enforcement or overage
  billing** (the firewall datapath is the natural source for internet-only
  accounting).
- **`CAST` must be outside `COALESCE` when summing.** `get_vm_traffic_total`
  first used `coalesce(cast(sum(x) as unsigned), 0)`, which decodes at runtime
  as `DECIMAL` and fails — COALESCE takes the aggregate type of its arguments
  and widens the cast straight back. The working form is
  `cast(coalesce(sum(x), 0) as unsigned)`. Neither `cargo test` nor a `mariadb`
  CLI query catches this (the CLI does not use the binary protocol); only the
  e2e run against a real server did. **Run the e2e suite for any change that
  adds an aggregate query.**
- Locally, port 8001 may be taken by an unrelated `vllm` process. Run the e2e
  script with `LNVPS_ADMIN_API_URL=http://localhost:8011` in that case.
- `cargo check --workspace --all-features` fails on master with a pre-existing
  `BitvoraNode` / `payments-rs` type error in
  `lnvps_api/src/payment_factory.rs:98`. Default features build clean. Not
  caused by this work; do not try to fix it here.

- No enforcement in this pass by explicit decision; increments must not wire
  `transfer_gb` into `VmResourceLimits` or host config generation.
- Retention of `vm_traffic_daily` is unbounded for now: one row per VM per day
  is ~50 bytes, so 1000 VMs for 3 years is ~55 MB. Revisit if that changes.
