# Per-day VM traffic accounting and monthly transfer quotas

**Status:** in-progress
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

### Increment 2 — worker sampling (M)

- [ ] Traffic accumulator in `lnvps_api/src/worker.rs` fed from
      `check_vms_on_host()`, with counter-reset detection
- [ ] Day rollover handling (a sample spanning UTC midnight attributes the whole
      delta to the day the sample was taken — document this, it is a rounding
      error of at most one poll interval)
- [ ] Skip accounting for VMs whose state is not `Running` where the counter is
      meaningless
- [ ] Tests: normal delta, counter reset, first sample (no baseline → record
      nothing, just set baseline), day rollover, deleted VM

### Increment 3 — user API (S/M)

- [ ] `GET /api/v1/vm/<id>/traffic?start=&end=` returning daily rows
- [ ] Include current-month usage + `transfer_gb` quota in the VM detail response
- [ ] Quota resolution helper (standard vs custom template), mirroring
      `vm_firewall_rule_limit()`
- [ ] `API_DOCUMENTATION.md` + `API_CHANGELOG.md`

### Increment 4 — admin API (S/M)

- [ ] `transfer_gb` on admin template / custom-pricing create/update/list models
- [ ] Admin VM traffic listing endpoint + quota field in admin VM info
- [ ] Region/host traffic report in `lnvps_api_admin/src/admin/reports.rs`
- [ ] `ADMIN_API_ENDPOINTS.md` + `API_CHANGELOG.md`

### Increment 5 — notifications (S)

- [ ] Worker check: on crossing 80% / 100% of monthly quota, email the customer
- [ ] Suppress repeat notifications within the same month (a `vm_history` entry
      or a dedicated `notified` marker — decide during implementation)
- [ ] Tests

## Notes

- `cargo check --workspace --all-features` fails on master with a pre-existing
  `BitvoraNode` / `payments-rs` type error in
  `lnvps_api/src/payment_factory.rs:98`. Default features build clean. Not
  caused by this work; do not try to fix it here.

- No enforcement in this pass by explicit decision; increments must not wire
  `transfer_gb` into `VmResourceLimits` or host config generation.
- Retention of `vm_traffic_daily` is unbounded for now: one row per VM per day
  is ~50 bytes, so 1000 VMs for 3 years is ~55 MB. Revisit if that changes.
