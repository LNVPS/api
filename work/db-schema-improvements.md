# Database Schema Improvements

**Status:** in-progress
**Started:** 2026-03-10
**Last updated:** 2026-03-10 (EXPLAIN review pass)

## Goal

Improve database performance, correctness, and maintainability by adding missing indexes,
removing redundant ones, fixing data integrity gaps, resolving the nullable
`subscription_line_item_id` issue, and cleaning up structural anti-patterns.

## Findings

All SQL queries are in `lnvps_db/src/mysql.rs`. Key findings confirmed by running `EXPLAIN` against
the live MariaDB container (`lnvps-db-1`) on 2026-03-10.

### Full table scans confirmed by EXPLAIN (`type: ALL`)

| Query | Table | Root cause |
|---|---|---|
| `SELECT * FROM users WHERE email_verify_token = ?` | `users` | No index on `email_verify_token` |
| `SELECT * FROM vm WHERE deleted = 0` | `vm` | No index on `deleted` |
| `SELECT * FROM vm_host_region WHERE enabled=1` | `vm_host_region` | No index on `enabled` (tiny table, low priority) |
| `SELECT * FROM ip_range WHERE enabled = 1` | `ip_range` | No index on `enabled` |
| `SELECT * FROM vm_ip_assignment WHERE ip=? AND deleted=0` | `vm_ip_assignment` | No index on `ip` |
| `SELECT * FROM vm_payment WHERE external_id=?` | `vm_payment` | No index on `external_id` |
| `SELECT * FROM vm_payment WHERE is_paid=true ORDER BY created DESC` | `vm_payment` | No index on `is_paid` or `created` |
| `SELECT * FROM available_ip_space ORDER BY created DESC` | `available_ip_space` | No index on `created` for sort |
| `SELECT * FROM payment_method_config ORDER BY company_id, payment_method, name` | `payment_method_config` | `idx_company_id` single-col, no composite for ORDER BY |
| `referral unpaid vm count` (`WHERE v.ref_code = ?`) | `vm` | No index on `ref_code` |
| `vm GROUP BY user_id` (in admin user list derived subquery) | `vm` | Full scan, grouped without index |

### Queries with `Using filesort` confirmed by EXPLAIN

| Query | Table | Fix |
|---|---|---|
| `vm_payment WHERE vm_id=? ORDER BY created DESC` | `vm_payment` | Composite `(vm_id, created DESC)` |
| `vm_payment WHERE vm_id=? AND … ORDER BY created DESC` | `vm_payment` | Same composite |
| `vm_history WHERE vm_id=? ORDER BY timestamp DESC` | `vm_history` | Composite `(vm_id, timestamp DESC)` |
| `subscription_payment WHERE subscription_id=? ORDER BY created DESC` | `subscription_payment` | Composite `(subscription_id, created DESC)` |
| `subscription_payment WHERE user_id=? ORDER BY created DESC` | `subscription_payment` | Composite `(user_id, created DESC)` |
| `subscription_payment WHERE is_paid=1 ORDER BY created DESC` | `subscription_payment` | Composite `(is_paid, created DESC)` |
| `payment_method_config WHERE company_id=? ORDER BY payment_method, name` | `payment_method_config` | Composite `(company_id, payment_method, name)` |

### Queries with `Using temporary` confirmed by EXPLAIN

| Query | Note |
|---|---|
| `admin permissions via role join` (DISTINCT) | Small RBAC tables; acceptable |
| `referral revenue` (window function `ROW_NUMBER() OVER`) | Window always materialises; acceptable |
| `users with active VMs contactable` (DISTINCT + full scan of `vm`) | Needs index on `vm.deleted` |
| `admin user list` derived subquery `GROUP BY user_id` on `vm` | Full scan; needs `(deleted, user_id)` or `(user_id, deleted)` |

### Queries that already use good indexes (EXPLAIN confirmed)
- `vm WHERE user_id = ? AND deleted = 0` — uses `fk_vm_user` (`type: ref`) ✓
- `vm WHERE host_id = ? AND deleted = 0` — uses `fk_vm_host` (`type: ref`) ✓
- `vm WHERE subscription_line_item_id = ?` — uses `idx_vm_subscription_line_item` ✓
- `vm_ip_assignment WHERE vm_id = ? AND deleted = 0` — uses `fk_vm_ip_assignment_vm` ✓
- `vm_ip_assignment WHERE ip_range_id = ? AND deleted = 0` — uses `fk_vm_ip_range` ✓
- `subscription WHERE is_active = 1 AND expires < NOW()` — uses `idx_subscription_active` (`type: ref`) with `Using where` post-filter on `expires` ✓ (composite would be better but not critical)
- `subscription_payment WHERE subscription_id = ?` — uses `idx_subscription_payment_subscription` ✓
- `subscription_payment WHERE external_id = ?` — uses `idx_subscription_payment_external_id` ✓
- `payment_method_config WHERE company_id = ?` — uses `idx_company_id` ✓
- `nostr_domain WHERE activation_hash = ?` — uses `ix_nostr_domain_activation_hash` ✓
- `vm expired via subscription JOIN` — uses `idx_subscription_expires`, `idx_line_item_subscription`, `idx_vm_subscription_line_item` ✓
- `base_currency for vm` (4-table JOIN by PK) — all `const` lookups ✓
- `ip_range_subscription by subscription_id` (via sli JOIN) — uses `idx_ip_range_subscription_line_item` ✓

### Corrections to prior findings
- **`vm WHERE user_id`** — EXPLAIN shows `fk_vm_user` index IS used (`type: ref`). The prior finding
  that there was no index on `user_id` was incorrect; the FK implicitly creates the index.
- **`vm WHERE host_id`** — Same: `fk_vm_host` index IS used. No new index needed for these two.
- **`payment_method_config WHERE company_id = ? AND enabled = TRUE`** — uses `idx_company_id`
  (`type: ref`) then filters `enabled` with `Using where`. A composite `(company_id, enabled)` would
  cover both predicates but the current plan is already a ref lookup; lower priority than originally
  assessed. The real gap is the ORDER BY sort, not the filter.
- **`vm_payment WHERE vm_id = ?`** — `fk_vm_payment_vm` index already exists and is used ✓.
  The prior task "Add index `vm_id` on `vm_payment`" was wrong; index already present.
- **`user_ssh_key WHERE user_id = ?`** — `fk_ssh_key_user` index already exists ✓.
  Prior task "Add index `user_id` on `user_ssh_key`" was wrong.
- **`ip_range WHERE region_id = ?`** — `fk_ip_range_region` already used ✓.
  "Add composite `(region_id, enabled)` on `ip_range`" still valid for the `enabled` filter.
- **`nostr_domain WHERE owner_id = ?`** — `fk_nostr_domain_user` already used ✓.
  "Add index `owner_id` on `nostr_domain`" is wrong; index already present.
- **`admin_roles` `idx_name`** — EXPLAIN shows `admin_roles` by name uses the UNIQUE KEY.
  Confirmed duplicate; drop task remains valid.
- **`admin_role_assignments` `idx_user_id`** — prefix of UNIQUE KEY confirmed; drop task valid.
- **`admin_role_permissions` `idx_role_id`** — confirmed prefix of unique composite; drop task valid.
- **`ix_vm_history_action_type`** — confirmed unused by EXPLAIN; drop task valid.

### Correctness bug
- `get_subscription_base_currency` in `mysql.rs` uses an incorrect JOIN:
  `JOIN company c ON u.id = c.id` should be `JOIN company c ON s.company_id = c.id`.
  This returns wrong or no results on every call. Must be fixed before any payment-related work.

### N+1 patterns identified
1. `admin_list_hosts_with_regions_paginated` (`mysql.rs` ~line 3459): fetches N hosts then loops,
   issuing one `SELECT FROM vm_host_disk WHERE host_id = ?` per host.
2. `check_vms` worker (`worker.rs` ~line 612): fetches all active VMs then issues 2 round-trips per
   VM (`get_subscription_line_item` + `get_subscription`) to check `is_setup`.
3. `vm_expires()` (`worker.rs` ~line 443): does `get_subscription_line_item` + `get_subscription`
   per VM on every non-hypervisor-found VM — not batched.
4. `handle_subscription_state` (`worker.rs` ~line 238): O(N×M) subscription → line-item → VM chain;
   acceptable today but worth batching if subscription counts grow.

### Indexes confirmed useless / to be dropped
- `ix_user_email` on `users.email` — column is encrypted ciphertext, never used in a WHERE clause.
  Also invalid DDL: `20260220165223` recreated this index on a `TEXT` column without a prefix length,
  which is invalid in MariaDB. The index likely does not exist on any DB that ran migrations in order.
- Duplicate `idx_name` on `admin_roles` — the UNIQUE KEY already creates this B-tree index.
- `idx_role_id` on `admin_role_permissions` — prefix of the composite UNIQUE KEY `(role_id, resource, action)`.
- `idx_user_id` on `admin_role_assignments` — prefix of the UNIQUE KEY `(user_id, role_id)`.
- `idx_active` on `admin_role_assignments` — the `is_active` column was dropped by `20250809000000`;
  verify MariaDB auto-dropped this index (it should when the column is dropped).
- `ix_vm_history_action_type` on `vm_history` — all `vm_history` queries filter only by `vm_id`;
  this index is never used and adds write overhead (EXPLAIN confirmed).

### Data integrity issues
- `vm.subscription_line_item_id` is `NULL`-able in the DB (added nullable by `20260302151134`) but
  mapped as non-optional `u64` in the Rust `Vm` struct — any row with NULL causes a deserialization
  panic. A NOT NULL migration must be applied after verifying the data migration binary has run.
- `VmForMigration` struct in `model.rs` still references `expires` and `auto_renewal_enabled`, both
  of which were dropped by `20260304000000`. This struct will panic at deserialization if used
  post-migration.
- `vm` has no CHECK constraint enforcing exactly one of `template_id` / `custom_template_id`.
- `vm.ref_code` has no FK to `referral.code` — referral attribution can silently diverge.
  Also confirmed: no index on `vm.ref_code` (EXPLAIN shows full scan on referral revenue query).

### Anti-patterns (lower priority)
- `vm_payment.id` / `subscription_payment.id` declared with UNIQUE INDEX instead of PRIMARY KEY —
  InnoDB uses a hidden rowid as the clustered key with an extra pointer dereference on every lookup.
- `vm_payment.rate` and `subscription_payment.rate` both stored as `FLOAT` — precision risk in
  monetary calculations.
- `payment_method_config.supported_currencies` and `nostr_domain*.relays` stored as comma-separated
  strings — never SQL-filtered so no index is possible; filtering/splitting done entirely in Rust.
- Broken FK in `init.sql`: `fk_template_region` on `vm_template` points at `vm_template.id` instead
  of `vm_host_region.id`. Corrected in migration `20250306113236` but the init migration is
  permanently wrong on a fresh replay.

### Confirmed NOT needed (re-verified by EXPLAIN)
- Additional index on `vm.user_id` — already covered by `fk_vm_user` FK index.
- Additional index on `vm.host_id` — already covered by `fk_vm_host` FK index.
- Additional index on `vm_payment.vm_id` — already covered by `fk_vm_payment_vm` FK index.
- Additional index on `user_ssh_key.user_id` — already covered by `fk_ssh_key_user` FK index.
- Additional index on `nostr_domain.owner_id` — already covered by `fk_nostr_domain_user` FK index.
- Additional index on `nostr_domain_handle.domain_id` — covered by leftmost prefix of `UNIQUE KEY ix_domain_handle_unique (domain_id, handle)`.
- Additional index on `nostr_domain.activation_hash` — already `ix_nostr_domain_activation_hash`.
- Additional index on `subscription.user_id` — already `idx_subscription_user`.
- Additional index on `subscription_payment.external_id` — already created in `20260127000000`.
- Additional index on `referral_payout.referral_id` — covered by FK implicit index.
- Index on `referral_payout.is_paid` — not used as a WHERE filter anywhere.
- Composite `(region_id, enabled)` on `vm_host` — hosts are a tiny table; full scan is fine.
- Normalizing `supported_currencies` or `relays` columns — opaque to SQL; no query benefit.
- Index on `subscription.company_id` — not filtered directly on the subscription table.

## Tasks

### Increment 0 — Correctness bug: get_subscription_base_currency wrong JOIN
- [ ] Fix `get_subscription_base_currency` in `mysql.rs`: change `JOIN company c ON u.id = c.id` to `JOIN company c ON s.company_id = c.id`

### Increment 1 — Critical: subscription_line_item_id NOT NULL migration
- [ ] Fix `VmForMigration` struct in `model.rs`: remove `expires` and `auto_renewal_enabled` fields (dropped by `20260304000000`)
- [ ] Verify data migration binary has been run on all environments (all `vm` rows have a non-NULL `subscription_line_item_id`)
- [ ] Create migration to add the NOT NULL constraint on `vm.subscription_line_item_id` (the nullable column was added by `20260302151134`)

### Increment 2 — High-priority indexes (full table scans on hot paths)
*EXPLAIN confirmed — these are the real full-scan gaps after correcting the prior analysis.*
- [ ] Add index `email_verify_token` on `users` — full scan on every email verification click
- [ ] Add index `deleted` on `vm` — full scan on bulk VM queries and admin derived subqueries
- [ ] Add index `ref_code` on `vm` — full scan on referral revenue and unpaid-vm-count queries
- [ ] Add index `ip` on `vm_ip_assignment` — full scan on IP conflict checks before insert/update
- [ ] Add index `external_id` on `vm_payment` — full scan on legacy payment lookup by external id
- [ ] Add composite index `(is_paid, created)` on `vm_payment` — eliminates full scan + filesort on `WHERE is_paid=true ORDER BY created DESC`
- [ ] Add index `enabled` on `ip_range` — full scan on `WHERE enabled = 1` (range listing)
- [ ] Add composite index `(company_id, payment_method, name)` on `payment_method_config` — eliminates full scan + filesort on list-all query; also covers existing `WHERE company_id=?` and `WHERE company_id=? AND payment_method=?` lookups (replaces `idx_company_id`)

### Increment 3 — Medium-priority: sort indexes (filesort elimination)
*EXPLAIN confirmed — index exists on filter column but ORDER BY column not covered.*
- [ ] Add composite index `(vm_id, created)` on `vm_payment` — eliminates filesort on `WHERE vm_id=? ORDER BY created DESC`
- [ ] Add composite index `(vm_id, timestamp)` on `vm_history` — eliminates filesort on `WHERE vm_id=? ORDER BY timestamp DESC`; also makes `ix_vm_history_vm_id` and `ix_vm_history_timestamp` redundant (drop in Increment 4)
- [ ] Add composite index `(subscription_id, created)` on `subscription_payment` — eliminates filesort on payment history queries
- [ ] Add composite index `(user_id, created)` on `subscription_payment` — eliminates filesort on user payment history
- [ ] Add composite index `(is_paid, created)` on `subscription_payment` — eliminates filesort on latest-paid lookup
- [ ] Add composite index `(is_active, expires)` on `subscription` — replaces filter+post-scan on background worker expiry loop; makes `idx_subscription_active` and `idx_subscription_expires` redundant (drop in Increment 4)
- [ ] Add index `created` on `available_ip_space` — eliminates filesort on `ORDER BY created DESC` full list

### Increment 4 — Remove redundant / invalid indexes
*EXPLAIN confirmed — all of these are either unused or prefixes of composite keys.*
- [ ] Drop `ix_user_email` on `users` (indexes encrypted ciphertext; never used in WHERE; invalid DDL without prefix length — index may already be absent on migrated DBs)
- [ ] Drop `idx_name` on `admin_roles` (duplicate of UNIQUE KEY — EXPLAIN confirms UNIQUE KEY is used)
- [ ] Drop `idx_role_id` on `admin_role_permissions` (prefix of composite UNIQUE KEY `(role_id, resource, action)` — EXPLAIN confirms composite is used)
- [ ] Drop `idx_user_id` on `admin_role_assignments` (prefix of UNIQUE KEY `(user_id, role_id)` — EXPLAIN confirms UNIQUE KEY is used)
- [ ] Verify and drop (if present) `idx_active` on `admin_role_assignments` (column `is_active` was dropped by `20250809000000`)
- [ ] Drop `ix_vm_history_action_type` on `vm_history` (EXPLAIN confirmed: never used; all history queries filter by `vm_id` only)
- [ ] Drop `ix_vm_history_vm_id` and `ix_vm_history_timestamp` after adding composite `(vm_id, timestamp)` in Increment 3
- [ ] Drop `idx_subscription_active` and `idx_subscription_expires` after adding composite `(is_active, expires)` in Increment 3
- [ ] Drop `idx_company_id` on `payment_method_config` after adding composite `(company_id, payment_method, name)` in Increment 2

### Increment 5 — Data integrity: vm table
- [ ] Add CHECK constraint on `vm`: exactly one of `template_id` / `custom_template_id` is non-NULL (requires MariaDB 10.2.1+)
- [ ] Add FK `vm.ref_code → referral.code` or document intentional denormalization with a comment

### Increment 6 — N+1 query fixes
- [ ] Fix `admin_list_hosts_with_regions_paginated`: batch-load `vm_host_disk` rows with `WHERE host_id IN (...)` instead of per-host loop
- [ ] Fix `check_vms` worker: replace 2-per-VM round-trips with a single JOIN query (`vm → subscription_line_item → subscription`) to read `is_setup` in one shot
- [ ] Fix `vm_expires()` in worker: replace `get_subscription_line_item` + `get_subscription` round-trips with a single JOIN query to get `subscription.expires` for a VM

### Increment 7+8 — vm_payment / subscription_payment primary key promotion and rate precision
> **Note:** Combine into one `ALGORITHM=COPY` table rebuild per table to avoid two full rebuilds.
- [ ] Promote `vm_payment.id` from UNIQUE INDEX to PRIMARY KEY and change `vm_payment.rate` from `FLOAT` to `DECIMAL(18, 8)` in the same migration (table rebuild required; low-traffic window)
- [ ] Promote `subscription_payment.id` from UNIQUE INDEX to PRIMARY KEY and change `subscription_payment.rate` from `FLOAT` to `DECIMAL(18, 8)` in the same migration

## Notes

- All migrations must follow project conventions: `NOT NULL DEFAULT <value>` for new columns,
  pure DDL only (no DML in migrations). See `docs/agents/migrations.md`.
- Increments 2–4 are all `ALGORITHM=INPLACE, LOCK=NONE` safe on MariaDB InnoDB — they can be
  deployed without downtime.
- Increment 7+8 requires a full table rebuild (`ALGORITHM=COPY`); plan for a maintenance window.
- The FLOAT→BIGINT×100 conversion in migration `20260217100000` may have silently corrupted BTC-
  denominated `vm_cost_plan` rows due to IEEE 754 rounding. Verify before proceeding with any payment-related changes.
- `payment_method_config.supported_currencies` and `nostr_domain*.relays` are confirmed opaque CSV
  strings filtered entirely in Rust — normalization would require API changes and is not prioritised.
- Increment 0 (JOIN bug fix) must precede Increment 7+8 (exchange rate precision work) since rate
  calculations depend on correctly resolving the base currency.
- Increment 1's NOT NULL constraint is a hard gate: the data migration binary must be verified
  complete on all environments before applying the DDL.
- **Prior task corrections (2026-03-10 EXPLAIN pass):** The tasks "Add index `vm_id` on `vm_payment`",
  "Add index `user_id` on `user_ssh_key`", "Add composite `(user_id, deleted)` on `vm`",
  "Add composite `(host_id, deleted)` on `vm`", "Add index `owner_id` on `nostr_domain`",
  "Add composite `(region_id, enabled)` on `vm_host`", and "Add composite `(region_id, enabled)`
  on `ip_range`" were all removed because EXPLAIN confirmed the required indexes already exist via FK
  constraints or prior migrations. Increment 2 and 3 now reflect only the genuine gaps.
