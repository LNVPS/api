# Database Migrations

## Timestamp Rules

**CRITICAL:** Migration filenames must have unique timestamps (full 14-digit `YYYYMMDDHHMMSS`). Before creating or modifying a migration:

1. **Check existing timestamps** — Run `ls lnvps_db/migrations/` and verify your full timestamp doesn't conflict
2. **After rebasing** — If your branch adds migrations, check that the timestamps don't collide with migrations added to master
3. **Use the current timestamp** — Generate with `date +%Y%m%d%H%M%S`

Migration format: `YYYYMMDDHHMMSS_description.sql`

Example conflict to avoid:
```
20260219000000_cpu_type.sql            # from master
20260219000000_email_verification.sql  # CONFLICT — same full timestamp!
```

Fix by using a completely unique timestamp:
```
20260219000000_cpu_type.sql
20260221120000_email_verification.sql  # different date AND time
```

## Migration Best Practices

- Use `NOT NULL DEFAULT <value>` for new columns to avoid breaking existing rows
- Test migrations against a database with production-like data
- Never modify a migration that has already been applied to any environment

## Notable Migrations

### vm_payment → subscription_payment (2026-03-02)

Two schema migrations and a data migration binary were added as part of migrating VM payments
from the legacy `vm_payment` table to the unified `subscription_payment` table.

**Schema migrations** (applied automatically by sqlx at startup):

- `20260302151134_vm_subscription_link.sql` — Adds `subscription_line_item_id` to `vm`; adds
  `interval_amount`/`interval_type` back to `subscription`; adds `time_value`/`metadata` to
  `subscription_payment`. All new columns have safe defaults so existing rows are unaffected.
  `vm.subscription_line_item_id` is added **nullable** so the data migration can backfill existing
  rows; the DB-level `NOT NULL` constraint is deferred to finalization (see below). The Rust `Vm`
  model already types the field as non-nullable (`u64`), and all provisioning paths set it. This
  migration also **relaxes** the legacy `vm.expires` (now nullable) and `vm.auto_renewal_enabled`
  (now `DEFAULT 0`) columns so new VM inserts — which no longer write those columns — succeed
  while the legacy data is preserved for the backfill.

**Ordering invariant (critical):** the legacy `vm.expires`, `vm.auto_renewal_enabled`, and
`vm.created` columns must NOT be dropped until *after* the startup backfill has run and been
verified in production. The backfill reads `vm.expires` and `vm.auto_renewal_enabled` to populate
`subscription.expires` / `subscription.auto_renewal_enabled`. Dropping these columns first (as an
earlier revision of this branch did via `20260304000000_drop_vm_expires.sql` /
`20260310000000_drop_vm_created.sql`) makes the backfill fail for every VM and discards all billing
expiry. Those drops have been moved into the finalization step below.

**Data migration** (runs automatically at startup):

The backfill runs unconditionally during app startup, immediately after schema migrations and
*before* `run_data_migrations` (see `lnvps_api/src/data_migration/vm_subscription_backfill.rs`,
called from `bin/api.rs`). This ordering is mandatory: `run_data_migrations` and every VM read
decode the non-nullable `vm.subscription_line_item_id`, which is `NULL` for pre-migration rows
until the backfill links them — so the app would be broken for all existing VMs in any window where
it served traffic before the backfill completed. Running it inside startup eliminates that window.

The backfill iterates all VMs that do not yet have a `subscription_line_item_id` set, creates a
`subscription` + `subscription_line_item` (type `Vps`) for each, and links the VM. It copies the
VM's `expires` into `subscription.expires` and `auto_renewal_enabled` into
`subscription.auto_renewal_enabled` so billing/renewal enforcement continues seamlessly. Phase 2
copies every `vm_payment` into `subscription_payment`. It is idempotent — VMs already linked and
payments already copied are skipped — so it is safe to run on every boot. If any VM or payment
fails, startup aborts so the issue is surfaced before the app serves traffic.

**Finalization** (after production verification — do not run until confirmed):

Once the data migration has been verified in production and all new VMs are going through the
subscription path:

```sql
-- Enforce the link at the DB level (Rust already treats it as non-nullable)
ALTER TABLE vm MODIFY subscription_line_item_id INTEGER UNSIGNED NOT NULL;

-- Drop the legacy expiry/auto-renewal/created columns now that subscription.expires
-- and subscription.auto_renewal_enabled are authoritative and backfilled.
ALTER TABLE vm DROP COLUMN expires, DROP COLUMN auto_renewal_enabled;
ALTER TABLE vm DROP COLUMN created;

-- Drop the legacy payment table
DROP TABLE vm_payment;
```
