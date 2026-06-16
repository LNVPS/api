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
  model already types the field as non-nullable (`u64`), and all provisioning paths set it.
- `20260304000000_drop_vm_expires.sql` — Removes `vm.expires` and `vm.auto_renewal_enabled`.
  Expiry is now read exclusively from `subscription.expires`, and auto-renewal is managed via
  `subscription.auto_renewal_enabled`.

**Data migration** (must be run manually):

```bash
cargo run --bin migrate_vm_subscriptions -- --database-url <URL>
# Dry-run first:
cargo run --bin migrate_vm_subscriptions -- --database-url <URL> --dry-run
```

The binary iterates all VMs that do not yet have a `subscription_line_item_id` set, creates a
`subscription` + `subscription_line_item` (type `VmRenewal`) for each, and links the VM. It is
idempotent — VMs that already have a subscription are skipped.

**Finalization** (after production verification — do not run until confirmed):

Once the data migration has been verified in production and all new VMs are going through the
subscription path:

```sql
-- Enforce the link at the DB level (Rust already treats it as non-nullable)
ALTER TABLE vm MODIFY subscription_line_item_id INTEGER UNSIGNED NOT NULL;

-- Drop the legacy payment table
DROP TABLE vm_payment;
```
