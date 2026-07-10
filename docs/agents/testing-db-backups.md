# Testing Changes Against a Production Database Backup

This describes how to safely test branch changes (schema migrations, data
migrations, startup behaviour) against a **real production database dump** without
ever touching real infrastructure or notifying real users.

The golden rules:

1. **Never** run against the live DB or the shared dev DB — always restore into a
   throwaway database.
2. **Sanitise before running anything**: swap all hosts to the mock (`Dummy`) kind,
   wipe user contact preferences, and neutralise encrypted secrets.
3. Point every external integration (DNS providers, routers, lightning) at
   something local/inert so no real API is ever called.

## Prerequisites

- Docker running with the project MariaDB (`docker compose up -d db`, port `3376`,
  `root`/`root`).
- A production dump, e.g. `~/lnvps-YYYYMMDDHHMMSS.sql.gz` (a `mariadb-dump` of the
  `lnvps` database).
- **Encryption key caveat.** Production encrypts sensitive columns (`ENC:` prefix)
  with a key you almost certainly don't have locally. Two options:
  - **Recommended:** neutralise the encrypted columns (step 2c) so the app can read
    them as plaintext with a locally auto-generated key. Safe because hosts are
    `Dummy` and external URLs are inert.
  - Or, if you have the production `encryption.key`, place it where `config.yaml`'s
    `encryption.key-file` points and skip step 2c (rows decrypt normally).

## Step 1 — Restore into an isolated database

Never reuse the dev `lnvps` schema; restore into a separate database name.

```bash
gunzip -c ~/lnvps-YYYYMMDDHHMMSS.sql.gz > /tmp/lnvps_backup.sql

docker exec lnvps_api-db-1 mariadb -uroot -proot \
  -e "DROP DATABASE IF EXISTS lnvps_restore; CREATE DATABASE lnvps_restore CHARACTER SET utf8mb4;"

docker exec -i lnvps_api-db-1 mariadb -uroot -proot lnvps_restore < /tmp/lnvps_backup.sql

# sanity check
docker exec lnvps_api-db-1 mariadb -uroot -proot lnvps_restore -e \
  "SELECT (SELECT COUNT(*) FROM vm) vms, (SELECT COUNT(*) FROM users) users, \
          (SELECT COUNT(*) FROM vm_host) hosts, (SELECT COUNT(*) FROM ip_range) ranges;"
```

## Step 2 — Sanitise the restored data

Run this **before** pointing any app at the database. It is idempotent.

```sql
-- 2a) Make every host the Dummy/mock kind. The Dummy host (VmHostKind::Dummy = 65535)
--     answers all hypervisor calls in-memory, so no real Proxmox/libVirt is contacted.
UPDATE vm_host SET kind = 65535, api_token = 'mock', ssh_key = NULL;

-- 2b) Wipe contact preferences so NO real user can ever be notified.
UPDATE users SET contact_nip17 = 0, contact_email = 0, email = '', nwc_connection_string = NULL;

-- 2c) Neutralise remaining encrypted secrets (skip only if you have the prod key).
--     Every encrypted value has an 'ENC:' prefix. Replace with safe plaintext dummies.
UPDATE router        SET token    = 'mock:mock:mock';                       -- app_key:app_secret:consumer_key shape
UPDATE user_ssh_key  SET key_data = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleBackupTestKeyOnly';
UPDATE vm_payment    SET external_data = '' WHERE external_data LIKE 'ENC:%';
-- If present in your dump, also blank any other ENC: columns (e.g. payment_method_config.config).

-- 2d) Point external integrations at inert endpoints so any stray call fails instantly
--     (connection refused) instead of hitting real OVH/Cloudflare/Mikrotik APIs.
UPDATE router SET url = 'http://127.0.0.1:1';
```

Verify nothing is left that startup would try to decrypt or call:

```sql
SELECT COUNT(*) FROM users     WHERE contact_nip17 = 1 OR contact_email = 1;   -- expect 0
SELECT COUNT(*) FROM vm_host   WHERE kind <> 65535;                            -- expect 0
SELECT COUNT(*) FROM router    WHERE token LIKE 'ENC:%';                       -- expect 0
SELECT COUNT(*) FROM user_ssh_key WHERE key_data LIKE 'ENC:%';                 -- expect 0
```

## Step 3 — Make the VMs appear "up"

The persistent Dummy host reads its VM state from `/tmp/lnvps_dummy_vms.json`
(`HashMap<vm_id, MockVm>`). Seed every VM as `running` so the worker doesn't try to
(re)provision them and status APIs report healthy VMs:

```bash
NOW=$(date +%s)
docker exec lnvps_api-db-1 mariadb -uroot -proot lnvps_restore -N -B \
  -e "SELECT id FROM vm WHERE deleted = 0" \
| awk -v now="$NOW" 'BEGIN{printf "{"} {printf "%s\"%s\":{\"state\":\"running\",\"uptime_secs\":3600,\"net_in\":0,\"net_out\":0,\"disk_read\":0,\"disk_write\":0,\"last_tick\":%s}", (NR>1?",":""), $1, now} END{printf "}"}' \
> /tmp/lnvps_dummy_vms.json

# (If you skip this, the worker will still only ever create/start VMs *in-memory*
#  on the Dummy host — never on real hardware — but reconciliation is slow.)
```

## Step 4 — Apply migrations

Migrations (`db.migrate()`, embedded `sqlx::migrate!()`) are pure DDL — no
decryption, no external calls — so this is the safe, high-value check that your
branch's schema migrations apply cleanly on top of real production data.

The quickest way without extra tooling is a tiny throwaway binary. Create
`lnvps_api/src/bin/_backup_migrate.rs` (delete it afterwards — do **not** commit it):

```rust
use lnvps_db::{LNVpsDbBase, LNVpsDbMysql};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = LNVpsDbMysql::new(&url).await?;
    db.migrate().await?;
    println!("OK: all schema migrations applied cleanly");
    Ok(())
}
```

```bash
DATABASE_URL="mysql://root:root@localhost:3376/lnvps_restore" \
  cargo run -q -p lnvps_api --bin _backup_migrate
rm lnvps_api/src/bin/_backup_migrate.rs
```

A clean run proves your migration (and every migration newer than the dump) applies
to real prod data — FK constraints, column types, and data volume included.

Then inspect the resulting schema / preview what a data migration will touch, e.g.:

```sql
-- new columns/tables added by your migration
SHOW TABLES LIKE 'dns_server';
SHOW COLUMNS FROM ip_range WHERE Field LIKE '%dns_server_id';

-- e.g. which ranges are OVH-routed (what the DNS data migration will map)
SELECT r.id, r.cidr, rt.name router, rt.kind
FROM ip_range r
JOIN access_policy ap ON r.access_policy_id = ap.id
JOIN router rt ON ap.router_id = rt.id
WHERE rt.kind = 1;
```

## Step 5 — (Optional) Run the full app against the backup

Running the real binary also exercises the **data migrations** and worker. It
additionally needs redis and a lightning node — point them at your local dev
instances. Copy `lnvps_api/config.yaml`, then set `db:` to the restored database:

```yaml
db: "mysql://root:root@localhost:3376/lnvps_restore"
read-only: true          # extra safety: avoids provisioning side effects
# lightning/redis: point at local regtest / local redis
# encryption: auto-generate a local key (works because step 2c removed ENC: values)
```

With steps 2–3 done, this is side-effect-free: hosts are `Dummy`, users are
un-notifiable, external URLs are inert (calls fail fast and are handled
best-effort), and VMs report `running`. Data migrations that make outbound calls
(e.g. DNS record backfill) will log warnings on the inert URLs and continue.

> Note: data migrations that read encrypted columns require step 2c (or the real
> key). Some (e.g. the vm_payment → subscription backfill) decode `external_data`;
> blanking it to `''` keeps startup moving for a test.

## Step 6 — Clean up

```bash
docker exec lnvps_api-db-1 mariadb -uroot -proot -e "DROP DATABASE lnvps_restore;"
rm -f /tmp/lnvps_backup.sql /tmp/lnvps_dummy_vms.json
# ensure no throwaway bin was committed
git status --porcelain | grep _backup_migrate || true
```

## Checklist (paste-ready summary)

- [ ] Restored into `lnvps_restore` (not `lnvps`).
- [ ] `vm_host.kind` all = `65535` (Dummy).
- [ ] `users.contact_nip17` / `contact_email` all = `0`.
- [ ] No `ENC:` values remain (or the real key is in place).
- [ ] `router.url` repointed to an inert endpoint.
- [ ] `/tmp/lnvps_dummy_vms.json` seeded (VMs report running).
- [ ] `db.migrate()` ran clean.
- [ ] Throwaway migrate bin deleted, DB dropped afterwards.
