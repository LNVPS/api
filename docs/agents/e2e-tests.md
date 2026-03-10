# E2E Integration Tests

## Overview

The `lnvps_e2e` crate contains end-to-end integration tests that run against live local API servers. Tests exercise real HTTP endpoints with NIP-98 authentication and verify the full request/response cycle.

**These tests are NOT run during Docker image builds.** They run in a dedicated CI workflow (`e2e.yml`) on pull requests, and can also be run locally.

## Running

### Using the script (recommended)

`scripts/run-e2e.sh` handles everything: starts docker infrastructure, waits for LND, creates the per-run database, patches the API configs, builds and starts both API servers, runs the tests, and tears everything down on exit.

```bash
# Full run (start docker, build, run all tests, stop docker)
./scripts/run-e2e.sh

# Skip rebuild if binaries are already up to date
./scripts/run-e2e.sh --no-build

# Run only the lifecycle test
./scripts/run-e2e.sh --filter lifecycle

# Leave API servers and docker running after the run (for debugging)
./scripts/run-e2e.sh --no-cleanup
```

### Script options

| Flag | Description |
|---|---|
| `--no-build` | Skip `cargo build` step |
| `--no-cleanup` | Leave API servers and DB running after the run |
| `--filter FILTER` | Pass a test-name filter to `cargo test` (e.g. `lifecycle`) |
| `--run-id ID` | Override the run ID (default: current timestamp) |

### Unit tests only (no API servers needed)

```bash
# Docker still required for the DB connection in unit tests
docker compose up -d
cargo test --workspace --exclude lnvps_e2e -- --test-threads=1
```

Do NOT set `LNVPS_DEV_SETUP=1` — the lifecycle test creates and cleans up all its own infrastructure. The `dev_setup.sql` script inserts data that can conflict.

## Per-run Database Isolation

Each test process creates its own temporary database named `lnvps_e2e_{run_id}` and drops it at the end of the lifecycle test. This prevents test runs from polluting the main `lnvps` database.

- In CI the run ID is `${{ github.run_id }}_${{ github.run_attempt }}` (set as `LNVPS_E2E_RUN_ID`).
- Locally, if `LNVPS_E2E_RUN_ID` is not set, the current Unix timestamp in milliseconds is used.
- The database is created automatically the first time any test calls `db::connect()`.
- The lifecycle test drops the database at the end of its cleanup section.

The API servers must be configured to connect to the same per-run database. In CI this is done by the workflow step that patches the API config files before starting the servers.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LNVPS_API_URL` | `http://localhost:8000` | User API base URL |
| `LNVPS_ADMIN_API_URL` | `http://localhost:8001` | Admin API base URL |
| `LNVPS_DB_BASE_URL` | *(derived from `LNVPS_DB_URL`)* | DB server URL without database name, e.g. `mysql://root:root@localhost:3376`. Used to create/drop the per-run database. |
| `LNVPS_DB_URL` | `mysql://root:root@localhost:3376/lnvps` | Full DB URL — only used to derive `LNVPS_DB_BASE_URL` when the latter is not set. |
| `LNVPS_E2E_RUN_ID` | *(current timestamp ms)* | Unique ID for this test run; determines the per-run DB name `lnvps_e2e_{run_id}`. |
| `NOSTR_SECRET_KEY` | *(random)* | Hex Nostr secret key for user identity |
| `ADMIN_NOSTR_SECRET_KEY` | *(random)* | Hex Nostr secret key for admin identity |

When secret keys are not set, random keys are generated per process. The admin user is bootstrapped in the DB with the `super_admin` role automatically.

## Architecture

### Modules

| Module | Purpose |
|---|---|
| `client.rs` | `TestClient` with NIP-98 auth, response parsing helpers, factory functions |
| `db.rs` | Direct MySQL access for bootstrapping users/roles and hard-deleting test data |
| `nip98.rs` | NIP-98 Authorization header generation |
| `user_api.rs` | Tests for all user-facing API endpoints |
| `admin_api.rs` | Tests for all admin API endpoints including CRUD lifecycles |
| `rbac.rs` | RBAC permission tests (no-role, read_only, vm_manager, payment_manager, super_admin) |
| `lifecycle.rs` | Full end-to-end lifecycle test (see below) |

### Key design decisions

- **Stable per-process identities**: User and admin keys are created once via `OnceLock` so all tests share the same identity. RBAC tests use one stable key per role.
- **DB bootstrap**: The admin user's `super_admin` role is assigned via direct DB insert (`db::ensure_user_with_role`), not through the API. This avoids chicken-and-egg auth problems.
- **Hard-deletes for cleanup**: The lifecycle test creates fake infrastructure (hosts, VMs) that the async worker cannot clean up (no real hypervisor). All cleanup is done via direct `DELETE FROM` SQL to avoid soft-delete orphans.
- **Clean DB compatible**: All tests handle empty result sets gracefully. Tests that need data (e.g., VM operations) skip with a message when none exists.
- **Re-runnable**: The lifecycle test uses timestamp-suffixed names for all resources so it can run repeatedly without conflicts.

## Lifecycle Test (`lifecycle.rs`)

The `test_full_lifecycle` test builds every infrastructure layer from scratch and exercises the complete VM lifecycle:

1. **Create company** (admin API)
2. **Create region** (admin API)
3. **Create cost plan** (admin API)
4. **Create OS image** (admin API)
5. **Create host + disk** (admin API)
6. **Create IP range** (admin API)
7. **Create VM template** (admin API)
8. **Create custom pricing** (admin API)
9. **Verify templates/images visible** from user API
10. **Create SSH key** (user API)
11. **Referral flow**: create referrer, sign up for referrals, verify validation errors
12. **Order VM with referral code** (user API)
13. **Renew VM** → creates unpaid payment (user API)
14. **Admin completes payment** → marks paid, extends expiry (admin API)
15. **Verify referral earnings** — referrer sees 1 success with BTC amount
16. **Admin referral report** — time-series report includes the referred VM
17. **Upgrade quote** (user API)
18. **Execute upgrade** → creates upgrade payment (user API)
19. **Admin completes upgrade payment** (admin API)
20. **Admin actions**: stop, start, disable (verify `disabled=true`), enable (verify `disabled=false`), extend
21. **Verify payment history** and **VM history**
22. **Custom VM order** with custom pricing → renew → admin complete payment
23. **Cleanup**: hard-delete all resources via direct DB access

## Adding New E2E Tests

### Testing a new user API endpoint

Add to `user_api.rs`. Use `user_client()` for authenticated or `user_client_no_auth()` for unauthenticated:

```rust
#[tokio::test]
async fn test_my_new_endpoint() {
    let client = user_client();
    let resp = client.get_auth("/api/v1/my-endpoint").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
```

### Testing a new admin API endpoint

Add to `admin_api.rs`. Use `setup().await` to bootstrap the admin user:

```rust
#[tokio::test]
async fn test_admin_my_endpoint() {
    let client = setup().await;
    let resp = client.get_auth("/api/admin/v1/my-endpoint").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
```

### Testing RBAC for a new resource

Add assertions to `rbac.rs` using the existing per-role key functions:

```rust
#[tokio::test]
async fn test_read_only_can_view_my_resource() {
    setup_rbac().await;
    let client = admin_client_with_keys(read_only_keys().clone());
    let resp = client.get_auth("/api/admin/v1/my-resource").await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
```

### Adding to the lifecycle test

If a new feature involves infrastructure or VM state, add it to `lifecycle.rs`:

1. **Create** the resource in the setup section (keep numbered comments sequential)
2. **Exercise** the feature in the test body
3. **Hard-delete** the resource in the cleanup section (add a `hard_delete_*` function to `db.rs` if the admin API soft-deletes it)

### DB cleanup helpers

When the admin API soft-deletes a resource (sets `enabled=false` or `deleted=true` instead of `DELETE FROM`), add a `hard_delete_*` function to `db.rs`:

```rust
pub async fn hard_delete_my_resource(pool: &MySqlPool, id: u64) -> anyhow::Result<()> {
    // Delete dependent rows first
    sqlx::query("DELETE FROM child_table WHERE parent_id = ?")
        .bind(id).execute(pool).await?;
    sqlx::query("DELETE FROM my_resource WHERE id = ?")
        .bind(id).execute(pool).await?;
    Ok(())
}
```

## CI Workflow

The `.github/workflows/e2e.yml` workflow runs E2E tests on every pull request. It installs dependencies, then delegates entirely to `scripts/run-e2e.sh` with `LNVPS_E2E_RUN_ID` set to `${{ github.run_id }}_${{ github.run_attempt }}`. The script:

1. Starts infrastructure via `docker-compose.e2e.yaml` (MariaDB, Redis, bitcoind regtest, LND)
2. Waits for LND to be ready and copies TLS cert + macaroon to the host
3. Mines 101 blocks so LND has spendable funds
4. Creates the per-run database `lnvps_e2e_{run_id}`
5. Writes temporary API configs pointing at the per-run database
6. Builds and starts both API servers
7. Runs `cargo test -p lnvps_e2e -- --test-threads=1`
8. Tears down API servers and docker containers on exit

### CI files

| File | Purpose |
|---|---|
| `.github/workflows/e2e.yml` | GitHub Actions workflow (thin wrapper around the script) |
| `scripts/run-e2e.sh` | Full runner script used by CI and local development |
| `docker-compose.e2e.yaml` | Compose file with DB, Redis, bitcoind, LND |
| `.github/e2e/api-config.yaml` | User API config template (DB URL replaced at runtime) |
| `.github/e2e/admin-config.yaml` | Admin API config template (DB URL replaced at runtime) |
| `.github/e2e/wait-for-lnd.sh` | Script to wait for LND readiness and mine initial blocks |
