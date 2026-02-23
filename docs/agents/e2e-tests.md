# E2E Integration Tests

## Overview

The `lnvps_e2e` crate contains end-to-end integration tests that run against live local API servers. Tests exercise real HTTP endpoints with NIP-98 authentication and verify the full request/response cycle.

**These tests are NOT run during Docker image builds.** They run in a dedicated CI workflow (`e2e.yml`) on pull requests, and can also be run locally.

## Prerequisites

Before running E2E tests, ensure:

1. **MySQL/MariaDB** is running on port 3376 (via `docker compose up -d`)
2. **User API** (`lnvps_api`) is running on port 8000
3. **Admin API** (`lnvps_api_admin`) is running on port 8001
4. Database migrations have been applied (automatic on server startup)

Do NOT set `LNVPS_DEV_SETUP=1` — the lifecycle test creates and cleans up all its own infrastructure. The `dev_setup.sql` script inserts data that can conflict.

## Running

```bash
# Run all E2E tests (always use --test-threads=1)
cargo test -p lnvps_e2e -- --test-threads=1

# Run with output visible
cargo test -p lnvps_e2e -- --test-threads=1 --nocapture

# Run a specific test module
cargo test -p lnvps_e2e lifecycle -- --test-threads=1 --nocapture
cargo test -p lnvps_e2e rbac -- --test-threads=1
cargo test -p lnvps_e2e admin_api -- --test-threads=1
cargo test -p lnvps_e2e user_api -- --test-threads=1

# Run against a remote server (override defaults)
LNVPS_API_URL=https://api-uat.lnvps.net cargo test -p lnvps_e2e user_api -- --test-threads=1
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LNVPS_API_URL` | `http://localhost:8000` | User API base URL |
| `LNVPS_ADMIN_API_URL` | `http://localhost:8001` | Admin API base URL |
| `LNVPS_DB_URL` | `mysql://root:root@localhost:3376/lnvps` | Direct DB connection for bootstrap/cleanup |
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

The `.github/workflows/e2e.yml` workflow runs E2E tests on every pull request. It:

1. Starts infrastructure via `docker-compose.e2e.yaml` (MariaDB, Redis, bitcoind regtest, LND)
2. Waits for LND to be ready and copies TLS cert + macaroon to the host
3. Mines 101 blocks so LND has spendable funds
4. Builds and starts both API servers using configs from `.github/e2e/`
5. Runs `cargo test -p lnvps_e2e -- --test-threads=1`
6. Tears down all containers on completion

### CI files

| File | Purpose |
|---|---|
| `.github/workflows/e2e.yml` | GitHub Actions workflow |
| `docker-compose.e2e.yaml` | Compose file with DB, Redis, bitcoind, LND |
| `.github/e2e/api-config.yaml` | User API config pointing to CI LND |
| `.github/e2e/admin-config.yaml` | Admin API config |
| `.github/e2e/wait-for-lnd.sh` | Script to wait for LND readiness and mine initial blocks |
