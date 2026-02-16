# AGENTS.md - Coding Agent Guidelines for LNVPS

## Project Overview

LNVPS is a Rust workspace for a VPS provisioning system with Lightning Network payments.
The workspace contains multiple crates: `lnvps_db`, `lnvps_api`, `lnvps_api_admin`, 
`lnvps_api_common`, `lnvps_nostr`, `lnvps_operator`, and `try-procedure`.

## Build, Test, and Lint Commands

```bash
# Build entire workspace
cargo build

# Build with all features
cargo build --all-features

# Run all tests (IMPORTANT: use --test-threads=1 to avoid flaky tests)
# Tests use shared static state (LazyLock) in mocks, so they must run sequentially
cargo test -- --test-threads=1

# Run a single test by name (substring match)
cargo test test_name_substring

# Run tests in a specific crate
cargo test -p lnvps_api_common

# Run a specific test in a specific crate
cargo test -p lnvps_api_common test_name

# Run tests with output visible
cargo test -- --nocapture

# Check code without building
cargo check

# Run clippy lints
cargo clippy

# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check
```

## Code Style Guidelines

### Import Organization

Organize imports in this order with blank lines between groups:
1. External crate imports (non-std)
2. Workspace crate imports (local crates from workspace)
3. Local module imports (`crate::`, `super::`)

```rust
use anyhow::{Result, anyhow, bail, Context};
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};

use lnvps_api_common::{ApiData, ApiResult, PageQuery};
use lnvps_db::{LNVpsDb, Vm, VmHost};

use crate::api::model::ApiVmStatus;
use crate::settings::Settings;
```

Combine imports from the same crate using curly braces.

### Error Handling

- Use `anyhow` for all application errors
- Return `Result<T>` (which resolves to `anyhow::Result<T>`)
- Use `.context()` to add context to errors
- Use `bail!()` for early returns with error messages
- Use `anyhow!()` to create inline errors

```rust
use anyhow::{Result, anyhow, bail, Context};

async fn get_router(&self, id: u64) -> Result<Router> {
    let cfg = self.db.get_router(id).await?;
    let token = cfg.token.as_str()
        .split(":")
        .next()
        .context("Invalid token format")?;
    
    if token.is_empty() {
        bail!("Token cannot be empty");
    }
    Ok(router)
}
```

**Prefer `map()`, `and_then()`, `ok_or()` over deeply nested if structures.**

### Naming Conventions

**Functions:** `snake_case`
- CRUD: `get_*`, `list_*`, `insert_*`, `update_*`, `delete_*`
- API handlers: `v1_get_vm`, `v1_patch_account`, `admin_list_hosts`

**Types:** `PascalCase`
- API models: prefix with `Api` (`ApiVmStatus`, `ApiUserSshKey`)
- Admin models: prefix with `Admin` (`AdminHostInfo`, `AdminVmHost`)
- Database models: no prefix (`User`, `Vm`, `VmHost`)
- Request types: suffix with `Request` (`CreateVmRequest`)
- Traits: describe capability (`LNVpsDb`, `VmHostClient`, `Router`)

**Enums:**
- `PascalCase` variants: `VmHostKind::Proxmox`, `PaymentMethod::Lightning`
- Use `#[repr(u16)]` for database-stored enums

### Async Patterns

- Use `tokio` as the async runtime
- Use `#[async_trait]` for async trait methods
- Use `futures::future::join_all` for parallel async operations
- Tests use `#[tokio::test]`

```rust
#[async_trait]
pub trait LNVpsDbBase: Send + Sync {
    async fn get_user(&self, id: u64) -> Result<User>;
}
```

### Documentation

- Use `///` doc comments on trait methods and public items
- Document struct fields with `///`
- Use `//!` for module-level documentation

```rust
/// Get a user by id
async fn get_user(&self, id: u64) -> Result<User>;

pub struct VmHost {
    /// Unique id of this host
    pub id: u64,
    /// The host kind (Hypervisor)
    pub kind: VmHostKind,
}
```

### Derive Macros

```rust
#[derive(FromRow, Clone, Debug, Default)]      // Database structs
#[derive(Serialize, Deserialize)]              // API models
#[derive(Clone, FromRef)]                      // Axum state
```

### Serde Customization

```rust
#[serde(rename_all = "kebab-case")]                    // For config files
#[serde(rename_all = "lowercase")]                     // For API enums
#[serde(skip_serializing_if = "Option::is_none")]      // Optional fields
```

### State Management

Use `Arc` for shared state across async boundaries:

```rust
pub struct RouterState {
    pub db: Arc<dyn LNVpsDb>,
    pub provisioner: Arc<LNVpsProvisioner>,
}
```

### Feature Flags

The project uses feature flags for optional functionality:
- `admin` - Admin API functionality
- `nostr-domain` - Nostr domain features
- `mysql` - MySQL database support (default)

Use conditional compilation:
```rust
#[cfg(feature = "admin")]
mod admin;

#[cfg(feature = "admin")]
pub use admin::*;
```

### Test Organization

- Place test modules in separate files: `#[cfg(test)] mod tests;`
- Use mock implementations in dedicated files (`mocks.rs`)
- Mocks use `Arc<Mutex<HashMap>>` for shared state

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_feature() -> Result<()> {
        // Test implementation
        Ok(())
    }
}
```

## Project-Specific Rules

- **Always return amounts in API responses as cents / milli-sats**
- **Never add JavaScript code examples to API documentation**
- **Prefer `map()` and `and_then()` over deeply nested if structures**
- **Never expose secrets in admin API responses** - tokens, API keys, webhook secrets, and other sensitive values must never be returned in GET/list responses. Use sanitized structs with boolean indicators (e.g., `has_token: true`) instead of actual values.

## API Documentation Requirements

When modifying any API (user-facing or admin), you **MUST**:

1. **Update the API documentation** - Keep `ADMIN_API_ENDPOINTS.md` and any other API docs in sync with code changes
2. **Update the API changelog** - Add an entry to `API_CHANGELOG.md` describing the change with:
   - Date of change
   - Type of change (Added, Changed, Deprecated, Removed, Fixed, Security)
   - Brief description of what changed
   - Which endpoints are affected

## Currency Handling

The project uses `payments_rs::currency::CurrencyAmount` for currency conversions.

### Database Storage
- All money amounts are stored as `u64` in smallest currency units (cents for fiat, millisats for BTC)
- This includes: cost plan amounts, custom pricing costs (cpu_cost, memory_cost, ip4_cost, ip6_cost, disk cost), fees, payment amounts

### Admin API
- The admin API accepts and returns amounts as `u64` in smallest currency units (cents for fiat, millisats for BTC)
- Use `payments_rs` for conversions:
  - `CurrencyAmount::from_u64(Currency, u64)` - smallest units directly
  - `CurrencyAmount::from_f32(Currency, f32)` - human-readable to smallest units
  - `.value()` - returns `u64` smallest units
  - `.value_f32()` - returns `f32` human-readable

### Currency Decimal Places
- Most fiat currencies (EUR, USD, GBP, CAD, CHF, AUD): 2 decimal places (100 cents = 1 unit)
- JPY: 0 decimal places
- BTC: uses millisats (1000 millisats = 1 satoshi)

### Example
```rust
use payments_rs::currency::{Currency, CurrencyAmount};

// Working with smallest units (preferred for API)
let amount = CurrencyAmount::from_u64(Currency::EUR, 1099); // €10.99 = 1099 cents
assert_eq!(amount.value(), 1099); // 1099 cents
assert_eq!(amount.value_f32(), 10.99); // €10.99

// Converting human-readable to smallest units
let amount = CurrencyAmount::from_f32(Currency::EUR, 10.99); // €10.99
assert_eq!(amount.value(), 1099); // 1099 cents
```

## Module Structure Pattern

```rust
// lib.rs pattern
mod capacity;
mod exchange;
mod model;
pub mod retry;  // Explicitly public for external use

pub use capacity::*;
pub use exchange::*;
pub use model::*;
```

## Workspace Crates

- `lnvps_db` - Database layer with traits and MySQL implementation
- `lnvps_api` - Main user-facing API service
- `lnvps_api_admin` - Admin API service
- `lnvps_api_common` - Shared types and utilities
- `lnvps_nostr` - Nostr protocol integration
- `lnvps_operator` - System operator/background tasks
- `try-procedure` - Retry utilities library
