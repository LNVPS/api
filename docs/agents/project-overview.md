# Project Overview

LNVPS is a Rust workspace for a VPS provisioning system with Lightning Network payments.

## Workspace Crates

| Crate | Purpose |
|---|---|
| `lnvps_db` | Database layer with traits and MySQL implementation |
| `lnvps_api` | Main user-facing API service |
| `lnvps_api_admin` | Admin API service |
| `lnvps_api_common` | Shared types and utilities |
| `lnvps_nostr` | Nostr protocol integration |
| `lnvps_operator` | System operator/background tasks |
| `try-procedure` | Retry utilities library |
| `lnvps_health` | Standalone network health monitoring service (MSS, DNS, PMTU checks, Prometheus metrics, SMTP alerts) |
| `lnvps_fw_service` | Firewall service that loads an eBPF/XDP program for per-VM rate limiting |
| `lnvps_ebpf` | eBPF program (XDP) implementing a token-bucket rate limiter; compiled separately with aya-build |

## Feature Flags

| Flag | Description |
|---|---|
| `admin` | Admin API functionality |
| `nostr-domain` | Nostr domain features |
| `mysql` | MySQL database support (default) |

Use conditional compilation:

```rust
#[cfg(feature = "admin")]
mod admin;

#[cfg(feature = "admin")]
pub use admin::*;
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
