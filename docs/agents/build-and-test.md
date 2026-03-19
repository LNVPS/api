# Build, Test, and Lint Commands

## Building

```bash
# Build entire workspace
cargo build

# Build with all features
cargo build --all-features

# Check code without building
cargo check
```

## Testing

**IMPORTANT:** Always use `--test-threads=1` to avoid flaky tests. Tests use shared static state (`LazyLock`) in mocks and must run sequentially.

**IMPORTANT:** Before running any tests, always ensure Docker is running:
```bash
docker compose up -d
```
The `lnvps_e2e` crate connects to MariaDB (port 3376) and the API servers. Without Docker the e2e tests all fail with connection errors.

```bash
# Run all unit tests (no API servers required)
cargo test --workspace --exclude lnvps_e2e -- --test-threads=1

# Run ALL tests including e2e (requires API servers on ports 8000 and 8001)
cargo test -- --test-threads=1

# Run a single test by name (substring match)
cargo test test_name_substring

# Run tests in a specific crate
cargo test -p lnvps_api_common

# Run a specific test in a specific crate
cargo test -p lnvps_api_common test_name

# Run tests with output visible
cargo test -- --nocapture
```

## Coverage

Uses `cargo-llvm-cov` (install once with `cargo install cargo-llvm-cov && rustup component add llvm-tools-preview`).

```bash
# Print a per-file coverage summary to the terminal
cargo llvm-cov --summary-only -- --test-threads=1

# Generate an HTML report (opens in browser)
cargo llvm-cov --open -- --test-threads=1

# Generate an lcov report (for CI or editor integration)
cargo llvm-cov --lcov --output-path lcov.info -- --test-threads=1
```

## Linting and Formatting

```bash
# Run clippy lints
cargo clippy

# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check
```
