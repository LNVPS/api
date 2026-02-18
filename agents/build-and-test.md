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

```bash
# Run all tests
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

## Linting and Formatting

```bash
# Run clippy lints
cargo clippy

# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check
```
