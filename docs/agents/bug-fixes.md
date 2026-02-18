# Bug Fixes — LNVPS Additions

See [docs/agents-common/bug-fixes.md](../agents-common/bug-fixes.md) for the base rules.

## LNVPS-Specific Overrides

- **Test placement:** use the existing `#[cfg(test)] mod tests` block in the relevant file, or a dedicated `tests.rs` sibling file.
- **Example names:** `test_vm_cost_overflow_with_zero_disk`, `test_payment_amount_rounds_correctly`.
- **Run tests with:** `cargo test -- --test-threads=1` (see [build-and-test.md](build-and-test.md))
