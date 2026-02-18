# Bug Fixes

## Required: Add a Regression Test for Every Bug Fix

When resolving a bug, you **MUST** add a unit test that:

1. **Reproduces the original failure** — the test should fail on the unfixed code and pass after the fix.
2. **Is placed in the appropriate test module** — either the existing `#[cfg(test)] mod tests` in the relevant file, or a dedicated `tests.rs` sibling file.
3. **Has a descriptive name** that makes the bug clear, e.g. `test_vm_cost_overflow_with_zero_disk`, `test_payment_amount_rounds_correctly`.

## Checklist Before Marking a Bug as Fixed

- [ ] Root cause identified
- [ ] Fix applied
- [ ] Unit test added that would have caught the bug
- [ ] `cargo test -- --test-threads=1` passes (see [build-and-test.md](build-and-test.md))
