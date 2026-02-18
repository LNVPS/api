# Test Coverage Requirements — LNVPS Additions

See [docs/agents-common/coverage.md](../agents-common/coverage.md) for the base rules.

## LNVPS-Specific Overrides

**Generate the coverage report:**

```bash
cargo llvm-cov --summary-only -- --test-threads=1
```

For a line-level breakdown, open the HTML report:

```bash
cargo llvm-cov --open -- --test-threads=1
```

**Interpreting the report:**

- The terminal summary shows per-file `Fns %`. A file you touched must reach **100%** for functions you added.
- The HTML report highlights uncovered lines in red.
- Functions that are `#[cfg(test)]`-only or compile-time-only (e.g. `derive` impls) are excluded automatically.

**Checklist additions:**

- [ ] `cargo llvm-cov --summary-only -- --test-threads=1` shows 100% function coverage for every file you modified
- [ ] `cargo test -- --test-threads=1` passes with no failures (see [build-and-test.md](build-and-test.md))
