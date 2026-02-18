# Test Coverage Requirements

## Rule: 100% Function Coverage on All New or Modified Code

Every function introduced **or modified** by an edit **must** be exercised by at least one test. This applies to:

- New free functions and methods
- Modified free functions and methods
- New or modified trait implementations
- New or modified `async fn` handlers
- Helper/utility functions, even private ones

## Workflow

1. **Write the code and its tests** together in the same PR/commit.
2. **Generate the coverage report** after all tests pass:

```bash
cargo llvm-cov --summary-only -- --test-threads=1
```

3. **Inspect uncovered functions.** For a line-level breakdown, open the HTML report:

```bash
cargo llvm-cov --open -- --test-threads=1
```

4. **Iterate** until every newly added function appears as covered (non-zero hit count) in the report.

## Interpreting the Report

- The terminal summary shows per-file `Fns %` (function coverage). A file you touched must reach **100 %** for functions you added.
- The HTML report highlights uncovered lines in red. Any red line inside a function you wrote means that function lacks coverage.
- Functions that are `#[cfg(test)]`-only or compile-time-only (e.g. `derive` impls) are excluded automatically and do not need explicit tests.

## Checklist Before Marking an Edit as Complete

- [ ] All new functions have at least one test path that calls them
- [ ] `cargo llvm-cov --summary-only -- --test-threads=1` shows 100 % function coverage for every file you modified
- [ ] `cargo test -- --test-threads=1` passes with no failures (see [build-and-test.md](build-and-test.md))
