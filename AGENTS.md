# AGENTS.md - Coding Agent Guidelines for LNVPS

This file is an index. Load only the specific doc(s) relevant to your task to minimize context usage.

## Before Starting Any Task

**1. Estimate the size** of the change using t-shirt sizing:

| Size | Lines of change | Action |
|------|----------------|--------|
| XS | < 50 | Proceed directly |
| S | 50–250 | Proceed directly |
| M | 250–750 | Proceed directly |
| L | 750–2,500 | Proceed directly |
| XL | > 2,500 | **Stop — split into increments first** |

If the estimate is XL, create a work file in `work/` that decomposes the task into L-or-smaller increments, then work through them one PR at a time. See [agents/incremental-work.md](agents/incremental-work.md) for the work file format.

**2. Check `work/`** for an active task file on the same topic before starting new work. If one exists, resume from the first unchecked task.

| File | Description |
|---|---|
| [work/agent-rules-compliance.md](work/agent-rules-compliance.md) | Bringing codebase into full compliance with all agent rules |

## Docs

Load the specific doc(s) relevant to your task:

| Doc | When to load |
|---|---|
| [agents/project-overview.md](agents/project-overview.md) | Understanding workspace crates, feature flags, module structure |
| [agents/build-and-test.md](agents/build-and-test.md) | Running builds, tests, clippy, or formatting |
| [agents/code-style.md](agents/code-style.md) | Writing or reviewing Rust code (imports, errors, naming, async, derives, serde, tests) |
| [agents/api-guidelines.md](agents/api-guidelines.md) | Modifying any user-facing or admin API endpoint |
| [agents/currency.md](agents/currency.md) | Working with money amounts, pricing, or payments |
| [agents/bug-fixes.md](agents/bug-fixes.md) | Resolving bugs (includes regression test requirement) |
| [agents/coverage.md](agents/coverage.md) | Any edit that adds or modifies functions (100 % function coverage required) |
| [agents/incremental-work.md](agents/incremental-work.md) | Managing a work file for a multi-increment task |
