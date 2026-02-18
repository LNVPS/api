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

If the estimate is XL, create a work file in `work/` that decomposes the task into L-or-smaller increments, then work through them one PR at a time. See [docs/agents-common/incremental-work.md](docs/agents-common/incremental-work.md) for the work file format.

**2. Check `work/`** for an active task file on the same topic before starting new work. If one exists, resume from the first unchecked task.

| File | Description |
|---|---|
| [work/agent-rules-compliance.md](work/agent-rules-compliance.md) | Bringing codebase into full compliance with all agent rules |

## Generic Docs

These docs apply to all projects using this agent structure:

| Doc | When to load |
|---|---|
| [docs/agents-common/bug-fixes.md](docs/agents-common/bug-fixes.md) | Resolving bugs (includes regression test requirement) |
| [docs/agents-common/coverage.md](docs/agents-common/coverage.md) | Any edit that adds or modifies functions (100% function coverage required) |
| [docs/agents-common/incremental-work.md](docs/agents-common/incremental-work.md) | Managing a work file for a multi-increment task |

## Project-Specific Docs

| Doc | When to load |
|---|---|
| [docs/agents/project-overview.md](docs/agents/project-overview.md) | Understanding workspace crates, feature flags, module structure |
| [docs/agents/build-and-test.md](docs/agents/build-and-test.md) | Running builds, tests, clippy, or formatting |
| [docs/agents/code-style.md](docs/agents/code-style.md) | Writing or reviewing Rust code (imports, errors, naming, async, derives, serde, tests) |
| [docs/agents/api-guidelines.md](docs/agents/api-guidelines.md) | Modifying any user-facing or admin API endpoint |
| [docs/agents/currency.md](docs/agents/currency.md) | Working with money amounts, pricing, or payments |
| [docs/agents/bug-fixes.md](docs/agents/bug-fixes.md) | Resolving bugs — LNVPS-specific additions |
| [docs/agents/coverage.md](docs/agents/coverage.md) | Function coverage — LNVPS-specific additions |
