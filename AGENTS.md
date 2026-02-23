# AGENTS.md - Coding Agent Guidelines for LNVPS

This file is an index. Load only the specific doc(s) relevant to your task to minimize context usage.

**Always load [docs/agents-common/common.md](docs/agents-common/common.md) first** — it contains essential guidelines for task sizing, git commits, and git push that apply to all tasks.

**Git push** — Always push using the HTTPS URL directly: `git push https://github.com/LNVPS/api.git`

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
| [docs/agents/migrations.md](docs/agents/migrations.md) | Adding or modifying database migrations |
| [docs/agents/currency.md](docs/agents/currency.md) | Working with money amounts, pricing, or payments |
| [docs/agents/bug-fixes.md](docs/agents/bug-fixes.md) | Resolving bugs — LNVPS-specific additions |
| [docs/agents/coverage.md](docs/agents/coverage.md) | Function coverage — LNVPS-specific additions |
| [docs/agents/e2e-tests.md](docs/agents/e2e-tests.md) | Writing or running E2E integration tests (`lnvps_e2e` crate) |

## Release Procedure

When the user asks to create a release:

1. **Update `API_CHANGELOG.md`** — Change `## [Unreleased]` to `## [vX.Y.Z] - YYYY-MM-DD` with the current date
2. **Update `Cargo.toml` versions** — Bump the version in the root `Cargo.toml` under `[workspace.package]` (all crates inherit via `version.workspace = true`)
3. **Commit the changes** — `git commit -m "chore: release vX.Y.Z"`
4. **Create an annotated tag** — `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
5. **Push commit and tag** — `git push https://github.com/LNVPS/api.git && git push https://github.com/LNVPS/api.git vX.Y.Z`
