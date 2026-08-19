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
| [docs/agents/testing-db-backups.md](docs/agents/testing-db-backups.md) | Testing branch changes (migrations, startup) against a restored production DB backup safely (mock hosts, no user notifications) |
| [docs/agents/fw-testing.md](docs/agents/fw-testing.md) | Running or extending the firewall XDP netns test harness (`lnvps_fw`) |

## Pull Request Procedure

When creating a PR that closes a GitHub issue:

1. **Label the issue** — Before opening the PR, apply appropriate labels to the linked issue using `gh issue edit <number> --add-label "<label>"`. Choose from existing repo labels; create a new one with `gh label create` only if no existing label fits. Typical labels:
   - `bug` — something is broken
   - `enhancement` — new feature or improvement
   - `host:proxmox` / `host:libvirt` — host-specific changes
   - `api` — user-facing or admin API changes
   - `database` — migration or schema changes
   - `payments` — payment/invoice logic
   - `refactor` — internal restructuring without behaviour change
   - `documentation` — docs-only change
2. **Open the PR** — Reference the issue in the PR body (`Fixes #N`).

## Release Procedure

When the user asks to create a release:

1. **Update `API_CHANGELOG.md`** — Change `## [Unreleased]` to `## [vX.Y.Z] - YYYY-MM-DD` with the current date
2. **Update `Cargo.toml` versions** — Bump the version in the root `Cargo.toml` under `[workspace.package]` (all crates inherit via `version.workspace = true`)
3. **Commit the changes** — `git commit -m "chore: release vX.Y.Z"`
4. **Create an annotated tag** — `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
5. **Push commit and tag** — `git push https://github.com/LNVPS/api.git && git push https://github.com/LNVPS/api.git vX.Y.Z`

The `vX.Y.Z` tag covers the API and its images only. `lnvps_fw` and the NixOS cloud image are **separate artifacts on their own tags** — releasing the API neither builds nor publishes them.

## `lnvps_fw` Release Procedure

`lnvps_fw` is a separate workspace (excluded from the root one) with its own `[workspace.package]` version in `lnvps_fw/Cargo.toml`, and it releases on its own tag — the same convention as the NixOS image's `nixos-image-v*`. Its version is **independent** of the API's: bump it when the firewall changes, leave it alone when it doesn't.

1. **Bump `lnvps_fw/Cargo.toml`** — the `[workspace.package]` version (all three fw crates inherit it).
2. **Rebuild the dashboard if `dashboard/src/` changed** — `cd lnvps_fw/lnvps_fw_service/dashboard && bun run build`, and commit `dist/index.html` (the daemon embeds it with `include_str!`).
3. **Commit** — `git commit -m "chore(fw): release lnvps_fw-vX.Y.Z"`
4. **Tag and push** — `git tag -a lnvps_fw-vX.Y.Z -m "lnvps_fw vX.Y.Z"` then `git push https://github.com/LNVPS/api.git && git push https://github.com/LNVPS/api.git lnvps_fw-vX.Y.Z`

Pushing the tag triggers `.github/workflows/lnvps_fw-deb.yml`, which builds the daemon (including the eBPF datapath, via a nightly `rust-src` + `bpf-linker` toolchain) into a Debian package with `cargo deb` and attaches the `.deb` to the GitHub release. Running daemons discover and install it through the self-upgrade endpoint (`GET`/`POST /api/v1/upgrade`).

The workflow **fails the build** if `lnvps_fw/Cargo.toml` does not match the tag, because the daemon compares its compiled `CARGO_PKG_VERSION` against the newest firewall release: were the version to lag the tag, every running daemon would report an upgrade available on startup and every 6h. Do step 1 before tagging.

The self-upgrade check (`lnvps_fw_service/src/upgrade.rs`) selects the newest release that carries an `lnvps-fw*.deb` asset, so it ignores API releases and still finds pre-split `vX.Y.Z` firewall releases. If you change the artifact's package name, update `DEB_ASSET_PREFIX` with it.
