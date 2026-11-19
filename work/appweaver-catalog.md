# AppWeaver catalog — PR #397

Target: [LNVPS/api#397](https://github.com/LNVPS/api/pull/397), branch
`catalog/appweaver` in `dhalsim/lnvps-api`.

## Reviewed release

- AppWeaver: **14.27.4**
- Source / embedded `APPWEAVER_GIT_SHA` / OCI revision:
  `88e8cb53b4119461738887c4d5a72c7cc5d17e3d`
- Image: `ghcr.io/getappweaver/core:alpine-v14.27.4`
- Image index: `sha256:1ecd9562ce8cd7e005093a0442599503fee2b6d4c8856c3994e42c3246f4a8e2`
- `linux/amd64` manifest: `sha256:5110b79368fe192a567fd68c0107a4037fc6904a9209112d07552954cd9e065a`
- [Successful publication](https://github.com/getappweaver/core/actions/runs/44606929834).

Registry metadata and the actual published entrypoint layer were inspected without
starting a container. The entrypoint requires a full SHA, fetches/verifies that
commit, and checks workspace HEAD and tracked files before dependency installation.
The image runs as `appweaver`; Node/npm are not installed. Runtime verification
remains separate from these artifact checks.

The reviewer's latest review in [PR #397](https://github.com/LNVPS/api/pull/397)
accepts commit-SHA source selection; the remaining requested documentation must
match the catalog's pinned image. This does not freeze independently installed apps.

## Existing merge (preserve)

The working tree initially had a staged, unfinished merge of upstream
`8dfe51763668b5c128daa1491cb59222074178c8` into PR head
`34f360159db901964330a75f57d5c3087778bb2a`. The original conflicts were
`docs/managed-app-examples.md` and `scripts/app-catalog-test.sh`. No unmerged index
entries or conflict markers remain in those files. Against the merge's upstream
parent, staged changes are limited to the AppWeaver catalog, docs and fixture.
Do not abort/reset the merge or discard its staged work. New release-pin edits
are initially unstaged so the pre-existing index remains intact.

Upstream master was `2ebee382b5e9edc364ab6ac5c684ceb3e8caa89e` when inspected,
42 commits beyond the merge target. Recheck before integration. A newer upstream
merge cannot begin until this merge is concluded; committing/pushing requires an
explicit user request. Existing staged whitespace issues in `lnvps_db/src/mysql.rs`
are outside this catalog change.

## Checklist

- [x] Verify 14.27.4 digest, platform, embedded SHA, CI revision and image entrypoint.
- [x] Review latest PR feedback and existing staged conflict resolutions.
- [x] Update catalog pin and matching docs; validate declarations and rendering.
- [ ] Conclude the current merge, preserving all staged work, when authorized to commit.
- [ ] Integrate current upstream master and review the resulting AppWeaver-only PR diff.
- [ ] Verify disposable-container first boot, restart, owner authentication and health.
- [ ] Verify quiesced backup/restore preserves keys, SQLite sidecars, installed apps,
      FIPS identity/pairings/relay settings and HOME/XDG credentials.
- [ ] Verify encrypted FIPS ping in both directions across separate networks on a VPS.
- [ ] Refresh PR description/evidence and publish reviewed commits when requested.

Do not run tests unless explicitly requested. See the [catalog documentation](../docs/managed-app-examples.md#appweaver--ai-powered-app-hub)
for runtime verification steps and [the platform plan](app-deployments.md) for
shared operator behavior. No VPS/runtime success is implied by static validation.

## Static checks completed

- `cargo run --offline --locked -q -p lnvps_compose --bin compose-validate -- catalog/appweaver.yaml`
  passed: one service, 1 CPU, 2Gi memory, 20Gi storage; only master pubkey and hostname
  are substituted.
- `compose-to-docker` rendered the catalog to
  `target/tmp/appweaver-14.27.4-review/` with a public test master pubkey and
  `appweaver.example.com`; no real credentials or containers were created.
- `docker compose -f target/tmp/appweaver-14.27.4-review/docker-compose.yaml config --quiet`
  passed. Inspected the rendered digest/SHA, HTTPS setup origin, UID 1000,
  read-only root, dropped capabilities, no-new-privileges, workspace and `/tmp`.
- Scoped `git diff --check` passed for catalog/docs edits. The existing staged
  whole-merge whitespace check reports four unrelated trailing-whitespace lines
  in `lnvps_db/src/mysql.rs`; those were left intact.
- No tests, application startup, VPS deployment or authenticated browser checks
  were run. Commits, push and PR edits remain pending explicit requests.
