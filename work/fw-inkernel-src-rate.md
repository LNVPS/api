# In-kernel per-source rate limiting (XDP rewrite)

**Status:** complete
**Started:** 2026-07-11
**Last updated:** 2026-07-11

## Goal

Move the per-source pps calculation and blocking decision from the userspace
control loop into the XDP datapath. Userspace stops scanning the (up to 256k
entry) source counter maps every 500ms tick and only reads state for display.
The class of bugs this kills structurally: cumulative-counter seeding, hidden
threshold drift between the two rate systems, and control-loop CPU that scales
with flood history instead of live traffic.

## Design

- `V4/V6_SRC_COUNTERS` (per-CPU cumulative u64) are **replaced** by
  `V4/V6_SRC_STATE: LruHashMap<addr, SrcState>` where
  `SrcState { window_start_ns, count, blocked_until_ns }`.
- Fixed-window rate machine, in-kernel, per packet under mitigation:
  - blocked? (`now < blocked_until_ns`) → count, and on window roll while
    still over-rate extend the block (re-trip); XDP_DROP.
  - window rolled (`now - window_start >= window_ns`) → reset window.
  - `count++` (atomic); `count > max_per_window` → `blocked_until = now +
    cooldown_ns`, XDP_DROP.
- Config via `SRC_RATE_CFG: Array<SrcRateConfig>` (1 entry):
  `{ max_per_window, window_ns, cooldown_ns, enforce }` — written by userspace
  at startup and on `PUT /limits`. `max_per_window` is precomputed
  (`rate_pps × window_secs`) so the datapath never divides.
- Counting happens under any mitigation flags (same as today); **dropping** is
  gated on the dest's `SOURCE_BLOCK` flag (escalation ladder unchanged:
  userspace still decides *when* a dest escalates via `escalate_pass_pps`).
- Auto CIDR aggregation, spoof gate (`max_real_sources`), `plan_blocks`,
  `V4/V6_CIDR_SRC` auto entries: **deleted**. The per-source state map IS the
  block list; a spoofed flood of unique IPs never trips per-source limits and
  simply churns the LRU (port-filter layer remains the defense, as today).
  Manual blocks keep the separate `MANUAL_BLOCK_V4/V6` tries (unchanged).
- Userspace `/sources` + `/blocks` views: batched on-demand read of the state
  maps (still via `batch.rs`), `state = blocked_until > now ? dropping :
  normal` (the `cooling` display state disappears), `pps` approximated from
  the current window. `src_exit_pct` is retired from `Limits`;
  `src_rate_pps`/`src_cooldown_secs` remain and now write `SRC_RATE_CFG`.

## Findings

- Prior perf work (uncommitted, kept): `batch.rs` raw `BPF_MAP_LOOKUP_BATCH`
  reader + batched dest/tx/GC scans + `block_pps` de-quadratic + idle purge.
  The purge/tracker machinery (`detect.rs` SourceTracker, `step_sources`) gets
  deleted by increment 2 of this rewrite.
- `mitigate_v4` at `lnvps_ebpf/src/main.rs:260` (`count_src_v4` +
  `cidr_blocked_v4`) and v6 at `:315` are the integration points.
- Harness tests that break: `tests/escalation.rs`
  (`cidr_escalation_blocks_offending_v24` — tests deleted aggregation),
  `tests/mitigation.rs` (`source_block_only_when_flag_set` — same semantics,
  new map). Harness accessors live in `tests/harness/mod.rs`.
- eBPF atomics: `count` increments use BPF atomic add; per-entry races on
  window reset are benign (approximate counting is acceptable).

## Tasks

- [x] Pre-work: batch reader + GC batching compiles green (63 lib tests)
- [x] Increment 1: `SrcState`/`SrcRateConfig` in `lnvps_fw_common`; eBPF
      `V4/V6_SRC_STATE` maps + `SRC_RATE_CFG`; rate machine in
      `mitigate_v4/v6`; deleted `V4/V6_SRC_COUNTERS` + `V4/V6_CIDR_SRC`
- [x] Increment 2: stripped userspace source polling (SourceTracker,
      step_sources, plan_blocks/aggregation, spoof gate, block trie
      reconciliation); `write_src_rate_cfg` at startup + on `PUT /limits`;
      `gc_src_states` on the GC timer (60s idle TTL); views from batched
      state-map snapshots; deprecated config knobs kept parseable (regression
      test `parses_legacy_escalation_keys`); `src_exit_pct` removed from
      `Limits`
- [x] Increment 3: harness accessors rewritten (`src_state_v4`,
      `src_blocked_v4`, `set_src_rate`); `escalation.rs` rewritten as two
      in-kernel scenarios (kernel blocks over-rate source + releases after
      cooldown with **zero** control ticks; drops gated on SOURCE_BLOCK);
      superseded `source_block_only_when_flag_set` removed; full e2e suite
      green (21 root tests: smoke 4, learning 3, mitigation 4, escalation 2,
      carpet_bomb 1, syn_proxy 3, gre_decap 2, scoping 2); docs + example
      config + dashboard updated, dist rebuilt

## Outcome

43 lib + 2 bin + 15 API tests and the full netns e2e suite pass. The control
loop's per-tick source work went from "iterate every counted source × 2
syscalls" to one batched display read; blocking latency went from up to one
500ms tick to the packet that crosses the limit; seeding/counter-lifecycle
bugs are structurally gone. Deployment note: on upgrade the old
`V4/V6_CIDR_SRC`-based auto blocks disappear (kernel re-blocks offenders
within one window); old config files parse unchanged.

## Notes

- Do NOT release mid-rewrite; single release once increment 3 is green.
- Keep `GET /blocks` API shape backward-compatible (manual + dropping /32s).
- `escalate_pass_pps` and the dest-level detection ladder are intentionally
  untouched — dest detection stays in userspace (16k entries, cheap, complex
  policy).
