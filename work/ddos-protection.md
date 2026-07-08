# XDP DDoS Protection System for VM Hosts

**Status:** in-progress
**Started:** 2026-07-08
**Last updated:** 2026-07-08 (Increment 6 complete; Increment 7 re-scoped to a
DB-less RESTful control API on fw_service)

## Goal

Build a full DDoS protection system (pletX-style) running on every VM host:
passively learn which ports each VM IP actually has open, and — when a
destination IP comes under attack — flip it into mitigation mode where inbound
traffic to non-open ports is dropped (phase 1), escalating through per-source
rate limits / CIDR blocking and SYN-proxy under sustained floods. Managed via
the LNVPS API with metrics and admin visibility.

## Design Decisions (confirmed with user 2026-07-08)

- **Port learning:** passive egress observation. A TCP SYN-ACK sent *by* a VM
  from `ip:port` marks that TCP port open; outbound UDP from `ip:port` marks a
  UDP service. Entries expire via TTL when unused. No user config required.
- **Enforcement:** only under attack. Steady state is pass-all (learning
  continuously). When per-dest thresholds trip (pps / SYN/s / bytes/s), that
  dest IP enters mitigation mode; hysteresis + cooldown to exit.
- **Deployment:** `lnvps_fw_service` is a stateless daemon on each protected
  host (router / VM host / edge box), attaching XDP to uplink NIC(s). It holds
  **no database**: it exposes a token-authed RESTful API (inc 7) that the
  primary `lnvps_api` service calls to push rules and poll state/events;
  `lnvps_api` is the source of truth and retains all durable rules + incident
  logs.
- **Full scope:** per-src rate limits + CIDR escalation, IPv6 parity,
  SYN-proxy/cookies phase, metrics + admin API visibility.

## Architecture

```
                 uplink NIC
                     │
      ┌── XDP ingress (xdp_lnvps) ──────────────────────────┐
      │ 1. parse eth/v4/v6 + tcp/udp/icmp                    │
      │ 2. per-dest counters (pps, SYN/s, bytes/s)           │
      │ 3. if dest in MITIGATE state:                        │
      │      - drop to non-learned ports                     │
      │      - per-src token buckets + LPM CIDR escalation   │
      │      - SYN-proxy (syncookies) when in SYN_PROXY stage│
      └──────────────────────────────────────────────────────┘
      ┌── TC egress (clsact) on uplink ─────────────────────┐
      │ learn open ports: SYN-ACK from VM ip:port → TCP open │
      │ outbound UDP from ip:port → UDP service              │
      └──────────────────────────────────────────────────────┘
                     │ BPF maps
      ┌── lnvps_fw_service daemon ──────────────────────────┐
      │ - samples per-dest counters, runs detection state    │
      │   machine (NORMAL → MITIGATE → SYN_PROXY), writes    │
      │   dest state map with hysteresis/cooldown            │
      │ - GC of learned-port TTLs and stale buckets          │
      │ - in-memory rules (pushed by lnvps_api) + event ring │
      │ - RESTful control API (token auth), NO local DB      │
      └──────────────────────────────────────────────────────┘
                     ▲ HTTP (lnvps_api → fw_service:
                     │  push rules, poll state/events)
                LNVPS API  (source of truth: rules + incident-log DB, admin API)
```

Key notes:
- XDP is ingress-only, so learning MUST use a TC egress (clsact) program on
  the same uplink; both programs share pinned maps (or one aya `Ebpf` object
  loading both).
- `lnvps_ebpf` / `lnvps_fw_service` are intentionally NOT workspace members
  (ebpf needs its own target/toolchain via aya-build). Keep it that way.
- During mitigation, TCP packets are filtered by learned dest port only (no
  full conntrack): SYN to closed port → drop; non-SYN to closed port → drop.
  ICMP under mitigation: rate-limited, not blanket-dropped.
- Existing stubs to build on: `V4_CIDR_SRC` (LpmTrie), `V4_TCP_SRC_STAGE`,
  `TcpProtectionMode`, `PacketLimits`, `Bucket` (lnvps_ebpf/src/maps.rs).
- Shared Pod types currently duplicated in fw_service main.rs (`Bucket`) —
  fix by adding a small `#![no_std]`-compatible shared types module/crate
  used by both sides.

## Findings

- `lnvps_ebpf/src/main.rs`: XDP prog parses v4/v6 TCP/UDP/ICMP; only v4 SYN
  dest rate limiting implemented (`Bucket::syn_dest_v4`).
- `lnvps_fw_service/src/main.rs`: hardcoded `eno2` attach, no config, just
  logs bucket contents. `sudo::escalate_if_needed`, ctrlc shutdown.
- `work/basic-firewall.md` (#36): user firewall rules exist in DB
  (`vm_firewall_rule`) — not used for learning (passive only), but ports the
  user explicitly allows could later be seeded as "pinned open" (out of scope).
- `lnvps_db` has `ip_assignment` (IP↔VM mapping) — API can expose per-host
  protected prefixes.
- `lnvps_agent` is the AI support agent, NOT a host agent — do not confuse.
- Admin API endpoints live in `lnvps_api_admin`; user API in `lnvps_api`.

## Tasks

### Increment 1 — eBPF foundation refactor (M) ✅ DONE
- [x] Restructured into `lnvps_fw/` sub-workspace (root workspace `exclude`s
      it): members `lnvps_ebpf`, `lnvps_fw_common`, `lnvps_fw_service`;
      `default-members` skip the eBPF crate on host builds. (Previous layout
      was broken — neither crate was a workspace member so nothing built.)
- [x] New `lnvps_fw_common` crate (no_std): `Bucket` (tick/try_consume/seeded
      + unit tests), `PacketLimits`, `DestCounters`, `DestState` +
      `DEST_MODE_*`, `PortKeyV4/V6`; `aya::Pod` impls behind `user` feature
- [x] XDP prog restructured: normalized `L4Meta`, fail-open on parse errors
      (XDP_PASS, no more XDP_ABORTED), IPv4 options + IPv6 ext headers
      detected and skipped for L4 inspection (counted only)
- [x] Per-dest counters maps `V4/V6_DEST_COUNTERS` (LruPerCpuHashMap):
      pkts/bytes/syn/tcp/udp/icmp/dropped
- [x] SYN rate limiting kept for v4 + added v6 (`syn_gate!` macro,
      `V6_SYN_RATE`, `V6_SYN_RATE_LIMITS`)
- [x] fw_service: CLI ifaces, embeds ebpf object via include_bytes_aligned,
      default→SKB attach fallback, per-dest stats logging (per-CPU sums)
- [x] aya stack bumped: aya 0.14, aya-ebpf 0.2.1, aya-build 0.2,
      network-types 0.2 (aya-log-ebpf 0.1.1 was yanked); bpf-linker 0.10.3
      installed
- [x] Builds green: ebpf target + host workspace; 8 unit tests; clippy/fmt
      clean; root workspace unaffected
- Deferred: `DST_STATE` maps moved to increment 4 where they get their first
      real reader (defining them now risks dead-code elimination of unused
      maps and adds untestable surface)

### Increment 2 — Virtualized-network test harness (M-L) ✅ DONE
- [x] Harness module (`lnvps_fw_service/tests/harness/`): builds a virtual
      network with netns + veth pairs: `attacker` ⇄ veth ⇄ `filter` (uplink
      side, XDP attached in SKB/generic mode on `f_up`) ⇄ veth ⇄ `vm` netns
      with real listening sockets; `filter` forwards between its veth ends
- [x] `NetnsTopology` (`tests/harness/netns.rs`): create/teardown netns, veth,
      addrs (v4+v6), routes, forwarding sysctls; RAII Drop deletes netns
      (tears down veths) even on panic. Shells out to `ip` only — no extra
      deps for topology. Unique per-instance names so instances can coexist
- [x] Harness loads the compiled ebpf object (`include_bytes_aligned!` of the
      build.rs OUT_DIR object) inside the filter netns via a per-thread
      `setns` switch for the XDP attach, then reads maps fd-based from the
      main thread; typed accessors (`dest_counters_v4/v6`, `syn_bucket_v4`,
      `set_syn_limits_v4`)
- [x] Traffic generators (`tests/harness/traffic.rs`): UDP send/recv via std
      sockets on threads pinned with `setns` (nix); raw-socket IPv4 SYN flood
      (libc, IP_HDRINCL, manual IP+TCP checksums)
- [x] Assertions read maps (per-dest counters, SYN buckets) and check packet
      delivery from the vm-side socket's perspective
- [x] Tests gated behind `#[ignore]` + `require_root()`; `scripts/fw-e2e.sh`
      wrapper builds the ebpf object as the user, then runs `--ignored` as
      root (`sudo -E`)
- [x] Smoke tests (`tests/smoke.rs`): prog attaches on veth; per-dest counters
      increment (UDP); UDP forwarded to a real vm listener; v4 SYN rate limit
      drops over-rate SYNs
- [x] Doc: docs/agents/fw-testing.md (how to run, kernel prereqs, adding
      scenarios); registered in AGENTS.md index
- Dev-deps added to lnvps_fw_service: `nix` (sched/setns) + `libc` (raw
      sockets), test-only. Normal `cargo test` stays green (4 tests ignored).
- VALIDATED: `scripts/fw-e2e.sh` run as root — all 4 smoke tests pass on the
      real netns/veth datapath (attach, counters, UDP forward-to-vm, SYN-rate
      drop) in ~3s on kernel 6.12.

### Increment 3 — Passive egress port learning (M-L) ✅ DONE
- [x] TC egress (SchedClassifier `tc_lnvps_egress`) in `lnvps_ebpf`: parses
      outbound eth/v4/v6 + tcp/udp; TCP SYN-ACK from `src ip:port` →
      `OPEN_PORTS_V4/V6: LruHashMap<PortKeyV4/V6, LastSeen>`; outbound UDP
      from `ip:port` → UDP service. Always `TC_ACT_OK` (never drops/mutates).
      Ports decoded host-order via `from_be_bytes` on both learn + (future)
      lookup sides for endianness consistency
- [x] UDP ephemeral-port pollution: learn-all + short TTL + attack-time
      relearn tradeoff documented in the classifier doc-comment
- [x] `learn_port_v4/v6` refresh `last_seen` on existing entries (LRU insert
      otherwise); `LastSeen` added to lnvps_fw_common (Pod, size test)
- [x] fw_service loads + attaches BOTH programs (XDP ingress + TC egress) to
      every configured interface; `qdisc_add_clsact` best-effort for <6.6,
      TCX on 6.6+
- [x] GC: `gc::gc_open_ports` sweeps `OPEN_PORTS_*` removing entries older
      than TTL (monotonic clock == bpf_ktime_get_ns); tokio interval loop.
      Pure `is_expired` unit-tested
- [x] YAML config (NOT toml — user pref) via serde_yaml_ng, kebab-case to
      match LNVPS API config style: interfaces, learning TTL/GC/stats,
      thresholds (parsed now, consumed inc 4). `config.example.yaml`.
      11 config/gc unit tests
- [x] Refactor: `src/lib.rs` exposes `config` + `gc` so the harness reuses the
      real GC (bin + lib in one package)
- [x] Harness: TC egress attached on f_up too; `open_port_v4/v6`,
      `open_port_count_v4`, `gc_open_ports_v4` accessors; traffic helpers
      `tcp_listen_accept`, `tcp_connect`, `udp_send_from`
- [x] Harness tests (`tests/learning.rs`, root-gated): SYN-ACK egress learns
      TCP port; outbound UDP learns UDP port; TTL expiry (long-TTL keeps,
      zero-TTL removes). All 3 pass via `scripts/fw-e2e.sh --test learning`
- VALIDATED as root: 4 smoke + 3 learning harness tests green; 8 common + 11
      service unit tests green; clippy/fmt clean

### Increment 4 — Attack detection + phase-1 enforcement (L) ✅ DONE
- [x] Detection loop (`runtime::run_detection`, injected timestamp): samples
      per-dest counters, computes rates, runs per-dest state machine writing
      `V4/V6_DEST_STATE`. Normal→Mitigate on pps/SYN/bytes entry threshold;
      Mitigate→Normal after cooldown below exit thresholds (hysteresis).
      Sample interval configurable (default 500ms)
- [x] XDP enforcement when dest in Mitigate (`mitigate_v4/v6`): pass only
      learned-open TCP/UDP ports (`port_is_open_*` on OPEN_PORTS), rate-limit
      ICMP (`icmp_allowed_*`, dedicated buckets), drop everything else
      (incl. non-TCP/UDP/ICMP protos). SYN rate limiter still always-on
- [x] Fragments: v4 non-first fragment (`frag_offset()!=0`) → dropped under
      mitigation; v6 fragment/ext-header next_hdr falls into drop-all-else
- [x] Per-dest drop counter already tracked (`account` on XDP_DROP);
      DestState maps added (deferred from inc 1, now have a real reader)
- [x] Structured mitigation events: `MITIGATION START/STOP` logs with dest,
      trigger rates, peak rates, total drops
- [x] Pure detection logic in `detect.rs` (compute_rates / evaluate /
      process_sample) — 11 unit tests (entry, syn-only, hysteresis band,
      cooldown, resurgence-resets, counter-reset, peak tracking)
- [x] Harness tests (`tests/mitigation.rs`, root-gated): closed-port drop,
      learned-port passes under mitigation, flood→Mitigate + cooldown→Normal
      via the real run_detection with injected clock. All 3 pass
- [x] Config: exit-pct / cooldown-secs / sample-interval-ms added to
      thresholds; `detection_config()` builder; example yaml updated
- Refactor: detection driver moved to `runtime.rs` (lib) with injectable
      `now_ns` so the harness exercises the real code (like gc). main.rs
      passes the monotonic clock
- VALIDATED as root: 10 harness tests (4 smoke + 3 learning + 3 mitigation)
      + 8 common + 22 service unit tests green; clippy/fmt clean
- Note: PortKeyV4/V6 gained `::new()` (zeroes _pad) used by lookup + learn

### Increment 5 — Per-source rate limits + CIDR escalation (L) ✅ DONE
- [x] Per-source token buckets (`V4/V6_SRC_RATE`) consulted under mitigation;
      over-rate sources dropped and flagged (`record_src_drop_*` →
      `V4/V6_SRC_DROPS`). Global limit via `SRC_RATE_LIMITS` config map (set
      from config; DEFAULT_SRC_* fallback). Order in mitigate_*: fragment →
      CIDR block → per-source rate → dest port/icmp policy
- [x] CIDR escalation: userspace aggregates offending sources by /24 (v4) /
      /64 (v6) via pure `cidr.rs` (offending_cidrs_v4/v6, drop_deltas);
      installs blocks into `V4/V6_CIDR_SRC` LpmTrie; XDP checks trie first
      (`cidr_blocked_*`, full-length LPM lookup). Single-level aggregation
      (deeper /16,/8 escalation deferred; noted below)
- [x] v6 equivalent (LpmTrie<[u8;16],u8>, /64 grouping)
- [x] Decay: `run_escalation` refreshes block timestamps for still-offending
      prefixes and removes blocks not refreshed within block-ttl-secs
- [x] Pure aggregation unit tests (6 in cidr.rs: /24 grouping, min-sources,
      distinct /24s, repeat-source, v6 /64, drop_deltas reset/new)
- [x] Harness test (`tests/escalation.rs`): spoofed multi-source /24 flood
      (raw IP_HDRINCL UDP, sources emulated in one netns) → /24 blocked;
      unrelated /24 safe; block decays after TTL. Passes
- [x] BONUS (user ask): drop/accept RATE tracking — `Rates` now carries
      drop_pps/pass_pps (computed from dropped delta + packets-dropped delta),
      peak-tracked, surfaced in MITIGATION START/STOP events
- [x] Config: `escalation` section (src-rate-pps/burst, min-src-drops,
      min-sources, block-ttl-secs); escalation_config()/block_ttl_ns()
- Design note: only aggregated CIDRs live in the trie (no /32s); individual
      sources are rate-limited via buckets, so no overlap-removal needed.
      Multi-level escalation (/24→/16→/8) is a future extension
- VALIDATED as root: 11 harness tests (4 smoke + 3 learning + 3 mitigation +
      1 escalation) + 8 common + 29 service unit tests green; clippy/fmt clean

### Increment 6 — SYN-proxy / SYN-cookies (L) ✅ DONE (v4 + v6)

Built with the flag model (not a ladder stage): userspace OR's the `SYN_PROXY`
flag into a mitigating dest/prefix once `syn_pps >= syn-proxy-syn-pps`; the XDP
datapath applies it independently of the other flags.

- [x] `SYN_PROXY` flag enabled by userspace on sustained SYN floods
      (`enforced_flags`, config `escalation.syn-proxy-syn-pps`, default 5000)
- [x] Manual XDP SYN-cookie (chose the manual path over
      `bpf_tcp_raw_gen_syncookie_*` for portability): SYN → craft SYN-ACK with
      the cookie as seq (byte-wise in-place rewrite + checksums) and XDP_TX;
      ACK → validate cookie (current+prev secret) → allowlist src into a
      verified-source LRU (`VERIFIED_V4/V6`); verified sources pass through
- [x] Cookie = `syn_cookie_v4`/`_v6` (FNV-1a over the 4-tuple + rotating
      2-slot `COOKIE_SECRET`); userspace seeds + rotates it (120s); need not be
      cryptographic since a spoofed src never receives the SYN-ACK
- [x] Verifier budget solved with **tail calls**: `xdp_syn_proxy` /
      `xdp_syn_proxy_v6` in a PROG_ARRAY (`SYN_PROXY_JUMP`, slots 0/1),
      tail-called from `mitigate_v4/v6`; rewrite verified independently
- [x] IPv6 parity: `tx_synack_v6` (40-byte header, 16-byte address swaps, TCP
      checksum over the v6 pseudo-header, no IPv6 header checksum)
- [x] Verified-source TTL GC in the daemon (both families)
- [x] Harness tests (`tests/syn_proxy.rs`, root): a real client completes the
      cookie handshake and is verified (v4 + v6); spoofed SYNs never verify
- Kernel-version gating NOT needed: the manual cookie + XDP_TX path works on
  the baseline kernel (6.12) and in SKB/generic mode on veth; no helper
  dependency. (Confirmed XDP_TX works in generic mode.)
- VALIDATED as root: 16 harness (4 smoke + 3 learning + 4 mitigation + 1
  escalation + 1 carpet_bomb + 3 syn_proxy) + full unit suite green.

**Verifier lessons (the big EFAULT hunt):** a *data-dependent* `while` loop (the
checksum fold) is rejected as an opaque EFAULT at load — use a loop-free
double-fold; constant-bound `while` loops (byte swaps) are fine. Whole-array
field assignments lower to `memmove` on packet memory and explode verifier
state — do byte-wise swaps. Use bounds-checked typed header pointers, not raw
`usize` packet arithmetic.

### Increment 7 — RESTful control API on fw_service (M)

**Scope:** fw_service exposes a small, token-authenticated RESTful API and is
the *server*; the primary service (`lnvps_api`) is the *client*. fw_service
holds **no database** — rules live in memory (pushed by `lnvps_api`, which is
the source of truth and re-pushes on reconnect) and events live in a bounded
in-memory ring buffer that `lnvps_api` polls and persists. This keeps the
datapath host stateless and puts all durable rules/incident-log storage in
`lnvps_api`.

Direction of calls: `lnvps_api` → fw_service (push rules, read state/events,
issue manual overrides). fw_service never calls `lnvps_api` and never touches a
DB.

- [ ] **HTTP server** in fw_service (lightweight async framework, e.g. `axum`
      or `hyper`; NOT Rocket — keep the datapath deps minimal), bound to a
      configurable `api.listen` address (default loopback / management iface),
      running alongside the existing tokio control loop.
- [ ] **API-token auth**: a static bearer token from config (`api.token`, or an
      env var), checked on every request via `Authorization: Bearer <token>`
      with a constant-time compare. Optional allow-list of source IPs. TLS is
      out of scope (terminate at a reverse proxy / private link) — document it.
- [ ] **Config**: new `api` section (`listen`, `token`, optional `allow-ips`,
      `events-buffer` size). Local YAML still bootstraps interfaces/thresholds;
      rules pushed over the API override/augment the local defaults in memory.
- [ ] **Rules endpoints** (in-memory ruleset behind an `Arc<RwLock<_>>`, applied
      to the BPF maps by the control loop):
  - `GET  /api/v1/rules` — current protected prefixes, per-prefix thresholds,
    and manual overrides.
  - `PUT  /api/v1/rules` — replace the full ruleset atomically (idempotent;
    `lnvps_api` re-pushes the desired state, e.g. on fw_service restart).
- [ ] **Manual override endpoints** (operator / `lnvps_api`-driven):
  - `POST   /api/v1/mitigations` — force a dest/prefix into mitigation with an
    explicit protection-flag set (e.g. pin PORT_FILTER|SYN_PROXY).
  - `DELETE /api/v1/mitigations/{cidr}` — clear a manual override / force-exit.
- [ ] **State + events endpoints** (read-only, for `lnvps_api` to poll & store):
  - `GET /api/v1/status` — daemon health: version, uptime, attached
    interfaces, map occupancy, active-mitigation count.
  - `GET /api/v1/mitigations` — currently active mitigations (dest/prefix,
    flags, since, peak pps/bps/syn, drop counters).
  - `GET /api/v1/events?since=<cursor>` — mitigation start/stop events from the
    bounded in-memory ring buffer, with a monotonic cursor so `lnvps_api` polls
    incrementally and persists them itself. Overflow drops oldest (documented;
    `lnvps_api` owns durable history).
- [ ] **Wire the detection loop to the ring buffer**: every MITIGATION
      START/STOP already logged also pushes a structured event into the buffer.
- [ ] **Docs**: `docs/agents/fw-api.md` — endpoint reference, auth, the
      push-rules / poll-events model, and the `lnvps_api`-side integration
      contract (what `lnvps_api` must implement: a client that pushes rules and
      a poller that persists events into its own DB + admin surface).
- [ ] **Tests**: API handler unit/integration tests (auth accept/reject,
      rules round-trip PUT→GET, manual mitigation reflected in the dest-state
      map via the harness, event buffer cursor/overflow semantics).

Deferred to `lnvps_api` (separate repo-side task, out of this increment): the
database schema for rules/incident logs, the rules-push client, the
event-poll-and-persist loop, and the admin API/UI that reads them. This
increment only delivers the fw_service server side of that contract.

### Increment 8 — Metrics, packaging, hardening (M)
- [ ] Prometheus metrics endpoint on fw_service: per-dest pass/drop, learned
      port counts, state distribution, map occupancy, event counters
- [ ] Systemd unit + Dockerfile (host-privileged) for fw_service; docs in
      docs/agents/ for running/debugging (mirroring lnvps_host_util pattern)
- [ ] Fail-open review: every map error path must XDP_PASS, never ABORT in
      production builds; remove `error!` log-per-packet hot paths
- [ ] Load-test script (scripts/) using e.g. trafgen/hping3 notes to validate
      detection + mitigation end-to-end on a lab host

## Architecture refactor (2026-07-08, user directive)

**eBPF = count + enforce only; userspace = all decisions.** Removed all
in-kernel token buckets (SYN/per-source/ICMP rate limiting). eBPF now:
- writes counters only (per-dest `DestCounters`; per-source packet counts in a
  **bounded LRU** `V4/V6_SRC_COUNTERS`, incremented only under mitigation);
- enforces userspace-written tables via pure lookups: `DEST_STATE` mode,
  `OPEN_PORTS_*` allow-list, `V4/V6_CIDR_SRC` LPM block trie.
- Steady state (NORMAL) is pass-all + learn; SYN protection folds into detection
  (high syn_pps -> mitigate), no always-on limiter.

Userspace `runtime::run_control` (one tick, injectable clock): dest detection +
per-source rate math -> multi-level CIDR aggregation (/32->/24->/16->/8,
/128->/64->/48->/32 via `cidr::aggregate_v4/v6`) -> reconcile LPM trie with TTL
decay. The trie is the single bounded block structure (holds /32s and aggregated
prefixes); the per-source counter map is LRU-bounded. No flat per-/32 block map.

**Threat-model note (user, 2026-07-08):** real threat is spoofed carpet-bomb /
reflection floods from millions of source IPs across the whole prefix. Source
blocking is the WRONG axis for that (LRU thrashes, spoofed IPs unblockable) and
is kept only for real botnets. The scaling defences are per-destination
mitigation + drop-to-non-open-ports (source-count-independent) and SYN-proxy
(inc 6) for open TCP ports.

### Prefix-level (carpet-bomb) detection ✅ DONE
- [x] `DEST_STATE` converted HashMap -> LPM trie: userspace mitigates a single
      IP (/32 entry) or a whole protected prefix (/22 etc.) with one entry;
      XDP does one longest-prefix lookup for dest mode.
- [x] `protected` prefixes in config (CIDR strings, host bits masked, bit-level
      mask supports non-byte-aligned like /22); API-sourced later (inc 7).
- [x] Network-aggregate detection (`runtime::detect_prefix`): sums per-dest
      counters across each protected prefix each tick; flips the prefix when the
      aggregate crosses the `network` thresholds. PREFIX MITIGATION START/STOP
      events. Separate per-prefix trackers with hysteresis/cooldown.
- [x] Harness test (`tests/carpet_bomb.rs`): thin spread across a /24 (no single
      dst trips) -> whole /24 flips to mitigate; outside-prefix stays normal;
      cooldown restores. Passes.
- Config: `network` thresholds section (network-scale defaults) + `protected`
      list; parse_protected unit-tested. RuntimeConfig now carries network cfg +
      protected prefixes; run_control does per-dest AND per-prefix detection
      into the shared dest-state trie.
- VALIDATED as root: 12 harness tests + 32 service unit tests green.

## Mitigation escalation ladder (2026-07-08, protection review)

User directive: prioritise layers by efficacy (high illegit-drop, low false-
positive) — the cheap open-port allow-list is phase 1; source blocking is last.
`DEST_MODE` is a BITMASK of independent protection FLAGS (user refinement:
not a strict ladder — any subset can be active at once). XDP applies each set
flag independently:
- NORMAL (0): pass + learn + count.
- PORT_FILTER (1<<0): drop fragments + traffic to non-learned ports (ICMP
      passes). The heavy lifter; set on any detection trip (per-dest OR prefix).
- SYN_PROXY (1<<1, reserved inc 6): validate TCP handshakes to open ports.
- RATE_CAPS (1<<2, reserved): per-(dst,port) caps for open UDP/ICMP.
- SOURCE_BLOCK (1<<3): also consult the CIDR trie (drop blocked sources).
Userspace enables flags in efficacy order (PORT_FILTER base, then OR in others
as warranted); the datapath treats them as an orthogonal set.

Escalation is residual-driven + spoof-gated (userspace, `runtime`):
- source analysis runs FIRST each tick; offenders computed from bounded LRU
      per-source counts. SPOOF GATE: if offender count > `max-real-sources`,
      skip source blocking entirely (spoofed floods are unblockable; the port
      filter carries them). Only bounded/real offenders get aggregated into the
      CIDR trie.
- a mitigating dest/prefix gets the SOURCE_BLOCK flag OR'd in only if `pass_pps`
      (traffic still getting through after the port filter) stays >=
      `escalate-pass-pps` AND a source block is active. Otherwise flags stay
      PORT_FILTER only.
- XDP gates the CIDR consult on the SOURCE_BLOCK flag, so source blocking never
      fires until userspace sets it. Verified by
      `tests/mitigation.rs::source_block_only_when_flag_set` (blocked source to
      an open port passes with PORT_FILTER, dropped with +SOURCE_BLOCK).
- Config: escalate-pass-pps, max-real-sources added to `escalation`.
- VALIDATED as root: 13 harness + 32 unit tests green.
- Deferred (user): phase-1 open-port FP hardening (config/firewall/API port
      seeding) — own task. SYN-proxy (level 2) is inc 6; UDP per-(dst,port)
      caps (level 3) later.

## Notes

- Increment order is dependency-driven; 1→2→3→4 delivers the user's phase-1
  ask (open-port tracking + drop-everything-else under attack) with an
  end-to-end virtual-network test harness. 5/6 are escalation phases;
  7/8 productionize.
- Test harness rationale: veth supports generic (SKB-mode) XDP and TC
  clsact, so the whole datapath is testable in netns on any modern kernel
  without hardware. Native-mode/driver behaviour still needs a lab host
  (increment 8 load-test script). Harness tests require root; they are
  `#[ignore]`d so `cargo test` stays green for normal runs.
- Workflow (user, 2026-07-08): this is a new service — no PR per increment;
  commit and push increments directly to master. Still ask before
  committing/pushing (common.md rules unchanged).
- eBPF code can't use the normal test harness — keep all detection/
  aggregation logic in userspace where possible so it's unit-testable
  (coverage rules apply to fw_service userspace fns).
- Open question (revisit in inc 3): UDP ephemeral-port learning pollution.
  Mitigation-time relearning window + short UDP TTL is the fallback.
- Open question (inc 7): whether fw_service talks to lnvps_api (public) or a
  new internal listener — decide when starting that increment.
