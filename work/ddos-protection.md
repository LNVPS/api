# XDP DDoS Protection System for VM Hosts

**Status:** in-progress
**Started:** 2026-07-08
**Last updated:** 2026-07-08 (Increment 3 complete)

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
- **Deployment:** `lnvps_fw_service` becomes a daemon on each VM host,
  attaching XDP to uplink NIC(s), syncing config (its IP ranges, thresholds)
  from the LNVPS API, exporting metrics.
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
      │ - syncs protected prefixes + thresholds from API     │
      │ - prometheus metrics + mitigation event reporting    │
      └──────────────────────────────────────────────────────┘
                     │ HTTPS
                LNVPS API / admin API / DB
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

### Increment 4 — Attack detection + phase-1 enforcement (L)
- [ ] fw_service detection loop: sample per-dest counters at interval
      (e.g. 500ms), compute rates, state machine per dest IP:
      Normal → Mitigate when pps/SYN/bytes thresholds exceeded;
      Mitigate → Normal after cooldown below exit thresholds (hysteresis)
- [ ] XDP enforcement when dest in Mitigate: drop inbound TCP/UDP to ports
      not present in `OPEN_PORTS_*`; rate-limit ICMP; pass learned ports
- [ ] Fragments: drop non-first fragments to mitigated dests (no L4 header)
- [ ] Per-dest drop/pass counters for visibility
- [ ] Structured mitigation event log from fw_service (start/stop, dest,
      trigger metric, drop counts)
- [ ] Unit tests for detection state machine (pure userspace logic)
- [ ] Harness tests: flood dest from attacker netns → dest flips to Mitigate;
      traffic to learned-open port still passes, closed port dropped;
      flood stops → cooldown returns dest to Normal

### Increment 5 — Per-source rate limits + CIDR escalation (L)
- [ ] For dests in Mitigate: per-src token buckets
      (`LruHashMap<SrcIp, Bucket>`), drop sources exceeding limits
- [ ] CIDR escalation per maps.rs design: userspace aggregates offending
      /32s; when count in a /24 (…up to /8 per V4_MIN_CIDR/V4_MAX_CIDR)
      breaches threshold, insert wider entry into `V4_CIDR_SRC` LpmTrie and
      remove overlapped narrower entries; XDP checks LpmTrie first
- [ ] v6 equivalent (LpmTrie<[u8;16]>, /64-based escalation)
- [ ] Expiry/decay of CIDR blocks in userspace GC
- [ ] Tests for aggregation/escalation logic
- [ ] Harness tests: multi-source flood (aliased addrs in attacker netns
      across a /24) triggers CIDR-wide block; unrelated source unaffected

### Increment 6 — SYN-proxy / SYN-cookie stage (L)
- [ ] Escalation: Mitigate → SynProxy when SYN flood persists on learned-open
      ports despite phase 1
- [ ] XDP SYN-cookie implementation: reply to SYN with SYN-ACK + cookie
      (XDP_TX, requires checksum + packet rewrite helpers,
      `bpf_tcp_raw_gen_syncookie_ipv{4,6}` where kernel supports, else manual
      cookie); validate ACK cookie, then allowlist src into a verified-src
      LRU map so subsequent packets pass
- [ ] Kernel version gating + graceful fallback (stay in Mitigate if
      helpers unavailable)
- [ ] Careful verifier budget check — may need tail calls
      (`lnvps_xdp_l4` stub exists)
- [ ] Harness tests: under SynProxy state a full TCP handshake from a real
      client socket still completes (cookie path); spoofed SYNs never reach
      the vm netns listener

### Increment 7 — Control plane integration (L)
- [ ] DB: host agent auth (token per host) + `host_mitigation_event` table
      (host_id, ip, started, ended, trigger, peak rates, drops); migration
- [ ] Internal API endpoints for fw_service: fetch protected prefixes for the
      host (from ip_assignment/ip_range), thresholds/overrides; POST
      mitigation events + periodic stats
- [ ] fw_service: API sync loop replacing/augmenting local TOML (TOML keeps
      bootstrap: API URL, token, interfaces)
- [ ] Admin API: list active/historical mitigation events, per-IP mitigation
      state, manual override (force mitigate / whitelist)
- [ ] ADMIN_API_ENDPOINTS.md + API_CHANGELOG.md updates

### Increment 8 — Metrics, packaging, hardening (M)
- [ ] Prometheus metrics endpoint on fw_service: per-dest pass/drop, learned
      port counts, state distribution, map occupancy, event counters
- [ ] Systemd unit + Dockerfile (host-privileged) for fw_service; docs in
      docs/agents/ for running/debugging (mirroring lnvps_host_util pattern)
- [ ] Fail-open review: every map error path must XDP_PASS, never ABORT in
      production builds; remove `error!` log-per-packet hot paths
- [ ] Load-test script (scripts/) using e.g. trafgen/hping3 notes to validate
      detection + mitigation end-to-end on a lab host

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
