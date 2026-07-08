# Firewall Datapath Testing (`lnvps_fw`)

The XDP/eBPF DDoS-protection datapath lives in the `lnvps_fw/` sub-workspace
(see `work/ddos-protection.md`). Because eBPF code cannot run under the normal
unit-test harness, datapath behaviour is verified with a **virtualized-network
integration harness** built from Linux network namespaces and veth pairs. This
doc covers how to run it, kernel prerequisites, and how to add scenarios.

## What the harness does

`lnvps_fw_service/tests/harness/` builds this topology per test:

```
[attacker]  a_up <──veth──> f_up  [filter]  f_dn <──veth──> v_dn  [vm]
 10.0.0.2/24                10.0.0.1/24      10.0.1.1/24            10.0.1.2/24
 fd00:0::2/64               fd00:0::1/64     fd00:1::1/64           fd00:1::2/64
                            (XDP attaches on f_up ingress, SKB mode)
```

- The compiled eBPF object is loaded into the `filter` namespace and the
  `xdp_lnvps` program is attached to the uplink veth (`f_up`) in **SKB /
  generic mode**, which veth supports on any modern kernel — no special NIC or
  driver-mode XDP is required.
- The `filter` namespace forwards between its two veth ends, so traffic sent by
  the attacker to the VM address transits the XDP ingress hook before reaching
  a real socket in the `vm` namespace. This mirrors the production datapath
  (attack traffic entering an uplink NIC bound for a guest IP).
- Traffic generators (`tests/harness/traffic.rs`) run on threads pinned into a
  namespace via `setns` (network namespaces are per-thread): UDP send/recv with
  std sockets, and a raw-socket TCP SYN flood for rate-limit tests.
- Assertions read the BPF maps through typed accessors on the `Harness` struct
  (`dest_counters_v4/v6`, `syn_bucket_v4`, `set_syn_limits_v4`, …).

Topology and program setup are RAII: dropping the `Harness`/`NetnsTopology`
tears down the namespaces (and their veths) even on panic.

## Prerequisites

- **Linux** with network-namespace, veth, and generic-XDP support (any kernel
  ≥ ~5.4; developed against 6.12).
- **root** (`CAP_NET_ADMIN` + `CAP_BPF`) — required to create namespaces, move
  veths, load/attach BPF, and open raw sockets.
- **iproute2** (`ip`) on `PATH`.
- The eBPF build toolchain (only needed once, to build the object):
  - a Rust **nightly** toolchain with the `rust-src` component, and
  - **bpf-linker** (`cargo install bpf-linker`).
  The object is built for `bpfel-unknown-none` automatically by `aya-build`
  from `lnvps_fw_service/build.rs`.

## Running

Use the wrapper, which builds the eBPF object first (as your user) and then
runs the `#[ignore]`d harness tests as root:

```sh
./scripts/fw-e2e.sh                     # all smoke tests
./scripts/fw-e2e.sh --filter syn_rate   # one scenario
```

Or manually:

```sh
# build (produces the ebpf object via build.rs)
cargo test -p lnvps_fw_service --test smoke --no-run
# run the ignored, root-only tests
sudo -E cargo test -p lnvps_fw_service --test smoke -- --ignored --test-threads=1
```

`--test-threads=1` avoids many namespaces being created at once; the harness is
safe to parallelise (names are unique per instance) but serial runs are easier
to read.

A normal `cargo test` (unprivileged) stays green: the harness tests are
`#[ignore]`d and additionally short-circuit via `require_root()`.

## Current scenarios

`tests/smoke.rs` (increment 1 datapath):
- `prog_attaches_on_veth` — the XDP program attaches to a veth uplink.
- `dest_counters_increment` — UDP to the VM address increments per-dest
  counters.
- `udp_delivered_to_vm_listener` — a datagram is forwarded through the filter
  to a real listener in the `vm` namespace.
- `syn_rate_limit_drops_over_rate` — with tightened limits, over-rate SYNs are
  dropped (`dropped` counter rises).

`tests/learning.rs` (increment 3 passive port learning):
- `tcp_open_port_learned` — a VM TCP listener's SYN-ACK teaches the TC egress
  learner that the port is open (`OPEN_PORTS_V4`).
- `udp_service_learned` — outbound UDP from a VM source port is learned.
- `ttl_expiry_removes_entry` — the shared userspace GC keeps fresh entries and
  removes them under a zero-TTL sweep.

`tests/mitigation.rs` (detection + escalation-ladder enforcement):
- `mitigation_drops_closed_ports` — under mitigation, UDP to an unlearned port
  is dropped (drop counter rises).
- `mitigation_allows_learned_ports` — under mitigation, a TCP handshake to a
  learned-open port still completes.
- `detection_flip_and_cooldown` — a flood flips the dest to mitigation (via the
  real `runtime::run_control` with injected timestamps) and the cooldown
  returns it to NORMAL once the flood stops.
- `source_block_only_when_flag_set` — a CIDR-blocked source to an *open* port is
  passed with the PORT_FILTER flag alone but dropped once the SOURCE_BLOCK flag
  is also set, proving protection flags are independent and source blocking is
  gated to when userspace enables it.

`tests/escalation.rs` (increment 5 per-source rate + CIDR escalation):
- `cidr_escalation_blocks_offending_v24` — a spoofed-source flood across a /24
  (raw sockets emulate many sources) escalates to a CIDR-wide block via the
  real `runtime::run_escalation`; an unrelated /24 is unaffected; the block
  decays after its TTL once the flood stops.

`tests/carpet_bomb.rs` (prefix-level / carpet-bomb defense):
- `thin_carpet_bomb_flips_whole_prefix` — a flood spread thinly across a
  protected /24 (no single dest trips its threshold) trips the aggregate
  network threshold and flips the whole prefix to mitigation via one dest-state
  LPM entry; addresses outside the prefix stay normal; cooldown restores it.

`tests/syn_proxy.rs` (SYN-proxy / SYN-cookie datapath):
- `syn_proxy_verifies_real_client` — under the SYN_PROXY flag, a real client's
  TCP handshake completes through the XDP-crafted SYN-cookie SYN-ACK (the client
  kernel only accepts it if the IP/TCP checksums and cookie are correct), and
  the source is then marked verified. Also confirms XDP_TX works in SKB mode on
  veth.
- `syn_proxy_spoofed_not_verified` — spoofed SYNs that never complete the
  handshake are never verified.
- `syn_proxy_v6_verifies_real_client` — the IPv6 datapath (`xdp_syn_proxy_v6`,
  40-byte header rewrite + pseudo-header TCP checksum): a real IPv6 client
  completes the cookie handshake and is verified.

`tests/gre_decap.rs` (router underlay GRE decapsulation):
- `gre_inner_closed_port_dropped` / `gre_inner_open_port_passed` — raw
  GRE-encapsulated SYNs (outer IP proto 47 → GRE → inner IP) to a mitigating VM
  are decapsulated in-XDP and filtered on the *inner* header (closed port
  dropped, open port passed), verified via the per-dest counters.

Run a single binary with `scripts/fw-e2e.sh --test learning` (or `--test
mitigation`, `--test escalation`, `--test carpet_bomb`, `--test syn_proxy`,
`--test gre_decap`, `--test smoke`).

## Service configuration

`lnvps_fw_service` loads a YAML config (kebab-case keys, matching the LNVPS API
config style); see `lnvps_fw/lnvps_fw_service/config.example.yaml`. It sets the
uplink interfaces, learned-port TTL / GC interval, stats logging cadence, and
(from increment 4) detection thresholds. Bare interface names may be passed on
the CLI instead of `--config` for quick runs.

## Adding a scenario

1. Add a `#[test] #[ignore = "requires root / CAP_NET_ADMIN"]` function in
   `tests/smoke.rs` (or a new `tests/<name>.rs` with `mod harness;`).
2. Guard it with `if !harness::require_root() { return; }`.
3. `let h = Harness::new()?;` builds the topology + attaches XDP.
4. Drive traffic with `harness::traffic::*`, passing
   `/var/run/netns/<h.topo.*_ns>` as the namespace path.
5. Assert against map accessors on `h`.

If a new BPF map needs to be inspected, add a typed accessor to `Harness` in
`tests/harness/mod.rs` rather than reaching into `bpf` from each test.

## Limitations

- SKB/generic-mode XDP exercises the program logic and verifier but not
  native/driver-mode behaviour or offload. Native-mode validation still needs a
  lab host (planned firewall load-test script, later increment).
- Raw-socket SYN flooding is IPv4-only in the current harness; IPv6 flood
  helpers can be added when the v6 mitigation path needs them.
