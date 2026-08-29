# LNVPS VPN (Mullvad-style multi-region WireGuard)

**Status:** in-progress
**Started:** 2026-08-27
**Last updated:** 2026-08-27 (increments 1-4 restructured: a VPN device is a `tunnel`)

## Goal

Sell a consumer VPN subscription: one subscription per account, a small number of device
slots (default 5), each device holding **one keypair and one fixed inner address that works
on every region**. Region selection is a client-side choice of endpoint plus server public
key, exactly as Mullvad does it, with no server-side state per region per device.

Done looks like: a user subscribes, pays over Lightning, registers up to 5 device public
keys, downloads a config per region, and traffic egresses via the route server's own
SNAT with no per-device logging retained.

## Non-goals (v1)

- Managing SNAT/masquerade or egress firewalling from the API. The route server does its
  own NAT; LNVPS manages tunnels and peers only.
- Per-device or per-region pricing. One flat plan, region is free choice.
- Multihop / device-to-device routing between regions.
- A first-party client app. Config files (and a QR) only.
- Port forwarding, dedicated exit IPs, static per-customer public addresses.
- Traffic quota enforcement. Counters are collected in aggregate; no metered billing in v1.

## Findings

### What already exists and is reused as-is

| Piece | Location |
|---|---|
| WireGuard keygen, pubkey derivation, base64 | `lnvps_api_common/src/wireguard.rs` |
| `tunnel_pool` (router, region, listen addr/port, server keypair, cidrs, MTU, keepalive) | `lnvps_db/migrations/20260808120000_tunnel_pool.sql` |
| `TunnelRouter` capability trait | `lnvps_api/src/router/mod.rs:150` |
| Linux-over-SSH and MikroTik backends | `lnvps_api/src/router/{linux_ssh,mikrotik}.rs` |
| Interface push + peer reconcile with drift reporting | `lnvps_api/src/worker.rs:1006` (`sync_tunnel_pool`), `:1123` (`reconcile_tunnel_peers`) |
| Desired-state planner | `lnvps_api/src/provisioner/tunnel.rs:357` (`plan_pool`) |
| Generic recurring billing (subscription 1:N line items) | `lnvps_db/src/model.rs:2899` onward |
| Proration math for mid-cycle changes | `lnvps_api_common/src/pricing.rs:1475`, `:1549` |
| Refunds | `lnvps_api_common/src/refund.rs` |
| Declarative netlink data-plane agent (the pattern to copy) | `lnvps_node/src/net.rs` |
| Agent outbound auth / inbound control auth / TLS identity | `lnvps_node/src/{credential,control_auth,tls}.rs` |
| Node-facing machine API surface (the pattern to copy) | `lnvps_api/src/api/marketplace.rs:47` |
| netns end-to-end WireGuard harness | `lnvps_e2e/tests/tunnel_netns.rs`, `scripts/tunnel-e2e.sh` |

### What does not fit and why

A VPN device is **not** a `tunnel` row. The `tunnel` table is built on three constraints
that are correct for a marketplace node and wrong for a floating device:

- `uk_tunnel_peer_pubkey` is globally unique, so one key cannot be a peer in two pools.
- `uk_tunnel_address4` / `uk_tunnel_address6` are globally unique, so an address exists once.
- the composite FK `(pool_id, router_id)` deliberately pins a tunnel to one route server.

Do not relax any of these. `20260805130000_tunnel.sql` already says a tunnel's purpose is
decided by whichever table links to it; a device links differently enough to be its own table.

Device addresses therefore come from a **global device block**, not from `tunnel_pool.cidr4`.
A device is `10.64.0.7/32` in every region simultaneously.

### Scale problems in the current code

- `set_tunnel_peer` is one peer per call, and on the Linux backend one SSH exec running one
  `wg set` (`linux_ssh.rs:799`). N devices x M regions makes this unusable.
- `plan_pool` calls `guest_addresses()` per tunnel, which hits `get_marketplace_node_by_tunnel`
  for every peer on every reconcile (`provisioner/tunnel.rs:560`). Needs a short-circuit for
  non-node peers.
- `sync_node_tunnel` runs a full `plan_pool` to push a single peer (`worker.rs:1226`).
- `tunnel_traffic()` is per **interface**, not per peer (`linux_ssh.rs:734`). With every device
  a peer on every interface, interface totals attribute nothing. Per-peer counters exist in
  `wg show all dump` and `parse_wg_dump` (`linux_ssh.rs:886`) already parses the format but
  discards the transfer columns.
- `router::Tunnel` carries the full `peers: Vec<WireguardPeer>` inline, so `list_tunnels()`
  on a VPN pool would return every device sold, on every polling cycle, on every router.

### How Mullvad does it (researched 2026-08-27)

Confirmed from public sources:

- Device registration is central. The client generates the keypair, POSTs only the pubkey, and
  the API returns `ipv4_address` / `ipv6_address` (`mullvad-api/src/device.rs`, `DeviceResponse`).
- The relay list is public (`api.mullvad.net/public/relays/wireguard/v1/`) with a `public_key`
  and `ipv4_addr_in` per relay; their own `mullvad-wg.sh` builds one `.conf` per relay sharing a
  single `[Interface]` block. Region switching is purely client-side.
- Relays remove and reapply a peer after 600s without a handshake, to scrub the peer's
  `endpoint` field, which holds the user's real IP (mullvad.net/en/help/why-wireguard).
- All relays are RAM-only with no disks, so the peer set is fetched from central after boot.

Not confirmed: whether a relay preloads every device or adds them lazily on first handshake.
Either is compatible with the design below.

### Regulatory and jurisdiction questions

Tracked outside this repository. Resolve with counsel before the service is offered for
sale, and before any claim is made about what is or is not retained.

## Design decisions

0. **There is no subscription type.** `subscription` has no column describing what is sold; the
   discriminant is `subscription_line_item.subscription_type`, typed as `LineItemType`. That is
   what lets one subscription carry a VM line item and a VPN line item on one renewal date and
   one payment.
1. **One `vpn_subscription` row per account, reused on resubscribe.** MySQL has no partial unique
   index, so a plain `UNIQUE (user_id)` would permanently block a returning customer. Reusing the
   row also means their existing device configs keep working after payment.
2. **`device_limit` is a column on `vpn_subscription`, not in `SubscriptionLineItem.configuration`.**
   `model.rs:3022` is explicit that `configuration` is upgrade bookkeeping only and never describes
   the billed resource. A 5-to-10 device tier upgrade is then a column update on the existing
   proration path with no migration.
3. **Slot cap enforced by the schema**, via `UNIQUE (vpn_subscription_id, slot)` with the allocator
   claiming the lowest free slot in `0..device_limit`. A `COUNT(*) < limit` check followed by an
   insert races and yields a sixth device.
4. **Client generates the keypair.** LNVPS receives only the public half, matching the marketplace
   node model and `wireguard.rs`'s stated rule.
5. **VPN pools are agent-managed and Linux-only.** MikroTik has no bulk peer call.
6. **The trait split:** `pool.router_id` stays. `AgentRouter` implements only the read half of
   `TunnelRouter` (`list_tunnels`, `tunnel_traffic`); the four peer/address/route mutators fall
   through to the existing `op_fatal!` defaults at `router/mod.rs:174-214`, which is the shape the
   trait was already designed for (and what `work/route-server-management.md` planned as
   "netlink agent later behind same traits").
7. **Realisation forks in the worker, not the trait.** `plan_pool` stays the single source of
   desired state for both backends; SSH pools execute it as commands, agent pools serialise it into
   a dataplane document. `reconcile_tunnel_peers` becomes a read-only drift detector for agent
   pools, keeping `TunnelPeerDrift` reporting for both.
8. **Drift by digest.** The agent's `list_tunnels` reports peer count plus a digest of the applied
   set; the full list is pulled only when the digest differs from `plan_pool`'s.
9. **The dataplane document carries no identity.** Peer entries are pubkey plus allowed IPs. No
   account id, no device name. A seized route server yields the key-to-address map and nothing else.
10. **600-second endpoint scrub** on the agent, copied from Mullvad, so customer source IPs do not
    sit in kernel memory.

## Restructure (2026-08-27, after review)

Increments 1-4 were rebuilt on three corrections, all of them the same mistake: inventing a
parallel structure instead of using the one already there.

0. **The block lives on the pool, not the service.** `vpn_service` has no `device_cidr` of its
   own: `tunnel_pool.cidr4` already means "the block this interface's peers come from", and a
   second column meaning the same thing in another table is one more place for the answer to
   differ. What is specific to a VPN is that every interface on a service shares one block, so a
   device keeps one address in every region, and that is enforced on `vpn_service_pool` — a pool
   cannot be linked to a service whose other pools carry a different block, and a linked pool's
   block cannot be edited away from theirs. `ck_tunnel_pool_has_a_block` therefore stays.

1. **A VPN device is a `tunnel` row**, with `pool_id` and `router_id` NULL. The original
   `20260805130000_tunnel.sql` already names this case ("a hand-configured peering, or a VPN on
   a router with no pool"); the earlier objection that the unique indexes forbade it was wrong,
   because a device is one key and one address. `vpn_device` is now a link row carrying only the
   plan, the slot and the customer's label, exactly like `marketplace_node.tunnel_id`.

   This also closes a hole: `vpn_device.address4` and `tunnel.address4` were separately unique,
   so overlapping blocks could hand a device and a node the same address. One table, one index,
   impossible.

2. **`plan_pool` no longer knows what a tunnel is for.** It read guest addresses and probe
   addresses per tunnel, which is marketplace vocabulary in the generic planner and a query per
   peer per reconcile. Prefixes behind a peer now live in `tunnel_route`, refreshed by
   `refresh_node_routes` before a reconcile and read by the planner in one batched query. A VPN
   device has no rows there, so it needs no special case.

   Without this, every VPN device would have been handed a probe address derived by offsetting
   its own v6 address by `0x8000` — which, with random placement, can be another customer's
   real address.

`vpn_subscription` also lost `device_limit`: one flat price per service means a per-plan number
with no price attached. The allowance is `vpn_service.default_device_limit`. And `create_vpn_plan`
lost its resubscribe branch entirely — renewal is a payment against the existing subscription, not
a new line item, so a returning customer renews what they already have and nothing needs
repointing.

**Structure (done).** `provisioner/tunnel.rs` was 1,483 lines holding four unrelated concerns,
with the apply half stranded in `worker.rs` and two public types both called `Tunnel`. Split into:

| module | owns | knows about |
|---|---|---|
| `provisioner/wg/address.rs` | block arithmetic: reserved addresses, carving, placement | nothing, pure |
| `provisioner/wg/plan.rs` | `InterfacePlan`, the desired state of one interface | db, pool, tunnel |
| `provisioner/wg/block.rs` | `PeerBlock`: what an address is carved out of | blocks, placement |
| `provisioner/wg/provisioner.rs` | `TunnelProvisioner`: plan, carve, reconcile, push | plan, block, `TunnelRouter` |
| `provisioner/marketplace_tunnel.rs` | node allocation, dataplane document, route maintenance | nodes, hosts, guests |
| `provisioner/vpn.rs` | device registration | plans, services |

Also renamed: `PoolPlan` to `InterfacePlan` (a pool no longer decides it alone, since a VPN
interface is addressed from its service), and `router::Tunnel` to `router::ObservedInterface`,
which had been colliding with `lnvps_db::Tunnel` — a desired-state row and an observed interface
sharing one name in files that import both.

Both halves are services holding the database once, matching `NetworkProvisioner`:
`TunnelProvisioner` (plan, carve, reconcile, push) and `MarketplaceTunnels` (allocate, dataplane,
refresh routes). Nothing in `provisioner/` takes `db: &Arc<dyn LNVpsDb>` as an argument any more.
`worker.rs` lost 340 lines and delegates through a `tunnels()` accessor.

`PeerBlock` is what removed the last duplicated function. Carving from a pool's own block and
carving from a VPN service's block were the same eight lines twice, differing only in which
columns hold the block, what is already taken, where to place a new address and what to call the
row in an error. Those four are the trait; carving is a default method. It also carries the
invariant `ck_tunnel_pool_has_a_block` used to hold, which the schema can no longer state because
whether a row may have no block depends on another table.

## Increments

Each is L or smaller and lands as its own PR.

### Increment 1 — schema and db layer  ✅ DONE
- [x] `20260827160000_vpn.sql`: one migration for the whole feature — `tunnel_route`,
      `vpn_service`, `vpn_service_pool`, `vpn_subscription` and `vpn_device`
- [x] `lnvps_db` models (`VpnService`, `VpnSubscription`, `VpnDevice`,
      `TunnelPool::terminates_devices`, `VpnService::dns_servers`)
- [x] 17 `LNVpsDb` trait methods + MySQL impl + `MockDb` impl enforcing every constraint
- [x] Unit tests: 7 in `mock::vpn_tests`, 2 in `lnvps_db::model::tests`

**Correction to the original plan:** the device address block is on `vpn_service`, **not** on
`tunnel_pool`. Per-pool blocks would hand one device a different address in each region, which
is the exact thing this design exists to avoid. `tunnel_pool.vpn_service_id` is the link, and
non-NULL is what makes a pool device-terminating, so no separate boolean was needed.

**Correction to decision 3 in the original sketch:** there is no `enabled`/`suspended` column on
`vpn_subscription`. Billing state lives on `subscription` (`is_active`, `is_setup`, `expires`)
and is joined in `list_active_vpn_devices`, so suspension for non-payment is not a write at all
and reactivation on payment needs no code path to remember anything.

Migrations were applied against a real MariaDB and every constraint was probed:
`ck_vpn_service_has_a_block`, `uk_vpn_subscription_user`, `uk_vpn_device_slot`,
`uk_vpn_device_pubkey`, `uk_vpn_device_address4` all fire, and NULL addresses do not collide
(so a v4-only or v6-only service works).

### Increment 2 — device allocator  ✅ DONE
- [x] `lnvps_api/src/provisioner/vpn.rs`: `register_vpn_device` (idempotent on key, refuses a key
      held by another account), `next_free_slot` (lowest free, so removing and re-adding reuses),
      `carve_device_addresses` / `carve_one` (from the service block, skipping what the block
      reserves), `plan_vpn_pool`
- [x] `plan_pool` dispatches on `get_vpn_service_for_pool`; an unlinked pool is unchanged
- [x] `list_vpn_devices_in_service` added to the db layer: the allocator's taken-set must include
      lapsed and disabled devices, so it cannot reuse `list_active_vpn_devices`
- [x] 15 unit tests; `provisioner/vpn.rs` is at 100% function and 100% line coverage

Notes:

- `guest_addresses()` needed no short-circuit after all. A VPN pool never reaches the tunnel loop,
  so the N+1 it would have caused does not exist. The marketplace path is untouched.
- The taken-set deliberately includes unpaid and disabled devices. Reissuing a lapsed customer's
  address would deliver their traffic to somebody else the moment they paid again.
- **No retry on slot contention.** `next_free_slot` proposes and `uk_vpn_device_slot` enforces, so
  a race is refused rather than over-allocating, but the loser currently gets an error. Retrying
  belongs where the request is handled: pick it up in increment 4.

### Increment 3 — billing  ✅ DONE
- [x] Pricing on `vpn_service` (`company_id`, `amount`, `currency`, `interval_amount`,
      `interval_type`, `setup_amount`), mirroring the `app` catalog table. Folded into the
      unreleased `20260827160000` migration rather than added as a follow-up.
- [x] `LineItemType::Vpn = 6` plus the four dispatch sites the exhaustive matches forced:
      the handler factory, `ApiSubscriptionLineItemResource`, the discount engine's
      `OrderProduct`, and the legal/resource listing
- [x] `VpnLineItemHandler`: every billing event queues `ReconcileTunnelPeers` for each
      interface on the service
- [x] `create_vpn_plan`: unpaid at the service's price, idempotent while live, repoints a
      lapsed plan at a fresh subscription and keeps its devices
- [x] 8 unit tests; `subscription/vpn.rs` at 100% function and line coverage

Notes:

- **Suspension needed no wiring at all.** The planner joins billing state, so paying, lapsing
  and cancelling change nothing that has to be written. The handler exists only for promptness:
  it pushes the interfaces so a change lands now instead of at the next poll, and a queue
  outage is logged rather than failing a payment the customer has already made.
- **Grace period does not delete devices.** The plan row is reused on return, so keys and
  addresses surviving is what makes coming back a payment rather than a re-setup.
- **Device-limit tiers are descoped.** `device_limit` is per plan and can be raised, but there
  is no per-tier price to charge for it, so there is nothing to prorate yet. One flat price per
  service. Add a tier table when there is a reason to sell one.
- `IntervalType` gained a `Default` of `Month`, matching every billing column's `DEFAULT 1`.

### Increment 4 — user API  ✅ DONE
- [x] Slot contention retried in `register_vpn_device` rather than in the handler: every
      caller wants the same behaviour, and the loop returns the last attempt's error directly
      so "ran out of attempts but recorded nothing" is not a state that has to exist
- [x] `/api/v1/vpn/services`, `/api/v1/vpn` (GET/POST), `/api/v1/vpn/devices` (GET/POST),
      `/api/v1/vpn/devices/{id}` (DELETE), `/api/v1/vpn/devices/{id}/enabled`,
      `/api/v1/vpn/devices/{id}/configs`
- [x] Config rendering per region, structured fields plus a `wg-quick` file
- [x] `API_CHANGELOG.md` and `API_DOCUMENTATION.md`
- [x] 6 unit tests in `api/vpn`, 2 more in `provisioner/vpn` for the race and the give-up

Notes:

- **No server-side QR.** It needs a barcode encoder as a dependency to produce something the
  client renders better from the `config` string. Dropped, and said so in the docs.
- **Handler coverage comes from e2e, not unit tests.** That is the existing pattern here:
  `api/subscriptions.rs` and `api/ip_space.rs` are at 0% under `cargo llvm-cov -p lnvps_api`.
  The unit tests cover config rendering and the ownership/billing predicates; **increment 9
  must cover the endpoints themselves**, or they ship untested.
- The slot race is covered deterministically rather than hopefully: holding the plans lock
  stops the allocator inside its address carve, after it has proposed a slot, so a device
  inserted meanwhile takes the slot it was about to use.
- Two services with overlapping device blocks now fail loudly (the carve only sees its own
  service, the unique index is global). That is a misconfiguration worth an error rather than
  two customers on one address.
- `provisioner/vpn.rs` 100% functions / 99% lines; the one uncovered region is a read-back
  failing immediately after a successful insert.

### Increment 5 — agent router backend
- [ ] `RouterKind::Lvd` + `router/agent.rs` implementing the read half of `TunnelRouter`
- [ ] Split `reconcile_tunnel_peers` into drift detection and push; gate push on backend
- [ ] Digest-based drift comparison; summarised peer view
- [ ] Unit tests

### Increment 6 — route-server-facing API
- [x] `RouterKind::Lvd = 3`: the one kind LNVPS never dials.
- [x] `GET /api/v1/routeserver/dataplane`, authenticated by a static `<router_id>.<secret>`
      bearer compared against `router.token`. No JWT: unlike a marketplace node there is
      nothing to mint, since a route server is provisioned by hand.
- [x] `tunnel_pool.generation`, bumped in `sync_pool`/`reconcile_peers` where a pushed pool
      would have been pushed, so there is one list of things that change an interface.
- [x] **Long-poll instead of poke-on-change.** An `lvd` instance runs wherever its region is,
      which means behind a NAT nothing here can traverse; dialling out to it would work
      everywhere it was tested and fail on the one machine nobody thought about, and that
      failure surfaces as a revoked device that keeps working. `?generation=N&wait=25` holds
      the request until the generation moves, so a change lands in one round trip over a
      connection the route server opened. A held request wakes on Redis pub/sub, over the
      existing `WorkFeedback`, on one channel per interface it terminates. The message is
      only a hint: the database is re-read regardless, because pub/sub is fire-and-forget
      and a message published while an instance was reconnecting is simply gone. A 5s
      re-read bounds that loss, and is the whole mechanism when no Redis is configured.
- [x] 5 unit tests, including one asserting the serialised document carries no identity.
- [ ] `POST /api/v1/routeserver/counters`

### Increment 7 — extract the netlink layer  ✅ DONE
- [x] `lnvps_netlink`: `NetOps`, `WgSettings`/`WgObserved`, the netlink `Kernel`,
      `UnavailableKernel`, `netns` and the `/proc/sys` helpers
- [x] `lnvps_node` repointed, re-exporting from `net::` and `lnvps_node::netns` so no call
      site moved and the e2e harness is untouched. No behaviour change.

Notes:

- `Kernel` is still namespace-bound, which is right for a node and wrong for a route server.
  A host-namespace constructor is additive and belongs with the daemon that needs it.
- The desired-document types, `apply`, `observe` and `DataPlaneState` stayed behind: bridges,
  guests and libvirt are a marketplace node's vocabulary, not a data plane's.

### Increment 8 — `lnvps_vpn` daemon  ✅ DONE (bar packaging)
- [x] New crate `lnvps_vpn`, binary `lvd`. Root workspace member, released on the API's tag.
- [x] `client.rs`: the long-polling fetch. Its own copy of the document types rather than a
      shared crate, because a route server must not compile the database and the payment
      stack to parse four structs, and because a daemon that tolerates fields it does not
      know can be upgraded in either order.
- [x] `apply.rs`: convergent, and **peer-at-a-time**. The kernel's only way to state a
      device's configuration replaces its peer set with it, so a whole-interface apply would
      reset every established session — one customer registering a phone becoming a stampede
      of renegotiation across thousands of peers. The interface is re-keyed only when the key
      or port is actually wrong.
- [x] `scrub.rs`: the 600s endpoint scrub, and the reason it exists spelled out where the
      code is.
- [x] `Kernel::host()` in `lnvps_netlink`, plus `set_wireguard_peer` /
      `configure_wireguard_interface`, and `WgObserved` carrying port, key, per-peer allowed
      IPs, endpoint and byte counters.
- [x] `config.example.yaml`, with a test asserting this build accepts it.
- [x] **Packaging**: `cargo deb` metadata, a systemd unit, maintainer scripts, and
      `.github/workflows/lvd-deb.yml` building `lnvps-lvd_<version>_amd64.deb` on its own
      `lvd-v*` tag. Built, installed, started, upgraded and purged on a real machine.
      `lnvps_vpn` carries an explicit `version` rather than inheriting the workspace's, so a
      route server's upgrade cadence is its own: publishing a package on every API release
      would leave an operator unable to tell from the version whether an upgrade mattered.
- [x] 26 unit tests. `client.rs`, `config.rs` and `scrub.rs` at 100% function coverage.

**No self-upgrade**, unlike `lnvps_fw`. That exists because firewall daemons run on many hosts,
some of which LNVPS does not administer. Route servers are few and ours, and a daemon that can
replace its own binary on a machine terminating customer traffic is a bigger thing to own than
`apt upgrade` on a box we already have access to.

**No inbound control listener.** The original sketch had one for immediate re-pull. It is not
needed and it is not wanted: long-poll already delivers a change in one round trip, and an
inbound listener would need a port, a certificate for LNVPS to pin, and reachability that a
route server behind somebody else's NAT does not have. Outbound-only means the daemon has no
listening socket at all.

Notes:

- **An interface the document does not mention is left alone.** A route server is not
  necessarily only a route server, and tearing down what LNVPS has not heard of would let a
  bug here take out the operator's own networking.
- **`main.rs` is uncovered** by unit tests, as `lnvps_node`'s is; the netns harness runs it as
  a real process instead.
- Installing the package surfaced a fault nothing else would have: `env_logger` defaults to
  errors only, so the unit ran green and silent while failing every fetch. Every way this
  daemon fails in the field is logged at `warn` or `info`. The unit sets `RUST_LOG=info`.
- The unit runs as root but with `CapabilityBoundingSet=CAP_NET_ADMIN` and `ProtectSystem=strict`.
  Verified under `systemd-run` with the same properties that creating a WireGuard interface,
  addressing it and routing through it all still work.
- No `StateDirectory`: the daemon holds nothing across restarts, so a rebuilt route server needs
  only its config file.
- Still open from increment 6: `POST /api/v1/routeserver/counters`. The counters are read
  from the kernel now (`WgPeerState::rx_bytes`/`tx_bytes`); nothing reports them yet.

### Increment 9 — end-to-end  ✅ DONE
- [x] `lnvps_e2e/tests/vpn_lvd.rs`: **LNVPS and `lvd` together**, on real namespaces, carrying
      real packets. Nothing is hand-written: the service and its two interfaces are created
      through the admin API, the plan is paid over Lightning, the device is registered through
      the user API with a keypair generated in the test, and two `lvd` processes are started
      with nothing but an API address and a token. They discover the rest themselves.
- [x] `scripts/vpn-e2e.sh`, plus `--setup-only` on `run-e2e.sh`. This harness needs a running
      stack *and* root, which no existing script gave it at once.
- [x] `lnvps_e2e/src/vpn.rs`: the HTTP surface, run against a live stack (11 tests).

**The first attempt was wrong and was thrown away.** `vpn_netns.rs` hand-wrote the document,
called `apply()` as a function and pinged. That proves "given a correct document, WireGuard
works", and WireGuard working is not ours to test. Worse, the document being correct was
*assumed*: the multi-region property it claimed to prove was written into the fixture by hand.
The seam that actually carries risk is the one it skipped — the document is defined twice, by
the API that publishes it and the daemon that parses it, with JSON in between and nothing
forcing them to agree.

What the real harness asserts:

- every region's config carries the **same** device address, checked against what the
  allocator did rather than against a fixture, and the configs differ only in their endpoint;
- both `lvd` instances install the customer's key unprompted, having been told only where
  LNVPS is;
- the device reaches **both** regions on the one address it holds, by switching peers the way
  a client switches region;
- revoking through the admin API removes the key from **every** region within a round trip,
  and the device then cannot reach the route server;
- the rendered `wg-quick` file carries the placeholder, because LNVPS never had the key.

It also subsumes the connected-route regression: with that bug, `apply` fails and no peer is
ever installed, so the harness fails at the first assertion.

Notes:

- The two `lvd` processes are real processes with real config files, started under
  `ip netns exec`. Nothing dials them, which is what makes this arrangement possible at all.
- Lost with `vpn_netns.rs`: the only test of `sync_routes` add-and-remove against a real
  kernel. A VPN interface asks for no routes, so that path is now covered by unit tests
  against the fake kernel and by the marketplace harness, not on real netlink.
- `scripts/run-e2e.sh` writes its generated configs to fixed `/tmp` paths, so two runs on one
  machine overwrite each other's. Not fixed here; it cost an hour to diagnose.

### Increment 10 — admin API  ✅ DONE
- [x] `AdminResource::VpnService = 32` and `VpnSubscription = 33`, granted to `super_admin` by
      `20260828120000_vpn_rbac_permissions.sql`. Two resources, not one: revoking a lost phone is
      support work and must not require the ability to reprice a product everyone else has bought.
- [x] `vpn_services.rs` — CRUD plus link/unlink an interface. Created off sale by default, since a
      service with no interfaces has no region to connect to. Delete refused while it has
      subscribers; retiring is `enabled: false`.
- [x] `vpn_subscriptions.rs` — list/get plans with their devices, and revoke a device. No create:
      a plan exists because a line item was paid for, and a device is a keypair whose private half
      never leaves the customer's machine.
- [x] `admin_list_vpn_subscriptions_filtered` in the db layer.
- [ ] Aggregate counter reporting

## Notes

- Migration timestamps must be unique 14-digit `YYYYMMDDHHMMSS`; latest on master is
  `20260827131900`. Check `ls lnvps_db/migrations/` before adding.
- Address sizing: 5 devices per customer out of a `/16` is ~13k customers. Use a `/12` for the
  global device block; widening later is a pool edit but existing allocations keep their address.
- Operational: block outbound 25 and have spare exit addresses before launch, so one null-route
  upstream is not a full regional outage.
