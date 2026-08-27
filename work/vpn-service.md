# LNVPS VPN (Mullvad-style multi-region WireGuard)

**Status:** in-progress
**Started:** 2026-08-27
**Last updated:** 2026-08-27 (increment 3 complete: billing)

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

## Increments

Each is L or smaller and lands as its own PR.

### Increment 1 — schema and db layer  ✅ DONE
- [x] `20260827160000_vpn_service.sql`: `vpn_service` (device blocks, DNS, default limit)
      plus `tunnel_pool.vpn_service_id`
- [x] `20260827160100_vpn_subscription.sql`: `vpn_subscription` and `vpn_device`, with
      `UNIQUE (vpn_subscription_id, slot)` as the race-free device cap
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

### Increment 4 — user API  (next)
- [ ] Retry slot contention here (see increment 2 note): `next_free_slot` proposes and the
      unique key enforces, so a concurrent registration currently errors rather than taking
      the next slot
- [ ] `/api/v1/vpn`: subscribe, status, list/add/delete device, list regions
- [ ] Config rendering per region (and QR), from `tunnel_pool` fields
- [ ] `API_CHANGELOG.md` + `API_DOCUMENTATION.md` per `docs/agents/api-guidelines.md`
- [ ] Unit tests

### Increment 5 — agent router backend
- [ ] `RouterKind::LnvpsAgent` + `router/agent.rs` implementing the read half of `TunnelRouter`
- [ ] Split `reconcile_tunnel_peers` into drift detection and push; gate push on backend
- [ ] Digest-based drift comparison; summarised peer view
- [ ] Unit tests

### Increment 6 — route-server-facing API
- [ ] `/api/v1/routeserver/dataplane` (versioned/ETagged) and `/counters`, per-router token auth
- [ ] Generation counter on `tunnel_pool`; poke-on-change
- [ ] Unit tests

### Increment 7 — extract the netlink layer
- [ ] Lift `lnvps_node/src/net.rs` (`NetOps` trait and impl) into a shared crate
- [ ] Repoint `lnvps_node` at it, no behaviour change

### Increment 8 — `lnvps_vpn` daemon
- [ ] New crate: pull loop, batch peer apply (`wg syncconf` equivalent over netlink),
      600s endpoint scrub, inbound control listener for immediate re-pull
- [ ] Config, packaging, `config.example.yaml`
- [ ] Unit tests

### Increment 9 — end-to-end
- [ ] Extend the netns harness: one device reaching two pools with the same inner address
- [ ] Script entry alongside `scripts/tunnel-e2e.sh`

### Increment 10 — admin API
- [ ] `AdminResource` variant, RBAC migration, admin CRUD for VPN subscriptions and devices
- [ ] Aggregate counter reporting

## Notes

- Migration timestamps must be unique 14-digit `YYYYMMDDHHMMSS`; latest on master is
  `20260827131900`. Check `ls lnvps_db/migrations/` before adding.
- Address sizing: 5 devices per customer out of a `/16` is ~13k customers. Use a `/12` for the
  global device block; widening later is a pool edit but existing allocations keep their address.
- Operational: block outbound 25 and have spare exit addresses before launch, so one null-route
  upstream is not a full regional outage.
