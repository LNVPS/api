# Route Server Management (#138)

**Status:** in-progress
**Started:** 2026-06-21
**Last updated:** 2026-06-21 (increments 1-5 complete)

## Goal

Extend the router subsystem to support: SSH-based Linux (BIRD/Pathvector) routers,
BGP session detection/toggle, originated-route + default-route detection, peer
discovery, and tunnel (GRE/VXLAN/WireGuard) detection/management with per-tunnel
traffic counters. Mikrotik must implement the same new capabilities. Traffic
counters come from tunnel interfaces (not BGP sessions).

## Findings

- Router trait + factory: `lnvps_api/src/router/mod.rs` (ARP-only today).
- Backends: `lnvps_api/src/router/{mikrotik.rs,ovh.rs}`. Mikrotik uses `JsonApi`.
- DB model `Router` + `RouterKind` enum: `lnvps_db/src/model.rs` (~L670). `RouterKind`
  is `#[repr(u16)] sqlx::Type`. DB methods in `lnvps_db/src/mysql.rs` (`get_router`,
  `list_routers`, `admin_*_router`).
- Admin CRUD: `lnvps_api_admin/src/admin/routers.rs` + models in
  `lnvps_api_admin/src/admin/model.rs` (`AdminRouterKind`, `AdminRouterDetail`,
  `Create/UpdateRouterRequest`).
- Mock router: `lnvps_api/src/mocks.rs` (`MockRouter`, uses LazyLock shared state).
- Reusable SSH: `lnvps_api/src/ssh_client.rs` (`SshClient`, ssh2, key-file +
  in-memory PEM). `ssh2` is gated behind `proxmox`/`libvirt` features currently.
- Feature flags in `lnvps_api/Cargo.toml`: `mikrotik` (default on), `proxmox` (pulls `ssh2`).
- Decision: abstraction-first. Capability traits `BgpRouter` + `TunnelRouter`
  separate from `Router`. Ship SSH/CLI backend first; netlink agent later behind
  same traits (`RouterKind::LinuxAgent` future).

## Tasks

### Increment 1 — Linux SSH backend skeleton + RouterKind  ✅ DONE
- [x] Add `RouterKind::LinuxSsh = 2` (db model) + `AdminRouterKind::LinuxSsh` mappings
- [x] New `lnvps_api/src/router/linux_ssh.rs` implementing `Router` (ARP via `ip neigh`)
- [x] Wire into `get_router()` factory + feature flag (`linux-ssh` pulling `ssh2`)
- [x] Unit tests for url parsing / neigh parsing
- Notes: url=`ssh://user@host:port/interface`, token=PEM key. ssh_client now gated
  on `any(proxmox, linux-ssh)`. Connect-per-operation (Send/Sync-safe). ARP via
  `ip -j neigh show` / `ip neigh replace ... nud permanent` / `ip neigh del`.

### Increment 2 — TunnelRouter trait + Linux impl  ✅ DONE
- [x] Define `TunnelRouter` trait + `Tunnel`/`TunnelKind`/`TunnelConfig`/`TunnelTraffic` +
      `Gre/Vxlan/WireguardConfig` + `WireguardPeer` (in router/mod.rs)
- [x] Capability accessor: `Router::tunnel() -> Option<&dyn TunnelRouter>` (default None)
- [x] Linux detect via `ip -s -d -j link show` (+ `wg show all dump` for WG) + manage
      (`ip link add/del`, `wg set` with 0600 temp key file) + traffic from stats64
- [x] MockRouter `TunnelRouter` impl + `tunnel()` override
- [x] Unit tests (gre/vxlan/wg parsing, gre-key, shq escaping, wg-set script, traffic
      filter, mock lifecycle)
- Notes: `update_tunnel` recreates iface (del+add) for deterministic config apply.
  GRE key accepts int or dotted-quad. WG private key never returned on list.

### Increment 3 — Mikrotik TunnelRouter impl  ✅ DONE
- [x] `/rest/interface/{gre,vxlan,wireguard}` (+ `/wireguard/peers`) list/add/remove/update
- [x] Traffic via `/rest/interface` rx-byte/tx-byte filtered by type {gre,vxlan,wg}
- [x] `Router::tunnel()` override; tunnel id encoded as `"<endpoint>:<ros_id>"`
- [x] Unit tests for helpers (mt_enabled, endpoint map, id split, endpoint split, wg peer)
- Notes: RouterOS booleans/numbers are strings. GRE has no key field (ignored).
  VXLAN remote handled via vteps (not yet supported — remote_addr=None). WG private
  key never returned on list. DELETE returns empty body → treated as success.

### Increment 4 — BgpRouter trait + Linux birdc + Mikrotik BGP  ✅ DONE
- [x] `BgpRouter` trait + `BgpSession`/`BgpPeer`/`BgpRoute`/`BgpPeerDirection` +
      `Router::bgp()` accessor (router/mod.rs)
- [x] Linux birdc: `show protocols all` parse (sessions), `show route` parse
      (originated/default), `birdc enable/disable` toggle; role→direction mapping
- [x] Mikrotik `/rest/routing/bgp/{connection,session,advertisements}` + `/rest/ip/route`;
      toggle PATCHes connection.disabled
- [x] MockRouter `BgpRouter` impl (+ `add_session` seed helper) + `bgp()` override
- [x] Unit tests: bird protocols/routes parsers, role mapping, mock bgp lifecycle
- Notes: BGP has NO byte counters (prefixes only). Mikrotik direction=Unknown
      (no customer/provider signal). birdc text parsing is inherently fragile —
      parsers are table-tested against captured sample output.
- **Full-table (DFZ) safety** — routers carry a full internet table (~1M+ routes):
  - `originated_routes(candidates)` is SCOPED to candidate prefixes (VM ranges),
    never enumerates the table. Empty slice => only locally-originated (small).
  - BIRD uses `show route for <addr>` (LPM lookup) + `show route where source =
    RTS_STATIC` (bounded output). Never a bare `show route` dump.
  - Mikrotik NEVER does unfiltered `GET /rest/ip/route`. Uses server-side
    `?dst-address=<prefix>&.proplist=...` filters per candidate / for default route.
  - Sampler (incr 5) samples ONLY tunnel traffic (bounded), never routes.

### Increment 5 — Persistence + background sampler  ✅ DONE
- [x] Migration `20260621220706_router_tunnels_bgp.sql`: `router_tunnel`,
      `router_tunnel_traffic`, `router_bgp_session` (FKs + unique(router_id,name))
- [x] DB models `RouterTunnel`/`RouterTunnelKind`/`RouterTunnelTraffic`/
      `RouterBgpSession`/`RouterBgpDirection` (model.rs)
- [x] DB trait methods (list/upsert/delete tunnels, insert/list traffic, list/upsert/delete
      bgp sessions) + MySQL impl (upsert via ON DUPLICATE KEY) + MockDb impl
- [x] `Tunnel::to_db`/`BgpSession::to_db` conversions (router/mod.rs)
- [x] `WorkJob::SampleRouterTraffic` + `Worker::sample_router_traffic`/`sample_one_router`;
      registered 60s interval in bin/api.rs
- [x] Tests: MockDb CRUD (tunnel/traffic/bgp), worker sampler integration test
- Notes: sampler only writes tunnel traffic to time-series; BGP refreshed as cached
      state. All queries bounded/full-table safe. 100% function coverage maintained.

### Increment 6 — Admin API + docs  ✅ DONE
- [x] Admin endpoints (routers.rs): GET tunnels, GET tunnel traffic (from/to, def 24h),
      GET bgp/sessions, POST bgp/sessions/toggle (dispatches WorkJob)
- [x] Admin models (model.rs): `AdminRouterTunnel`/`AdminRouterTunnelTraffic`/
      `AdminRouterBgpSession` From impls + `ToggleBgpSessionRequest`
- [x] `WorkJob::ToggleBgpSession` + `Worker::toggle_bgp_session` handler (refreshes cache)
- [x] API_CHANGELOG.md + ADMIN_API_ENDPOINTS.md updated (incl. linux_ssh RouterKind)
- [x] Tests: admin model conversions + request deserialize; worker toggle test
- Notes: admin crate has NO dep on lnvps_api, so reads cached DB state and dispatches
      live actions via WorkCommander. Originated/default-route admin exposure deferred
      (needs caching or RPC; capability exists in BgpRouter trait).

## Notes

- Open questions (asked on issue): Pathvector toggle persistence, WG key storage,
  tunnel→customer/subscription linkage, router count × sampling cadence.
- Per-session BGP byte counters do NOT exist — traffic is per-tunnel only.
