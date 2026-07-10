# DNS Forward/Reverse DB-Driven Refactor + OVH Reverse DNS

**Status:** complete
**Started:** 2026-07-10
**Last updated:** 2026-07-10

## Summary (complete)

Done in a single PR. DNS providers are now DB rows (`dns_server` table, encrypted token),
referenced per IP range via `forward_dns_server_id` / `reverse_dns_server_id` +
`forward_zone_id` (reverse zone already existed). The `DnsServer` trait was generalized
(zone/ip folded onto `BasicRecord`), a `dns::get_dns_server(db,id)` factory dispatches on
kind, and a new `ovh` provider implements reverse DNS via `POST/DELETE /ip/{ip}/reverse`
(reuses shared `crate::ovh::OvhTokenGen`, extracted from `router/ovh.rs`). `vm_network.rs`
resolves DNS servers per range from the DB; the static `Settings.dns` is now legacy,
consumed once by `DnsDataMigration` to bootstrap the DB rows. Admin CRUD at
`/api/admin/v1/dns_servers` (+ new `dns_server` permission, `AdminResource::DnsServer = 22`).
All unit tests pass; clippy clean on new files; API_CHANGELOG + ADMIN_API_ENDPOINTS updated.
Closes #78 (and finishes #16). Not done: authoritative DNS server crate (#110, out of scope).

## Goal

Refactor the DNS subsystem so forward and reverse DNS are configured entirely in the
database (mirroring the existing `router` pattern) instead of the global `settings.yaml`,
and add an OVH reverse-DNS provider. Closes GitHub issue #78 ("OVH Reverse").

Done looks like:
- A `dns_server` DB table (`id, name, enabled, kind, url, token`) with an encrypted token,
  a Rust model, DB trait CRUD methods, and admin API — mirroring `router`.
- IP ranges reference a **forward** and a **reverse** DNS server (per-range, per user's choice)
  plus provider-specific zone fields; the static `Settings.dns` config is removed.
- A generalized `DnsServer` trait + factory `dns::get_dns_server(db, id)` dispatching on kind.
- A new `dns/ovh.rs` provider implementing reverse DNS via `POST /ip/{ip}/reverse` and
  `DELETE /ip/{ip}/reverse/{ip}` (forward DNS unsupported by OVH — reverse only).
- `vm_network.rs` resolves DNS servers per IP-range from the DB.
- Data migration moving existing config (`Settings.dns` + `IpRange.reverse_zone_id`) into the
  new tables, and updated tests + `MockDnsServer` + `API_CHANGELOG.md`.

## Findings

### Current architecture (config split, needs unifying)
- Provider + creds: `settings.yaml` → `Settings.dns` = `DnsServerConfig { forward_zone_id, api: DnsServerApi::Cloudflare { token } }` (single global). `lnvps_api/src/settings.rs:138`, factory `get_dns()` at `settings.rs:256`.
- Forward zone: global `DnsServerConfig.forward_zone_id`.
- Reverse zone: DB `IpRange.reverse_zone_id: Option<String>` (`lnvps_db/src/model.rs:791`). Column added in `lnvps_db/migrations/20250325113115_extend_ip_range.sql`.
- Record refs: DB `VmIpAssignment.dns_forward/dns_forward_ref/dns_reverse/dns_reverse_ref` (`model.rs:1061-1068`).

### Key files
- `lnvps_api/src/dns/mod.rs` — `DnsServer` trait (`add_record`/`update_record`/`delete_record` all take `zone_id: &str`), `BasicRecord`, `RecordType`, `is_valid_fqdn`.
- `lnvps_api/src/dns/cloudflare.rs` — only provider; zone+record-id based.
- `lnvps_api/src/provisioner/vm_network.rs:119-200` — `remove_ip_dns` / `update_forward_ip_dns` / `update_reverse_ip_dns`. Currently uses `self.dns` (single) + `self.forward_zone_id` + `range.reverse_zone_id`.
- `lnvps_api/src/data_migration/dns.rs` — existing forward/reverse backfill using global settings; model the new data migration on this.
- `lnvps_api/src/mocks.rs` — `MockDnsServer`.

### Blueprint to mirror: the `router` subsystem
- DB table `router (id, name, enabled bit(1), kind smallint, url varchar(255), token varchar(128))` — migration `20250325113115_extend_ip_range.sql`.
- Model `Router { id, name, enabled, kind: RouterKind, url, token: EncryptedString }` (`model.rs:686`).
- `RouterKind` enum: Mikrotik=0, OvhAdditionalIp=1, LinuxSsh=2, MockRouter=u16::MAX (`model.rs:697`).
- Factory `router::get_router(db, router_id) -> OpResult<Arc<dyn Router>>` dispatches on kind (`router/mod.rs:370`).
- DB trait CRUD: `get_router`/`list_routers`/... (`lnvps_db/src/lib.rs:411`).
- Admin API: `lnvps_api_admin/src/admin/routers.rs` (CRUD at `/api/admin/v1/routers`).
- **OVH auth already implemented**: `lnvps_api/src/router/ovh.rs` has `OvhTokenGen` (app_key:app_secret:consumer_key token, SHA1 signature, `X-Ovh-*` headers) + time-delta bootstrap via `v1/auth/time`. Extract this into a shared module so both router and DNS OVH clients reuse it.

### OVH reverse DNS API (issue #78)
- `POST /ip/{ip}/reverse` body `{ ipReverse: "<the IP>", reverse: "host.example.com." }` — sets PTR.
- `GET /ip/{ip}/reverse/{ipReverse}` — read; `DELETE /ip/{ip}/reverse/{ipReverse}` — remove.
- **No zones, no record IDs.** The "ref" is just the IP. This is why the zone-based `DnsServer` trait must be generalized (make zone optional/opaque; treat the returned ref opaquely). OVH provider supports **reverse only** — return an error/no-op for forward records.

### Migrations note
- New migration timestamp must be unique 14-digit; generate with `date +%Y%m%d%H%M%S`. Latest existing is `20260624140000`. Use `NOT NULL DEFAULT`/nullable columns so existing rows survive.
- `EncryptedString` type is used for `router.token`; reuse for `dns_server.token`.

### Related issues
- **#16 "Cloudflare zone ids" (CLOSED, completed 2025-03-25)** — predecessor. Commit `c570222 "feat: move zone-id configuration"` moved only the **reverse** zone id onto `ip_range.reverse_zone_id`; the **forward** zone id + provider token stayed global in `settings.yaml`. This refactor finishes that job (moves forward zone onto `ip_range`, removes `Settings.dns`). Reference #16 in the PR.
- **#110 "DNS server" (OPEN)** — distinct, larger: build an authoritative `lnvps_dns` crate on `trust-dns-server` to host PTR/A/AAAA ourselves. Out of scope here, but it becomes another `DnsServerKind` (self-hosted) that plugs into this DB-driven abstraction. This refactor is an enabler for #110.

## Design decisions (confirmed with user)
- **Full DB-driven refactor** (not minimal OVH-only).
- Forward DNS configured **per IP range** (store both `forward_dns_server_id` and `reverse_dns_server_id` on `ip_range`, alongside zone fields).

## Tasks

### Increment 1 — DB schema + model + trait CRUD (size: M)
- [ ] Extract OVH token/signature helper from `router/ovh.rs` into a shared module (e.g. `lnvps_api/src/ovh/mod.rs` or `json_api`), reused by router + dns. (Can be deferred to Increment 3 if cleaner.)
- [ ] Migration: `create table dns_server (id, name, enabled bit(1), kind smallint, url varchar(255), token varchar(128))`. Add columns to `ip_range`: `forward_dns_server_id`, `reverse_dns_server_id` (both `integer unsigned` nullable, FKs to `dns_server`), and `forward_zone_id varchar(255)` (reverse already exists as `reverse_zone_id`). Keep `reverse_zone_id`.
- [ ] Model: `DnsServer` DB struct + `DnsServerKind` enum (Cloudflare=0, Ovh=1, MockDns=u16::MAX). Extend `IpRange` with the new fields.
- [ ] DB trait + mysql impl: `get_dns_server`/`list_dns_servers`/`insert_dns_server`/`update_dns_server`/`delete_dns_server`. Update `ip_range` queries (get/list/insert/update) for new columns.
- [ ] Note DB model type name clash: DB `DnsServer` struct vs api `DnsServer` trait — rename one (e.g. DB `DnsServerConfig`/`DnsServerRow`, or trait stays `DnsServer` and DB row is `DnsServer` in `lnvps_db` namespace — pick and document).

### Increment 2 — Generalize DnsServer trait + factory (size: M)
- [ ] Change trait signatures so zone is optional context (e.g. carry an optional zone on `BasicRecord` or pass `&IpRange`), and record ref is opaque. Keep Cloudflare working.
- [ ] Add `dns::get_dns_server(db, dns_server_id) -> OpResult<Arc<dyn DnsServer>>` factory dispatching on `DnsServerKind` (Cloudflare/Ovh/Mock), decrypting token.
- [ ] Update `MockDnsServer` and any callers to the new trait shape.

### Increment 3 — OVH reverse DNS provider (size: S/M)
- [ ] `lnvps_api/src/dns/ovh.rs`: implement `DnsServer` for reverse via `POST/GET/DELETE /ip/{ip}/reverse`. Reuse shared OVH token gen. Forward = unsupported error. Feature-flag `ovh-dns` (or reuse existing `ovh`/router feature).
- [ ] Wire into factory + Cargo features.

### Increment 4 — vm_network + provisioner wiring (size: M)
- [ ] `vm_network.rs`: resolve forward+reverse DNS servers from the IP range via factory instead of `self.dns`/`self.forward_zone_id`. Update `remove_ip_dns`/`update_forward_ip_dns`/`update_reverse_ip_dns`.
- [ ] Remove `forward_zone_id`/`dns` constructor params where they came from settings; source from DB per range.
- [ ] Remove `Settings.dns` / `DnsServerConfig` / `DnsServerApi` from `settings.rs` and `get_dns()`. Update all constructors/tests.

### Increment 5 — Admin API for dns_server CRUD (size: M)
- [ ] `lnvps_api_admin/src/admin/dns_servers.rs` mirroring `routers.rs` (list/create/get/patch/delete) with `AdminResource` permission. Add route wiring + admin model types. Expose ip_range forward/reverse dns server + zone fields in the ip_range admin API (`lnvps_api_admin/src/admin/ip_ranges.rs`).
- [ ] Update `ADMIN_API_ENDPOINTS.md`.

### Increment 6 — Data migration + docs + tests (size: M)
- [ ] Data migration: create a `dns_server` row from the old `Settings.dns` Cloudflare token, point existing IP ranges' `forward_dns_server_id` at it + set `forward_zone_id` from old global, and `reverse_dns_server_id` at it where `reverse_zone_id` is set. Model on `data_migration/dns.rs` (which then becomes/needs updating).
- [ ] Update/extend E2E + unit tests, mocks, and demo-data generator (`generate_demo_data.rs`).
- [ ] `API_CHANGELOG.md` under `## [Unreleased]`. Label issue #78 (`enhancement`, `api`, `database`) and open PR `Fixes #78`.

## Notes
- Coverage rule: 100% function coverage required for added/modified functions — add tests per increment.
- One PR per increment (each L-or-smaller). Ask user before committing/pushing.
- Watch the `DnsServer` name collision between the api trait and a DB model struct.
