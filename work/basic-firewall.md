# Basic Firewall Support (#36)

**Status:** complete
**Started:** 2026-06-24
**Last updated:** 2026-06-24 (All increments complete)

## Goal

Implement basic user-configurable per-VM firewall rules (issue #36): a data
model for rules, user API endpoints to CRUD them, and a Proxmox PVE firewall
backend that applies the user rules on top of the always-enforced ipfilter
(anti-spoof) rules. Default policy stays allow-all (no regression).

nftables backend (#33) and the `use_nftables` host flag (#34) are **out of
scope** for this initial work — tracked separately.

## Findings

### Existing firewall infrastructure
- `Host::patch_firewall(cfg: &FullVmInfo)` trait method: `lnvps_api/src/host/mod.rs:83`
  - Proxmox impl: `lnvps_api/src/host/proxmox.rs:1514` — enables PVE fw on NIC,
    manages `ipfilter-net0` IPset (anti-spoof), adds an ACCEPT rule for that set.
  - libvirt impl: stub returning Ok (`lnvps_api/src/host/libvirt.rs:230`)
  - dummy impl: stub (`lnvps_api/src/host/dummy_host.rs:271`)
- Proxmox API client already has rule helpers: `list_vm_firewall_rules`,
  `add_vm_firewall_rule` (proxmox.rs:835+). May need a delete helper.
- `VmFirewallRule` (proxmox API type), `VmFirewallAction`, `VmFirewallRuleType`
  already exist for the proxmox client — distinct from our new DB model type.
- patch_firewall is invoked from worker: `lnvps_api/src/worker.rs:1255`.
- NIC always has `firewall=1` (proxmox.rs:928).

### DB patterns
- Model structs in `lnvps_db/src/model.rs`; enums use
  `#[derive(sqlx::Type)] #[repr(u16)]`. Trait in `lnvps_db/src/lib.rs`,
  mysql impl in `lnvps_db/src/mysql.rs`. Mock in db trait area too.
- Migrations: `lnvps_db/migrations/` timestamped `.sql`.
- Template limit columns added via ALTER (see template_limits migration);
  `VmTemplate` at model.rs:837.

### API patterns
- Routes registered in `lnvps_api/src/api/routes.rs` (axum `.route(...)`).
- API DTO types in `lnvps_api/src/api/model.rs`.
- VM ownership check pattern used across `v1_*` handlers.
- `API_CHANGELOG.md` must be updated for user-facing API changes.

## Tasks

### Increment 1 — Data model + DB layer (M) ✅ DONE
- [x] Migration: create `vm_firewall_rule` table
      (`20260624123544_vm_firewall_rule.sql`)
- [x] Migration: add `firewall_rule_limit` to `vm_template` + `vm_custom_template`
- [x] Model: `VmFirewallRule` struct + `VmFirewallDirection`,
      `VmFirewallProtocol`, `VmFirewallRuleAction` enums (model.rs)
- [x] Add `firewall_rule_limit` field to `VmTemplate` / `VmCustomTemplate`
- [x] DB trait methods (LNVpsDbBase): insert / get / list_by_vm / update / delete
- [x] mysql impl of the above
- [x] Update mock DB impl (`firewall_rules` map + 5 methods)
- [x] cargo build --workspace + lnvps_api_common tests green

### Increment 2 — User API (M) ✅ DONE
- [x] API DTOs: `ApiVmFirewallRule` + `ApiFirewall{Direction,Protocol,Action}`,
      `CreateVmFirewallRule`, `PatchVmFirewallRule` (api/model.rs)
- [x] `GET /api/v1/vm/{id}/firewall`
- [x] `POST /api/v1/vm/{id}/firewall`
- [x] `PATCH /api/v1/vm/{id}/firewall/{rule_id}`
- [x] `DELETE /api/v1/vm/{id}/firewall/{rule_id}`
- [x] Validation: ownership (`get_user_vm`), max-rule limit
      (`vm_firewall_rule_limit`, default 20), CIDR + port-range parsing
- [x] Trigger firewall re-apply: new `WorkJob::ApplyVmFirewall { vm_id }` +
      worker `apply_vm_firewall` handler; queued on every change
- [x] `FullVmInfo` now loads `firewall_rules` (for Increment 3 backend)
- [x] API_CHANGELOG.md + API_DOCUMENTATION.md entries
- [x] OpenAPI auto-generated from handlers (`cargo build --features openapi` ok)
- [x] Unit tests: validators, enum round-trips, ApiVmFirewallRule::from,
      mock DB firewall CRUD

### Increment 3 — Proxmox backend (M-L) ✅ DONE
- [x] Translate DB rules → Proxmox PVE firewall rules
      (`ProxmoxClient::to_pve_firewall_rule`, tagged with `lnvps-fw:{id}` comment)
- [x] Sync semantics in `patch_firewall`: delete stale user rules (by pos, desc)
      then re-add current set in reverse priority order (PVE inserts at top);
      ipfilter anti-spoof ACCEPT rule always preserved
- [x] Added `ProxmoxClient::delete_vm_firewall_rule` (DELETE by pos)
- [x] Unit tests: inbound tcp port-range + outbound any single-port disabled
- [x] Full workspace tests green (`--test-threads=1`)

## Summary

All three increments complete. nftables backend (#33) + `use_nftables` host
flag (#34) remain out of scope (separate issues); libvirt `patch_firewall`
stays a stub until then. Default policy unchanged (allow-all); anti-spoof always
enforced.

## Notes

- Default policy: inbound allow-all, outbound allow-all (current behaviour).
- Anti-spoof ipfilter rules always enforced regardless of user rules.
- Protocols: TCP/UDP/ICMP/Any. Port range optional (start/end).
- Direction: inbound / outbound.
