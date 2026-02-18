# Agent Rules Compliance Evaluation

**Status:** in-progress
**Started:** 2026-02-18
**Last updated:** 2026-02-18

## Goal

Bring the codebase into full compliance with all rules in `agents/`. Every rule should be COMPLIANT with no gaps.

## Findings

### Rule 1 — Project Overview: PARTIAL

- Documented crates all exist and are correct.
- Three undocumented crates are present in the workspace: `lnvps_health`, `lnvps_fw_service`, `lnvps_ebpf`.
- `agents/project-overview.md` needs a row for each of these.

### Rule 2 — Code Style: COMPLIANT (fixed this session)

- Import order was wrong in `lnvps_api/src/api/routes.rs` and `lnvps_api_admin/src/admin/model.rs`. Both fixed.
- `panic!("Invalid router kind")` catch-all in `lnvps_api_admin/src/admin/model.rs` `From<RouterKind>` impl replaced
  with explicit `RouterKind::MockRouter => AdminRouterKind::Mikrotik`.
- No other violations found in reviewed files.

### Rule 3 — API Guidelines: COMPLIANT

- `ADMIN_API_ENDPOINTS.md` and `API_CHANGELOG.md` exist and are maintained.
- Amounts returned as u64 smallest units. No secrets in GET responses.

### Rule 4 — Currency: COMPLIANT

- `CurrencyAmount` used for conversions throughout. DB uses u64 smallest units.

### Rule 5 — Bug Fixes: COMPLIANT (fixed this session)

- Bug `d88e153` (payment amount formatted with `CurrencyAmount` instead of raw u64) had no regression test.
- Regression test `test_payment_received_description_uses_formatted_amount` added to
  `lnvps_api_common/src/vm_history.rs`. Passes.

### Rule 6 — Coverage: PARTIAL

- `lnvps_api_common/src/vm_history.rs`: was zero-covered. 16 tests added this session covering all `VmHistoryLogger`
  methods and `serialize_json_to_bytes`. All pass.
- `lnvps_api_admin`: **zero tests**. All handler functions and model builder methods are uncovered.

### lnvps_api_admin uncovered functions (from code review)

Model builder methods in `lnvps_api_admin/src/admin/model.rs`:

- `AdminHostInfo::from_host_and_region`
- `AdminHostInfo::from_host_region_and_disks`
- `AdminHostInfo::from_host_capacity`
- `AdminHostInfo::from_admin_vm_host`
- `AdminVmInfo::from_vm_with_admin_data`
- `AdminVmOsImageInfo::from_db_with_vm_count`
- `AdminVmHistoryInfo::from_vm_history_with_admin_data`
- `AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data`
- `AdminIpRangeSubscriptionInfo::from_subscription_with_admin_data`
- `CreateRouterRequest::to_router`
- `CreateIpRangeRequest::to_ip_range`
- `CreateAccessPolicyRequest::to_access_policy`
- `AdminCreateCostPlanRequest::to_cost_plan`
- `CreatePaymentMethodConfigRequest::to_payment_method_config`
- `Permission::from_str` / `Permission::fmt`
- `PartialProviderConfig::merge_with` / `PartialProviderConfig::provider_type`
- `CreateAvailableIpSpaceRequest::to_available_ip_space`
- `CreateIpSpacePricingRequest::to_ip_space_pricing`
- `AdminCreateSubscriptionRequest::to_subscription`
- `AdminCreateSubscriptionLineItemRequest::to_line_item`
- `CreateVmOsImageRequest::to_vm_os_image`
- All `From<T>` conversion impls in `model.rs`

Handler functions (no tests at all):

- `lnvps_api_admin/src/admin/routers.rs` — all handlers
- `lnvps_api_admin/src/admin/hosts.rs` — all handlers
- `lnvps_api_admin/src/admin/vms.rs` — all handlers
- other handler files in `lnvps_api_admin/src/admin/`

## Tasks

- [x] Audit all rules against codebase
- [x] Fix import order in `lnvps_api/src/api/routes.rs`
- [x] Fix import order in `lnvps_api_admin/src/admin/model.rs`
- [x] Remove `panic!` from `From<RouterKind>` in `lnvps_api_admin/src/admin/model.rs`
- [x] Add regression test for bug d88e153 (`test_payment_received_description_uses_formatted_amount`)
- [x] Add tests for all `VmHistoryLogger` methods in `lnvps_api_common/src/vm_history.rs`
- [ ] Add `lnvps_health`, `lnvps_fw_service`, `lnvps_ebpf` to `agents/project-overview.md`
- [ ] Add tests for all model builder methods in `lnvps_api_admin/src/admin/model.rs`
- [ ] Add tests for handler functions in `lnvps_api_admin/src/admin/` (routers, hosts, vms, etc.)
- [ ] Run `cargo llvm-cov --summary-only -- --test-threads=1` and confirm 100% function coverage on `lnvps_api_admin`

## Notes

- `VmHistoryActionType` does not derive `PartialEq` — use `.to_string()` comparisons in tests.
- `MockDb` in `lnvps_api_common/src/mock.rs` is the right harness for unit-testing `lnvps_api_admin` model methods that
  need a DB.
- Handler tests will likely need an Axum `TestClient` or direct function calls with a mock `RouterState`.
- All tests must run with `cargo test -- --test-threads=1` (shared `LazyLock` state in mocks).
