# Migrate vm_payment to Subscriptions System

**Status:** in-progress
**Started:** 2026-02-23
**Last updated:** 2026-03-02

## Goal

Consolidate `vm_payment` into `subscription_payment` so there is a single unified payment table. VMs link to subscriptions via `vm.subscription_line_item_id` (mirroring the `ip_range_subscription` → `subscription_line_item` pattern), so a single subscription can contain VMs, extra IPs, and other products as line items. Drop `vm_payment` when complete.

Full plan details captured in this work file.

## Findings

- `vm_payment` created in init migration (`20241103155733`), has ~50 references across codebase
- `subscription_payment` added in `20260127000000`, structurally similar but with different lifecycle
- VMs use two pricing paths: standard (`vm_template → vm_cost_plan`) and custom (`vm_custom_template → vm_custom_pricing`)
- Custom VMs are always billed monthly; standard VMs use `vm_cost_plan.interval_amount` + `interval_type`
- `subscription` table originally had `interval_amount`/`interval_type` but they were dropped in `20260130000003`
- `VmCostPlanIntervalType` enum has ~50 references across the codebase
- Upgrade flow (`convert_to_custom_template`) converts standard → custom and needs to update subscription + line item

## Tasks

### Increment 0: Rename VmCostPlanIntervalType → IntervalType ✓
- [x] Rename `VmCostPlanIntervalType` → `IntervalType` in `lnvps_db/src/model.rs`
- [x] Rename `ApiVmCostPlanIntervalType` → `ApiIntervalType` in `lnvps_api_common/src/model.rs`
- [x] Update all direct references across codebase to use new names (no aliases)
- [x] Verify build + tests pass

### Increment 1: Schema migration + database layer
- [x] Create SQL migration `20260302151134_vm_subscription_link.sql`: re-add `interval_amount`, `interval_type` to `subscription`; add `time_value`, `metadata` to `subscription_payment`; add `subscription_id` to `vm`
- [x] Backfill via DEFAULT values (interval_amount=1, interval_type=1=Month)
- [x] Add `VmRenewal=3`, `VmUpgrade=4` to `SubscriptionType` enum
- [x] Add `Upgrade=2` to `SubscriptionPaymentType` enum
- [x] Update `SubscriptionPayment` / `SubscriptionPaymentWithCompany` structs: add `time_value`, `metadata`
- [x] Update `Subscription` struct: add `interval_amount`, `interval_type`
- [x] Update `Vm` struct: add `subscription_id` (nullable)
- [x] Fix `subscription_payment_paid()` transaction bug; add VM path (time_value) + regular path (interval from subscription)
- [x] Add `get_vm_by_subscription()` and `list_vm_subscription_payments()` to trait + MySQL + mock
- [x] Update `insert_vm` / `update_vm` SQL to include `subscription_id`
- [x] Propagate new fields through all API models (admin + user-facing)
- [x] Fix all `Subscription {}` / `SubscriptionPayment {}` / `Vm {}` struct literals in source + tests
- [x] Verify build + tests pass

### Increment 2: Data migration tool ✓
- [x] Create `lnvps_api_admin/src/bin/migrate_vm_subscriptions.rs` standalone binary
- [x] Handle standard VMs (interval + amount from cost_plan)
- [x] Handle custom VMs (1-Month interval, amount=0 pending custom pricing)
- [x] Handle VMs with neither template (bail with warning)
- [x] Implement dry-run mode (--dry-run flag)
- [x] Idempotent: VMs with subscription_id already set are skipped
- [x] Fix `insert_subscription` / `insert_subscription_with_line_items` / `update_subscription` SQL to bind `interval_amount` and `interval_type`
- [ ] Test against local backup: `~/Downloads/lnvps_lnvps-20250316020007.sql.gz`

### Increment 3 + 4: VM payment creation + payment processing ✓
- [x] `vm.subscription_id` changed from `Option<u64>` to `u64` (NOT NULL)
- [x] Migration `20260302154256_vm_subscription_not_null.sql` to enforce NOT NULL
- [x] `provision()` creates Subscription + SubscriptionLineItem(VmRenewal) before inserting VM
- [x] `provision_custom()` does the same with 1-Month interval
- [x] `CostResult::Existing` changed to hold `SubscriptionPayment` (deduplication via `list_vm_subscription_payments`)
- [x] `price_to_payment_with_type` rewritten to create `SubscriptionPayment` (uses `vm.subscription_id`)
- [x] `renew()` / `renew_intervals()` return `SubscriptionPayment` via `renew_subscription(vm.subscription_id)`
- [x] `renew_amount()` returns `SubscriptionPayment`
- [x] `create_upgrade_payment()` uses `SubscriptionPaymentType::Upgrade`, stores config in `metadata` JSON
- [x] `auto_renew_via_nwc()` returns `SubscriptionPayment`
- [x] `handle_upgrade()` updated to accept `SubscriptionPayment`, reads `metadata`
- [x] Lightning invoice handler uses `get_subscription_payment` + `subscription_payment_paid`
- [x] Revolut handler uses `get_subscription_payment_by_ext_id` + `subscription_payment_paid`
- [x] Both handlers look up VM via `get_vm_by_subscription(subscription_id)` for history logging
- [x] Cancel other upgrade payments via `list_vm_subscription_payments` + `update_subscription_payment`
- [x] `v1_renew_vm` → `ApiVmPayment::from_subscription_payment`
- [x] `v1_get_payment` → `get_subscription_payment`
- [x] `v1_get_payment_invoice` → `get_subscription_payment` + `from_subscription_payment`
- [x] `v1_payment_history` → `list_vm_subscription_payments`
- [x] `v1_vm_upgrade` → `ApiVmPayment::from_subscription_payment`
- [x] `ApiInvoiceItem::from_subscription_payment` added
- [x] `insert_subscription` / `insert_subscription_with_line_items` mock fixed to actually insert
- [x] Test helpers updated to create subscriptions for VMs
- [x] Verify build + all 214 unit tests pass

### Increment 5: VM upgrade updates subscription & line item ✓
- [x] Update `convert_to_custom_template()` to update subscription interval to `1 Month`
- [x] Update `convert_to_custom_template()` to update line item `subscription_type` → `VmRenewal` and store config
- [x] Verify build + tests pass

### Increment 6: Admin API updates ✓
- [x] `admin_list_vm_payments` — use `list_vm_subscription_payments` with manual pagination
- [x] `admin_get_vm_payment` — use `get_subscription_payment` + `get_vm_by_subscription` for ownership check
- [x] `admin_complete_vm_payment` — use `subscription_payment_paid`; read upgrade config from `metadata`
- [x] `AdminVmPaymentInfo::from_subscription_payment()` added to model
- [x] Verify build + all 214 unit tests pass

### Increment 7: Reporting updates ✓
- [x] Update revenue report queries to use subscription_payment
- [x] Update company report queries
- [x] Update referral cost tracking to join via vm.subscription_id
- [x] Verify build + tests pass

### Increment 8: Subscription creation for new VMs
- [ ] Update standard VM provisioning to create subscription + line item
- [ ] Update custom VM provisioning to create subscription + line item
- [ ] Update IP range subscription creation to explicitly set interval on subscription
- [ ] Verify build + tests pass

### Increment 9: Testing & validation
- [ ] Unit tests: subscription_payment_paid() for VMs
- [ ] Unit tests: subscription_payment_paid() for regular subscriptions
- [ ] Unit tests: interval computation from subscription
- [ ] Unit tests: standard vs custom VM subscription creation
- [ ] Integration tests: VM renewal flow
- [ ] Integration tests: VM upgrade flow (standard → custom)
- [ ] Integration tests: webhook processing
- [ ] Data migration tests against backup
- [ ] Validation endpoint: VMs without subscriptions, missing time_value, duplicates

### Increment 10: Documentation & cleanup
- [ ] Update API_DOCUMENTATION.md
- [ ] Update API_CHANGELOG.md
- [ ] Add migration notes to docs/agents/migrations.md
- [ ] Remove deprecated vm_payment code after finalization migration

### Finalization (after production verification)
- [ ] Apply finalization migration: `ALTER TABLE vm MODIFY subscription_id NOT NULL`
- [ ] Apply finalization migration: `DROP TABLE vm_payment`

## Notes

- Test database backup: `~/Downloads/lnvps_lnvps-20250316020007.sql.gz`
- `VmCostPlanIntervalType` has ~50 references — rename via type alias for incremental migration
- Custom VMs always use 1 Month interval; standard VMs copy from cost plan
- All line items on a subscription share the same interval (interval lives on subscription, not line item)
