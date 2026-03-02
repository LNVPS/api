# Migrate vm_payment to Subscriptions System

**Status:** in-progress
**Started:** 2026-02-23
**Last updated:** 2026-03-02

## Goal

Consolidate `vm_payment` into `subscription_payment` so there is a single unified payment table. VMs link to subscriptions via `vm.subscription_id`. Drop `vm_payment` when complete.

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

### Increment 3: VM payment creation updates
- [ ] Update `renew()` / `renew_intervals()` to create `SubscriptionPayment` with `vm.subscription_id`
- [ ] Update `create_upgrade_payment()` to create `SubscriptionPayment` with `payment_type=Upgrade`, `metadata`
- [ ] Update `GET /api/v1/vm/{id}/renew` to return SubscriptionPayment
- [ ] Update `GET /api/v1/vm/{id}/invoice/{payment_id}` to query subscription_payment
- [ ] Update `GET /api/v1/vm/{id}/invoices` to query via vm.subscription_id
- [ ] Verify build + tests pass

### Increment 4: Payment processing updates
- [ ] Update Lightning webhook handler to use `subscription_payment`
- [ ] Update Revolut webhook handler to use `subscription_payment`
- [ ] Handle upgrades: check `metadata.upgrade_params`, look up VM via `get_vm_by_subscription()`
- [ ] Verify build + tests pass

### Increment 5: VM upgrade updates subscription & line item
- [ ] Update `convert_to_custom_template()` to update subscription interval to `1 Month`
- [ ] Update `convert_to_custom_template()` to update line item amount + configuration
- [ ] Verify build + tests pass

### Increment 6: Admin API updates
- [ ] Update `GET /api/admin/v1/vms/{id}/payments` to query via vm.subscription_id
- [ ] Update `GET /api/admin/v1/vm_payments/{id}` to query subscription_payment
- [ ] Verify build + tests pass

### Increment 7: Reporting updates
- [ ] Update revenue report queries to use subscription_payment
- [ ] Update company report queries
- [ ] Update referral cost tracking to join via vm.subscription_id
- [ ] Verify build + tests pass

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
