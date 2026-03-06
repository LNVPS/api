# Migrate vm_payment to Subscriptions System

**Status:** in-progress
**Started:** 2026-02-23
**Last updated:** 2026-03-04
**Phase 2+3 status:** All increments 11–19 complete

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

### Increment 8: Subscription creation for new VMs ✓
- [x] Update standard VM provisioning to create subscription + line item (done in Inc 3+4)
- [x] Update custom VM provisioning to create subscription + line item (done in Inc 3+4)
- [x] Update IP range subscription creation to explicitly set interval on subscription (already correct)
- [x] Verify build + tests pass

### Increment 9: Testing & validation ✓
- [x] Unit tests: subscription_payment_paid() for VMs (time_value path)
- [x] Unit tests: subscription_payment_paid() for regular subscriptions (interval path)
- [x] Unit tests: interval computation from subscription (Day/Month/Year)
- [x] Unit tests: standard vs custom VM subscription creation (provision/provision_custom)
- [x] Unit tests: consecutive payment stacking
- [x] Unit tests: list_vm_subscription_payments_paginated pagination
- [x] Unit tests: NodeInvoiceHandler::mark_payment_paid (Renewal + Upgrade paths)
- [x] Fix Bug 1 (double-conversion in renew_subscription): collect full NewPaymentInfo from get_vm_cost_for_intervals; do not pass already-converted BTC amounts through get_amount_and_rate again
- [x] Fix Bug 2 (time_value: None): set time_value from summed NewPaymentInfo.time_value values on created SubscriptionPayment
- [x] Add amount/time_value assertions to all 4 renew tests
- [ ] Data migration tests against backup
- [ ] Validation endpoint: VMs without subscriptions, missing time_value, duplicates

### Increment 10: Documentation & cleanup ✓
- [x] Update API_CHANGELOG.md
- [x] Add migration notes to docs/agents/migrations.md
- [ ] Remove deprecated vm_payment code after finalization migration (blocked on production verification)

### Finalization (after production verification)
- [ ] Apply finalization migration: `ALTER TABLE vm MODIFY subscription_id NOT NULL`
- [ ] Apply finalization migration: `DROP TABLE vm_payment`

---

## Phase 2: General-Purpose Subscription Lifecycle

The lifecycle worker currently has VM-specific logic (`check_vms`, `handle_vm_state`). The goal is to generalise it so that *any* subscription product (IP ranges, ASN sponsoring, DNS hosting, future products) benefits from the same expiry detection, auto-renewal, suspension, and deletion behaviour.

### Context

- `Subscription.expires` is already extended atomically by `subscription_payment_paid()` for all product types (VM and non-VM).
- `Subscription.auto_renewal_enabled` exists on the subscription record but is only read for VMs today.
- Non-VM subscriptions (e.g. `IpRangeSubscription`) have `is_active` / `ended_at` fields that serve as the "suspension" state, but nothing flips them today.
- `check_vms` and `handle_vm_state` in `worker.rs` are the only lifecycle enforcement points; they must be extended or their logic extracted.
- VM lifecycle decisions read `vm.expires` directly. After this phase, `vm.expires` should remain authoritative for hypervisor decisions, but it must continue to be driven by `subscription.expires` (already the case via `subscription_payment_paid`).

### Increment 11: DB layer — subscription lifecycle queries ✓
- [x] Add `list_expiring_subscriptions(within_seconds: u64) -> Vec<Subscription>` to DB trait + MySQL + mock
- [x] Add `list_expired_subscriptions() -> Vec<Subscription>` to DB trait + MySQL + mock
- [x] Add `deactivate_subscription(id: u64)` to DB trait + MySQL + mock: sets `is_active = false` + flips `ip_range_subscription.ended_at`
- [x] Implement all `ip_range_subscription` mock methods (were `todo!()`); add `ip_range_subscriptions` field to `MockDb`
- [x] Verify build + 116 unit tests pass

### Increment 12: Worker — generalised `check_subscriptions` loop ✓
- [x] Add `WorkJob::CheckSubscriptions` variant + `can_skip` + `Display` to `lnvps_api_common/src/work/mod.rs`
- [x] Add `check_subscriptions()` to `Worker`: iterates all active subscriptions, calls `handle_subscription_state`
- [x] Add `handle_subscription_state(sub, last_check)`: expiring-soon NWC attempt / notify; expired non-VM deactivation; grace-period cancellation notify
- [x] Add `get_last_check_subscriptions` / `set_last_check_subscriptions` KV helpers
- [x] Wire `WorkJob::CheckSubscriptions` into `try_job`
- [x] Schedule at 30-second interval in `bin/api.rs`
- [x] Verify build + 116 unit tests pass

### Increment 13: VM lifecycle — drive from subscription.expires ✓
- [x] Add `vm_expires(vm)` helper: resolves `vm.subscription_line_item_id → subscription.expires`, falls back to `vm.expires`
- [x] Rewrite `handle_vm_state`: uses `vm_expires()` for stop/delete decisions; remove NWC auto-renewal path (now owned by `handle_subscription_state`)
- [x] Update `check_vm` and `check_vms_on_host` spawn guards to use `vm_expires()`
- [x] Verify build + 116 unit tests pass

### Increment 14: IP range deactivation on expiry ✓
- [x] `deactivate_subscription` (Inc 11) sets `ip_range_subscription.is_active = false` + `ended_at = NOW()` for all linked rows in a transaction
- [x] `handle_subscription_state` (Inc 12) calls `deactivate_subscription` for non-VM expired subscriptions and sends "expired and deactivated" notification
- [x] Expiring-soon notification fires for all subscription types including IP range (same 1-day window)
- [x] All covered by Inc 11–12 implementation; no additional code needed

### Increment 15: Unit tests for generalised lifecycle ✓
- [x] Test `list_expiring_subscriptions`: returns soon-expiring active subscriptions; excludes far-future
- [x] Test `list_expired_subscriptions`: returns past-expiry active subscriptions; excludes not-yet-expired
- [x] Test `deactivate_subscription`: flips `is_active = false` on subscription
- [x] Test `deactivate_subscription`: sets `is_active = false` + `ended_at` on linked `ip_range_subscription` rows
- [x] 122 unit tests pass (6 new)

---

## Phase 3: Generic Payment Completion Pipeline

Currently `NodeInvoiceHandler` and `RevolutPaymentHandler` each independently duplicate the same post-payment sequence (mark paid → fetch VM before/after → log history → dispatch WorkJob). Neither handler can complete a non-VM payment (both call `get_vm_by_subscription` unconditionally, which returns `RowNotFound` for IP range subscriptions). Stripe is a stub. Admin handlers duplicate the pattern a third and fourth time without dispatching work jobs.

This phase extracts a single `on_payment_complete` pipeline that is product-agnostic and payment-method-agnostic.

### Context

- `subscription_payment_paid()` in the DB layer is already product-agnostic — it extends `subscription.expires` and optionally `vm.expires` for VM subscriptions. No changes needed there.
- The VM-specific post-payment actions (logging, `CheckVm` dispatch) need to be moved into a product handler abstraction.
- IP range subscriptions have no post-payment actions today; this phase adds CIDR allocation + `ip_range_subscription.is_active` flip.
- Cancel-competing-upgrades logic is also duplicated per payment method and must be centralised.

### Increment 16 + 17: `PaymentCompletionHandler` trait + centralised `complete_payment` ✓
- [x] Define `PaymentCompletionHandler` trait in `lnvps_api/src/payments/mod.rs`
- [x] Implement `VmPaymentCompletionHandler`: fetches VM before/after, logs history, dispatches `CheckVm`/`ProcessVmUpgrade`
- [x] Implement `NonVmPaymentCompletionHandler`: dispatches `CheckSubscriptions`
- [x] Implement `make_completion_handler` dispatcher: selects handler by `subscription_type`
- [x] Extract `complete_payment(db, payment, handler, cancel_fn)` free function
- [x] Refactor `NodeInvoiceHandler`: replaces `mark_payment_paid(vm_id)` with `complete(payment)` — removes all duplicated VM logic and the `get_vm_by_subscription` call
- [x] Refactor `RevolutPaymentHandler::try_complete_payment` — removes duplicated VM history logging, uses `complete_payment`; also removes `VmHistoryLogger` from struct
- [x] `admin_complete_subscription_payment`: add `CheckSubscriptions` WorkJob dispatch (was missing)
- [x] Remove `VmHistoryLogger` from both handler structs (moved into `VmPaymentCompletionHandler`)
- [x] 203 unit tests pass (81 lnvps_api + 122 lnvps_api_common)

### Increment 18: Stripe handler implementation ✓
- [x] Implement `StripePaymentHandler` struct with `StripeApi`, `db`, `tx`, `config_id`
- [x] Implement `try_complete_payment`: looks up payment by ext_id, calls `complete_payment` + `make_completion_handler`
- [x] Implement cancel-competing-upgrades via `api.cancel_payment_intent`
- [x] Implement `listen()`: subscribes to `WEBHOOK_BRIDGE`, filters Stripe endpoint, verifies signature, handles `payment_intent.succeeded`
- [x] Wire Stripe handler into `listen_all_payments` (behind `#[cfg(feature = "stripe")]`)
- [x] Add `/api/v1/webhook/stripe` route to `webhook.rs`
- [x] Stripe payment creation (`bail!` in provisioner) left as-is — checkout session creation is out of scope for this phase
- [x] Verified build with `--features stripe`

### Increment 19: Unit tests for generic payment pipeline ✓
- [x] Test `complete` (VM renewal): marks paid, dispatches `CheckVm`
- [x] Test `complete` (VM upgrade): dispatches `ProcessVmUpgrade`
- [x] Test `complete` (non-VM IpRange renewal): marks paid, dispatches `CheckSubscriptions` (not `CheckVm`)
- [x] 204 unit tests pass (82 lnvps_api + 122 lnvps_api_common)

## Notes

- Test database backup: `~/Downloads/lnvps_lnvps-20250316020007.sql.gz`
- `VmCostPlanIntervalType` has ~50 references — rename via type alias for incremental migration
- Custom VMs always use 1 Month interval; standard VMs copy from cost plan
- All line items on a subscription share the same interval (interval lives on subscription, not line item)
- Phase 2 key invariant: `vm.expires` stays on the `vm` table for hypervisor decisions; `subscription.expires` is the billing/policy source of truth that drives it
- Phase 3 key invariant: payment methods know nothing about products; product handlers know nothing about payment methods; `complete_payment` is the only join point
