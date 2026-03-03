# Migrate vm_payment to Subscriptions System

**Status:** in-progress
**Started:** 2026-02-23
**Last updated:** 2026-03-04

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

### Increment 14: IP range deactivation on expiry

- [ ] When `deactivate_subscription` is called for a subscription with one or more `IpRange` line items, set `ip_range_subscription.is_active = false` and `ended_at = NOW()` for each linked row.
- [ ] Add worker notification: "Your IP range subscription has expired and your allocation has been deactivated."
- [ ] Add worker notification for expiring-soon (same 1-day window as VMs).
- [ ] Verify build + tests pass

### Increment 15: Unit tests for generalised lifecycle

- [ ] Test `check_subscriptions`: expiring-soon triggers NWC attempt then notification
- [ ] Test `check_subscriptions`: expired non-VM subscription triggers `deactivate_subscription`
- [ ] Test `check_subscriptions`: expired VM subscription still stops the hypervisor VM
- [ ] Test `deactivate_subscription`: flips `is_active = false` and sets `ended_at` on linked IP range rows
- [ ] Test grace-period deletion notification path
- [ ] Verify all existing 214+ unit tests still pass

---

## Phase 3: Generic Payment Completion Pipeline

Currently `NodeInvoiceHandler` and `RevolutPaymentHandler` each independently duplicate the same post-payment sequence (mark paid → fetch VM before/after → log history → dispatch WorkJob). Neither handler can complete a non-VM payment (both call `get_vm_by_subscription` unconditionally, which returns `RowNotFound` for IP range subscriptions). Stripe is a stub. Admin handlers duplicate the pattern a third and fourth time without dispatching work jobs.

This phase extracts a single `on_payment_complete` pipeline that is product-agnostic and payment-method-agnostic.

### Context

- `subscription_payment_paid()` in the DB layer is already product-agnostic — it extends `subscription.expires` and optionally `vm.expires` for VM subscriptions. No changes needed there.
- The VM-specific post-payment actions (logging, `CheckVm` dispatch) need to be moved into a product handler abstraction.
- IP range subscriptions have no post-payment actions today; this phase adds CIDR allocation + `ip_range_subscription.is_active` flip.
- Cancel-competing-upgrades logic is also duplicated per payment method and must be centralised.

### Increment 16: `PaymentCompletionHandler` trait + VM implementation

- [ ] Define trait `PaymentCompletionHandler` in `lnvps_api_common` (or `lnvps_api/src/payments/mod.rs`):
  ```rust
  #[async_trait]
  pub trait PaymentCompletionHandler: Send + Sync {
      /// Called after subscription_payment_paid() succeeds.
      /// `payment` is already marked paid in the DB.
      async fn on_payment_complete(&self, payment: &SubscriptionPayment) -> Result<()>;
  }
  ```
- [ ] Implement `VmPaymentCompletionHandler`:
  - Fetch VM (via `get_vm_by_subscription`) — returns early (no-op) if no VM linked
  - Fetch VM state before/after payment for history logging
  - Call `vm_history_logger.log_vm_payment_received` + `log_vm_renewed`
  - Branch on `payment_type`: dispatch `WorkJob::ProcessVmUpgrade` (Upgrade) or `WorkJob::CheckVm` (Renewal)
- [ ] Implement `IpRangePaymentCompletionHandler`:
  - On first payment (`!is_setup` before the call): allocate CIDR block, insert `ip_range_subscription` row with `is_active = true`
  - On renewal: flip existing `ip_range_subscription.is_active = true`, clear `ended_at`
  - Send user notification: "Your IP range subscription is now active"
  - Dispatch `WorkJob::CheckSubscriptions` to pick up new state
- [ ] Implement a `CompositePaymentCompletionHandler` (or a dispatcher fn) that selects the right handler by inspecting `subscription_line_item.subscription_type`
- [ ] Verify build + tests pass

### Increment 17: Centralised `complete_payment` function

- [ ] Extract shared `complete_payment(db, payment, completion_handler, cancel_fn) -> Result<()>` free function in `payments/mod.rs`:
  1. Call `db.subscription_payment_paid(payment)` (atomic DB mark-paid + expiry extension)
  2. Call `completion_handler.on_payment_complete(payment)`
  3. Call `cancel_fn(payment)` to cancel competing upgrade payments for the same subscription (method-specific: cancel Lightning invoice vs. Revolut order vs. no-op)
- [ ] Refactor `NodeInvoiceHandler::mark_payment_paid` to call `complete_payment` — remove all duplicated VM logic
- [ ] Refactor `RevolutPaymentHandler::try_complete_payment` to call `complete_payment` — remove all duplicated VM logic; also remove the `get_vm_by_subscription` call (it moves into `VmPaymentCompletionHandler`)
- [ ] Refactor `admin_complete_vm_payment` to call `complete_payment`
- [ ] Refactor `admin_complete_subscription_payment` to call `complete_payment` (this also adds the missing WorkJob dispatch to the admin subscription path)
- [ ] Verify build + all existing tests pass

### Increment 18: Stripe handler implementation

- [ ] Implement `StripePaymentHandler::listen()` using Stripe webhook events (`payment_intent.succeeded`)
- [ ] Implement `StripePaymentHandler`'s payment lookup by `external_id` → `get_subscription_payment_by_ext_id`
- [ ] Implement cancel-competing-upgrades using Stripe API (cancel PaymentIntent)
- [ ] Wire into `complete_payment` with the same `CompositePaymentCompletionHandler`
- [ ] Remove the `bail!("not yet implemented")` for `PaymentMethod::Stripe` in `renew_subscription`
- [ ] Verify build + tests pass

### Increment 19: Unit tests for generic payment pipeline

- [ ] Test `complete_payment` with VM renewal: DB marked paid, VM history logged, `CheckVm` dispatched
- [ ] Test `complete_payment` with VM upgrade: `ProcessVmUpgrade` dispatched, competing upgrades cancelled
- [ ] Test `complete_payment` with IP range renewal: `ip_range_subscription.is_active` flipped, notification sent
- [ ] Test `complete_payment` with IP range first payment: CIDR allocated, `ip_range_subscription` row inserted
- [ ] Test `admin_complete_subscription_payment` now dispatches a WorkJob (regression: it previously did not)
- [ ] Verify all existing 214+ unit tests still pass

## Notes

- Test database backup: `~/Downloads/lnvps_lnvps-20250316020007.sql.gz`
- `VmCostPlanIntervalType` has ~50 references — rename via type alias for incremental migration
- Custom VMs always use 1 Month interval; standard VMs copy from cost plan
- All line items on a subscription share the same interval (interval lives on subscription, not line item)
- Phase 2 key invariant: `vm.expires` stays on the `vm` table for hypervisor decisions; `subscription.expires` is the billing/policy source of truth that drives it
- Phase 3 key invariant: payment methods know nothing about products; product handlers know nothing about payment methods; `complete_payment` is the only join point
