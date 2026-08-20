# Discount Engine (phase 1: discount codes)

**Status:** complete
**Started:** 2026-08-20
**Last updated:** 2026-08-20 (all six increments landed; phase 1 complete)

Tracks [#57](https://github.com/LNVPS/api/issues/57). Whole feature is **XL**, so it is split into
the increments below; each is L-or-smaller and lands as its own PR.

## Goal

A customer can enter a **discount code** on an order and pay less. Admins create codes whose
eligibility *and* effect are a single **CEL expression** returning a decision map, clamped in Rust
so a badly written rule can never over-discount. Usage windows, global usage limits and per-user
limits are enforced by DB columns/rows, not by the expression.

Phase 2 (not this work file): automatic (code-less) discounts, richer admin templates, stacking.

## Decisions (agreed with @v0l, 2026-08-20)

| Question | Decision |
|---|---|
| Rule representation | **CEL** expression -> decision map (`cel` crate, v0.14). No Lua. |
| Multiple eligible discounts | **Best-value auto-select** — evaluate all eligible candidates, apply the one that saves the most. Never stack. |
| `free_item` effect | **Dropped for phase 1.** Effects are percent-off and fixed-amount-off only. "FREE X when you spend Y" is expressed as an amount discount. |
| Referral interaction | Discount applies first; **referral rev-share is calculated on the discounted (actually paid) amount**. |
| Recurring subscriptions | **First payment only.** Renewals bill at list price; no discount state on the subscription. |
| Redemption timing | **On payment settlement**, i.e. in the `SubscriptionHandler::complete_payment` funnel. Unpaid/expired invoices never consume stock. Accept the small over-issue window rather than build a reservation sweeper. |

## Findings (current codebase)

- **Nothing discount-related exists.** Every `discount` hit in `lnvps_api_common/src/pricing.rs`
  (`UpgradeCostQuote::discount`, lines ~40, 1529, 1600-1630) is the *prorated credit for time
  remaining on the old plan* during a VM upgrade — unrelated naming, must not be conflated.
- **Pricing entry points** — `PricingEngine` (`lnvps_api_common/src/pricing.rs:283`), built from
  `db + ExchangeRateService + VatClient`. Quotes return `CostResult::{Existing(SubscriptionPayment),
  New(NewPaymentInfo)}` (`pricing.rs:1669`). `NewPaymentInfo { amount, currency, rate, time_value,
  new_expiry, tax, tax_details, processing_fee }` — `amount` is **net**, tax and processing fee are
  derived from it, so the discount must be applied to `amount` *before* `determine_tax` and
  `net_from_gross`/fee gross-up, or tax and fees will be charged on money the customer never pays.
- **Cost paths that must all route through the discount step**: `get_vm_cost` /
  `get_vm_cost_for_intervals` (`pricing.rs:688,693`), template vs custom VM cost
  (`get_template_vm_cost`, `get_custom_vm_cost`), `get_cost_by_amount` (`pricing.rs:530`) and its
  subscription equivalent. `get_cost_by_amount` scales time from an amount *already paid* — a
  discount there means more time for the same sats; decide explicitly per-path rather than
  applying blindly (see increment 3).
- **Settlement funnel** — `SubscriptionHandler::complete_payment`, reached from
  `lnvps_api/src/payments/invoice.rs:42` (Lightning), `revolut.rs:224`, `stripe.rs:47`,
  `onchain.rs`. Single place to record a redemption for every payment method.
- **Referral rev-share** — `lnvps_api/src/referral/mod.rs` (`process_one`, `owed_fiat`,
  `owed_btc_msat`) computes payouts from recorded payment amounts. Because the discount reduces
  `SubscriptionPayment.amount` itself, the "pay on discounted amount" decision needs **no referral
  code change** — verify this in increment 3 rather than assuming it.
- **Admin RBAC** — add `AdminResource::Discount = 31` to the enum at `lnvps_db/src/model.rs:2306`
  (next free discriminant; 30 = `SupportAgent`), plus its `Display` arm and any `FromStr`/list.
- **Admin module layout** — one file per resource in `lnvps_api_admin/src/admin/` (e.g.
  `referrals.rs`, `cost_plans.rs`); register in `mod.rs`; document in `ADMIN_API_ENDPOINTS.md`.
- **Mock DB** — `lnvps_api_common/src/mock.rs` implements `LNVpsDb` for tests; every new trait
  method must be implemented there or the whole workspace test build breaks.
- **Money rules** — `docs/agents/currency.md`. Minor units as `u64`/`i64` everywhere; no `f64` in
  discount math (the existing `cost_per_second` f64 is legacy and must not be extended).

## Increments

### 1. CEL rule evaluator + `DiscountDecision` (M)

- Add `cel = "0.14"` to the workspace; new module `lnvps_api_common/src/discount/`
  (`mod.rs`, `context.rs`, `decision.rs`).
- Read-only context exposed to rules — the security boundary, hand-built, **never** a DB row
  serialized wholesale: `order { amount, currency, months/intervals, interval_type, is_new,
  template_id, product }`, `user { id, country }`, `history { orders, total_spend }`, `now`.
  All money i64 minor units.
- `DiscountDecision { percent: Option<u8>, amount: Option<i64>, currency: Option<String> }`,
  deserialized from the CEL result map; `{}`/null/absent = not applicable.
- Rust-side validation/clamping: percent `0..=100`, amount `>= 0` and `<= order total`, currency
  must parse and match the order currency (or be converted, decided in increment 3), rule errors
  and non-map results = "no discount" + logged, never a 500.
- Tests: 100% function coverage per `docs/agents/coverage.md`, plus safety cases —
  percent 500, negative amount, wrong currency, wrong return type, syntax error, deeply nested
  expression, huge literals.

### 2. Migration + DB model + `LNVpsDb` methods (M)

- Migration `lnvps_db/migrations/<ts>_discount.sql` (`date +%Y%m%d%H%M%S`, per
  `docs/agents/migrations.md`):
  - `discount(id, company_id, code NULL UNIQUE, name, rule TEXT, valid_from, valid_to,
    usage_limit NULL, used_count NOT NULL DEFAULT 0, per_user_limit NULL, active, created)`
  - `discount_redemption(id, discount_id FK, user_id FK, subscription_payment_id, amount_off,
    currency, redeemed_at)`, unique on `(discount_id, subscription_payment_id)` so a replayed
    settlement cannot double-count.
  - Index on `code`; `code NULL` reserved for phase 2 automatics.
- `Discount` / `DiscountRedemption` structs in `lnvps_db/src/model.rs`; trait methods on `LNVpsDb`:
  CRUD, `get_discount_by_code`, `count_user_redemptions`, atomic
  `redeem_discount` (`UPDATE ... SET used_count = used_count + 1 WHERE id = ? AND (usage_limit IS
  NULL OR used_count < usage_limit)` + insert redemption, one transaction).
- Implement in `lnvps_db/src/mysql.rs` and in `lnvps_api_common/src/mock.rs`.

### 3. `PricingEngine` integration (done)

- `PricingEngine::quote_discount(&DiscountOrder) -> Result<Option<AppliedDiscount>>` in
  `lnvps_api_common/src/discount/engine.rs`: resolve candidates -> DB guards (company, `active`,
  window, `usage_limit`, `per_user_limit`) -> context -> evaluate -> clamp -> best value.
- A discount is resolved for the **whole order**, not per VM line item: an order aggregates line
  items plus setup fees in `SubscriptionHandler::renew_subscription_inner`, so discounting a single
  `NewPaymentInfo` inside `get_vm_cost_for_intervals` would miss everything else. `NewPaymentInfo`
  is therefore unchanged; increment 5 subtracts `amount_off` from the aggregated net and
  re-derives tax and processing fee from it.

### 4. Admin API: discount CRUD + rule preview (done)

- `lnvps_api_admin/src/admin/discounts.rs`: list/get/create/update/delete, `{id}/redemptions`,
  and `POST /api/admin/v1/discounts/preview`.
- `AdminResource::Discount = 31` + grants migration `20260820130000_discount_rbac_permissions.sql`
  (a resource with no grants is unreachable — there is no super-admin bypass, and `model.rs` has a
  test that fails the build if a resource is granted to nobody).
- The `list_*` pagination rule forced `list_discounts` / `list_discount_redemptions` to become
  `*_paginated` (LIMIT/OFFSET + COUNT), plus `sum_discount_redemptions` for campaign cost.
- `ADMIN_API_ENDPOINTS.md` and `API_CHANGELOG.md` updated.

### 5. User API: apply a code (done)

- **Provenance lives on `discount_redemption`, not on `subscription_payment`.** The plan was two
  columns on the payment; instead the redemption row gained `settled` / `created` / `settled_at`
  and a `UNIQUE (subscription_payment_id)`. Reasons: the payment's `amount` is *already* net of the
  discount, so tax, refunds and referral commission are right without any payment column;
  `amount_off` is then recorded exactly once; the unique key expresses the no-stacking rule where
  it cannot be bypassed *and* makes settlement idempotent; and `SubscriptionPayment` has no
  `Default` impl and 43 exhaustive struct literals across the workspace, so adding fields there
  would have been a large mechanical edit for a worse model.
- Row is written **unsettled** when the invoice is created and settled in
  `SubscriptionHandler::apply_payment` — not `complete_payment`, because the admin-override path
  marks a payment paid itself and reaches `apply_payment` via `WorkJob::ApplySubscriptionPayment`.
  Only settled rows count towards limits or campaign cost.
- `code` query parameter on `GET /api/v1/vm/{id}/renew` and `GET /api/v1/subscriptions/{id}/renew`;
  `discount { code, amount_off }` on `ApiVmPayment` / `ApiSubscriptionPayment`, read back from the
  recorded row so a reused pending invoice reports what it was really created with.
- `discount_tax_lines` (in `lnvps_api_common::discount`) attributes the discount across lines
  proportionally and **recomputes** each line's tax as `floor(net * rate)` — the customer is never
  taxed on money they do not pay. The processing fee is scaled on the discounted gross.
- `API_CHANGELOG.md` and `API_DOCUMENTATION.md` updated.

### 6. E2E + docs (done)

- `lnvps_e2e/src/discounts.rs`: admin CRUD lifecycle, duplicate/invalid rejection, rule preview
  (clamping, tiering, declining, broken rules, non-decision returns), and that a rule cannot read
  outside its context. `lifecycle.rs` gains the customer path: code reduces the invoice, unpaid
  invoice consumes nothing, settlement redeems exactly once, per-user limit then refuses, a
  redeemed discount cannot be deleted but can be deactivated.
- `docs/agents/discounts.md` written and linked from `AGENTS.md`.

**Two bugs the e2e run found, both fixed:**

1. **A code was answered with the existing full-price invoice.** `get_vm_cost_for_intervals`
   returns a pending unpaid payment when method/type/time_value match, so entering a code after an
   invoice existed handed the customer the un-discounted one while reporting success. Fixed with
   `get_vm_cost_for_intervals_fresh`, used whenever a code is supplied (unit test:
   `a_code_is_not_answered_with_an_existing_full_price_invoice`).
2. **Lifecycle cleanup could not delete the company** — `discount` has a real FK to `company`.
   Added `db::hard_delete_company_discounts`.

Also worth knowing (pre-existing, not fixed here): pending-payment reuse matches on
`(method, type, time_value)` and **not** on price, so an unpaid invoice created before a VM upgrade
is reused after it, billing the old rate. The lifecycle test only surfaced this because an extra
quote left a stray invoice; that quote was removed.

## Tasks

- [x] Agree open questions (rule engine, stacking, free_item, referral, recurrence, redemption timing)
- [x] Create this work file
- [x] Increment 1 — CEL evaluator + `DiscountDecision` (`lnvps_api_common/src/discount/`)
- [x] Increment 2 — migration + DB model + `LNVpsDb` methods
- [x] Increment 3 — `PricingEngine` integration (`quote_discount`)
- [x] Increment 4 — admin API CRUD + rule preview
- [x] Increment 5 — user API apply-code + redemption on settlement
- [x] Increment 6 — E2E tests + docs + changelog

## Notes

- **CEL map keys must be quoted.** The examples in the issue (`{percent: 10}`) are protobuf
  message syntax; in CEL a bare identifier in a map literal is a *variable reference* and fails
  with `Undeclared reference to 'percent'`. The supported form is `{'percent': 10}` /
  `{'amount': 500, 'currency': 'EUR'}`. The admin condition builder must emit quoted keys, and the
  docs in increment 6 must say so.
- **Increment 2 verification:** the migration was applied to a scratch DB (`mig_test`) on top of the
  full migration history against the docker MariaDB, and every statement in the `mysql.rs` impl was
  run by hand there (`RETURNING id` works; `INSERT IGNORE` returns 0 rows on a replayed payment).
  The `LNVpsDbMysql` methods themselves are uncovered by unit tests, as every other method in that
  file is — real-DB coverage arrives with the e2e tests in increment 6. `MockDb` and the `Discount`
  helpers are at 100%.
- Settlement increments `used_count` **unconditionally** rather than gating on `usage_limit`: by
  then the customer has paid a discounted invoice, which must be honoured. The count therefore
  records what really happened and can sit at or past the limit, which still refuses every later
  quote. This is the accepted over-issue window from the redemption-timing decision.
- The admin handlers themselves (and `router()`) are not unit-tested, matching every other module
  in `lnvps_api_admin`; admin endpoints are covered by `lnvps_e2e/src/admin_api.rs`, which
  increment 6 extends. The logic they call (`to_discount`, `apply_update`, `preview_rule`,
  `discount_info`) is tested directly.
- **Referral interaction is already correct with no referral-code change:** `list_referral_usage`
  computes commission from the stored `subscription_payment.amount`, and a discount reduces that
  stored amount, so the referrer is paid on what the customer actually paid. Asserted end-to-end
  in increment 6, once discounted payments exist.
- **Amount-already-paid paths take no discount:** `get_cost_by_amount` and
  `get_subscription_cost_by_amount` convert an arbitrary amount the customer already sent (LNURL
  top-up, on-chain deposit) into time. A discount there could only mean "more time for the same
  money", which is not what a code promises and cannot be shown on an already-paid invoice.
- **`history.total_spend` was dropped from the rule context.** A customer's payments span
  currencies, so a single lifetime-spend number is either wrong or needs their whole payment
  history converted at every quote. `history.orders` (settled payment count) and `order.is_new`
  cover the "first order" case that motivated it.
- `discount.code` is unique **globally**, not per company: a customer types a code without
  selecting a company, so a code shared by two companies would be ambiguous exactly when used.
  NULL codes stay distinct in MySQL, so phase 2 automatic discounts are unaffected.
- Rule results are strict: a bare `10` or `'10%'` is an **error**, not "10 percent" — a typo must
  not silently change what customers are charged. `{}`, `null` and `false` all mean "no discount".

- The `cel` crate (0.14.x, formerly `cel-interpreter`) is pure Rust and non-Turing-complete, so
  evaluation terminates; still cap rule length at the API boundary and treat any evaluation error
  as "no discount".
- Do **not** let a rule see raw DB rows. Context fields are added deliberately, one at a time.
- `used_count` may over-issue slightly under concurrent settlement of the last few redemptions;
  that was accepted over building a reservation + expiry sweeper. Note it in the admin UI copy.
