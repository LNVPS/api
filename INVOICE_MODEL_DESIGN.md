# Subscription Invoicing Redesign

Status: **Draft / for review**
Scope: move subscription billing from opaque, one-shot-setup lump-sum payments to
itemized, JIT-reconciled **invoices**.

## 1. Why

Today a `SubscriptionPayment` is already invoice-_like_ (amount, currency, created,
expires, is_paid, paid_at, tax, processing_fee, time_value, metadata, method, type —
`lnvps_db/src/model.rs:1617`), but it has two structural problems:

1. **It is opaque.** `renew_subscription` (`lnvps_api/src/subscription/mod.rs:245`)
   iterates the line items and collapses everything into a single `amount`. There is
   no per-line breakdown, so we cannot show a customer _what_ they paid for, and we
   cannot reconcile partial / mid-cycle changes.

2. **Setup fees are a subscription-wide one-shot.** Setup is billed only while
   `subscription.is_setup == false`, i.e. on the very first (Purchase) payment
   (`mod.rs:303-307`, `mod.rs:321-323`). Any line item **added after** that first
   payment — an upgrade line, an extra IP range — never bills its `setup_amount`.
   There is no way to charge it.

Meanwhile upgrades already work the "right" way: a separate `Upgrade` payment charges
the **prorated difference** for the remaining cycle, does not extend expiry, and the
line item's `amount` becomes the new full rate at next renewal (`pricing.rs:709`,
`mod.rs` upgrade path, `provisioner/vm.rs:540`). We want to generalise that pattern to
all line items and make it itemized.

## 2. Goals

1. Invoices are issued on the billing cycle and **itemize** every charge.
2. Mid-cycle subscription changes are accounted **JIT at invoice generation**, not via
   a global flag.
3. Support **on-demand invoices** for additional items (upgrades, added IPs) that align
   to the existing cycle.
4. Produce a clean read-model for **customer-facing invoices**.
5. Close the "setup fee after `is_setup`" hole.

Non-goals (first pass): PDF/HTML invoice rendering; multi-currency per line; dropping
`is_setup` (deprecate, don't delete yet).

## 3. Design

### 3.1 Invoice = `SubscriptionPayment` (header) + new `subscription_payment_line` (lines)

Keep `SubscriptionPayment` as the **invoice header**. Its converted totals
(`amount`, `tax`, `processing_fee`, `rate`, `time_value`, currency, payment method,
`external_data`/`external_id`) stay exactly as today, so **payment providers and the
settlement path are untouched**.

Add a child table that is the itemized breakdown, in the **subscription's base
currency** (pre-conversion, pre-tax):

```sql
CREATE TABLE subscription_payment_line (
    id           BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    payment_id   BINARY(32)      NOT NULL,   -- FK subscription_payment.id
    line_item_id BIGINT UNSIGNED NULL,       -- FK subscription_line_item.id
    kind         SMALLINT UNSIGNED NOT NULL, -- 0 Recurring, 1 Setup, 2 Proration, 3 Discount
    description  VARCHAR(255)    NOT NULL,    -- snapshot for the invoice
    period_start DATETIME        NULL,        -- span this line covers (null for Setup)
    period_end   DATETIME        NULL,
    amount       BIGINT UNSIGNED NOT NULL,    -- subscription currency, pre-tax
    FOREIGN KEY (payment_id)   REFERENCES subscription_payment(id)   ON DELETE CASCADE,
    FOREIGN KEY (line_item_id) REFERENCES subscription_line_item(id) ON DELETE SET NULL
);
```

Header invariant: `header.amount` (converted) == convert(`Σ lines.amount`) + `tax`
(+ `processing_fee` per method, as today). Tax and processing fee remain header-level —
they are computed on the converted total and don't need per-line splitting yet.

`kind`:
- **Recurring** — one full billing period for a line item.
- **Setup** — a line item's one-time `setup_amount`, billed on the first invoice that
  includes that line item (see 3.2).
- **Proration** — partial-period charge for a mid-cycle add/upgrade (see 3.4). For
  upgrades this is the rate _difference_, matching today.
- **Discount** — negative/credit line (e.g. prorated unused time on a downgrade).

### 3.2 Setup billing derived from invoice history (retire the one-shot)

Replace `if !subscription.is_setup { add setup }` with a per-line-item check:

> A line item bills its `setup_amount` on the first invoice that includes it — i.e.
> when **no paid `Setup` line exists for that `line_item_id`** yet.

This is a single query against `subscription_payment_line` joined to paid payments. It
naturally bills setup for line items added long after the subscription's first payment,
which is impossible today. `subscription.is_setup` is kept for backward compatibility
and as a fast "has this subscription ever been paid" flag, but no longer gates fees.

### 3.3 Cycle invoice (renewal)

At the billing boundary, for the subscription's **current** active line items:
- For each line item: add a **Recurring** line for the next full period
  `[cycle_start, cycle_end]`.
- For each line item with an unbilled setup: add a **Setup** line.
- Convert `Σ lines` once to the payment currency, compute tax + processing fee on the
  converted total (reusing the existing `get_amount_and_rate` / `get_tax_for_user` /
  `calculate_processing_fee` helpers), build the header. VM lines keep using
  `get_vm_cost_for_intervals` for their converted amount + `time_value`; the itemized
  line records the pre-conversion base.

This is behaviour-preserving relative to today's renewal **except** that setup is now
history-derived and the payment is itemized.

### 3.4 On-demand invoice (mid-cycle add / upgrade)

When a line item is added or upgraded between cycles, issue an invoice immediately:
- **Setup** line if applicable.
- **Proration** line for `[now, current_cycle_end]` at the (new) rate. For an upgrade,
  the amount is the **difference** between new and old rate for the remaining time —
  exactly `calculate_vm_upgrade_cost` today (`pricing.rs:709`).
- `time_value = 0` (does not extend expiry).
- The next cycle invoice then bills the line item at full rate with everything else.

Upgrades route through this path and become itemized Proration lines instead of an
opaque `Upgrade` payment. The existing `SubscriptionPaymentType::Upgrade` is retained
on the header for compatibility.

### 3.5 Settlement (unchanged)

`subscription_payment_paid` (`lnvps_db/src/mysql.rs:2030`) remains the single
settlement transaction. Lines are children of the header, so they become "paid" with
it — no extra write needed beyond the insert at generation. The per-line-item handlers
(`on_payment`, `VmLineItemHandler` / `IpRangeLineItemHandler`) are untouched.

### 3.6 Customer-facing invoice

With header + lines + user/company already in the DB, a formal invoice (HTML/PDF) is a
pure read-model: itemized lines, subtotal, tax, processing fee, total, currency, paid
status. Deferred, but unblocked by this work.

## 4. Migration / compatibility

- New `subscription_payment_line` table is **additive**; no column changes to existing
  tables in phase 1.
- Historical payments stay unitemized (or optional best-effort backfill: synthesize one
  Recurring line per current line item — lossy, only for display).
- `is_setup` retained; deprecate after the generator switches to history-derived setup.
  A later migration may drop it.

## 5. Phasing

1. **Schema + model + DB methods** for `subscription_payment_line`
   (`insert_subscription_payment_line`, `list_subscription_payment_lines(payment_id)`,
   and a "has paid setup for line_item" check). No behaviour change.
2. **Itemize the cycle generator** — refactor `renew_subscription` to build lines, with
   `header.amount == convert(Σ lines) + tax`. Behaviour-preserving (setup still
   one-shot for this step to isolate risk).
3. **History-derived setup** — switch setup logic to the line-history check; fixes the
   hole. Add a regression test: add a line item after first payment → next invoice bills
   its setup.
4. **On-demand invoice path** — generalise; route upgrades through it as Proration lines.
5. **Expose lines on the API** (public + admin) + docs (`API_DOCUMENTATION.md`,
   `ADMIN_API_ENDPOINTS.md`, `API_CHANGELOG.md`).
6. *(Later)* customer invoice rendering; *(later)* drop `is_setup`.

Each phase is independently shippable and testable.

## 6. Proration policy for mid-cycle additions — DECIDED: **A (prorate now)**

A mid-cycle add/upgrade is invoiced immediately (on-demand) for the prorated remainder
of the current cycle; the cycle stays aligned so the next cycle bills every line together
at full rate, and the add does **not** extend expiry. This matches today's upgrade
behaviour and is the basis for §3.4.

Alternatives considered and rejected:
- **B — Next cycle only.** No immediate charge; the new line first appears on the next
  cycle invoice at a full period. Simpler (no on-demand path for adds) but gives the
  remainder of the current cycle free and diverges from today's upgrades.
- **C — Charge full now, own cycle per line.** Each line bills a full period from its add
  date with its own expiry. Most flexible, much more complex (per-line expiries).
