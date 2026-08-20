# Discounts

Load this when working on discount codes, discount rules, or the pricing engine's discount step.
See `work/discount-engine.md` for the increment history and the decisions behind the design.

## Shape of the feature

A discount's **eligibility and its effect are one CEL expression** (`discount.rule`) returning a
decision map. Only the *integrity guards* are columns — validity window, total usage limit, per-user
limit — because they need atomic enforcement at redemption time and cannot be counted inside a
side-effect-free expression. Everything else (minimum spend, country, product, term length,
tiering) lives in the rule, so a new campaign shape needs no migration.

Phase 1 is **codes only**. `discount.code = NULL` is reserved for phase 2 automatic discounts;
nothing evaluates such a row today, so the admin API rejects creating one.

| Where | What |
|---|---|
| `lnvps_api_common/src/discount/context.rs` | The read-only context a rule may read |
| `lnvps_api_common/src/discount/decision.rs` | `DiscountDecision` + the Rust-side clamping |
| `lnvps_api_common/src/discount/engine.rs` | Candidate resolution, guards, best-value selection, allocation across order lines |
| `lnvps_api_common/src/discount/mod.rs` | `validate_rule`, `evaluate_rule`, `evaluate_rule_or_none` |
| `lnvps_api_admin/src/admin/discounts.rs` | Admin CRUD + `POST /api/admin/v1/discounts/preview` |
| `lnvps_api/src/subscription/mod.rs` | Applying a code to an order; settling the redemption |

## Writing a rule

**Map keys must be quoted.** In CEL a bare identifier in a map literal is a *variable reference*,
so `{percent: 10}` fails with `Undeclared reference to 'percent'`. Always `{'percent': 10}`.

```
{'percent': 10}                                                     flat 10% off
order.amount >= 5000 ? {'percent': 10} : {}                         10% over 50.00
order.intervals >= 12 ? {'percent': 15}
  : order.intervals >= 6 ? {'percent': 10} : {}                     term-length tiers
order.amount >= 10000 ? {'amount': 500, 'currency': 'EUR'} : {}     5.00 EUR off over 100.00
user.country == 'IRL' && history.orders == 0 ? {'percent': 20} : {} first order, one country
order.items.exists(i, i.type == 'vm' && i.template_id == 3)
  ? {'percent': 10} : {}                                            one plan
order.items.all(i, i.type == 'vm' && i.cpu >= 8) ? {'percent': 5} : {}   big machines only
order.items.exists(i, i.type == 'vm' && i.template_id == null)
  ? {'percent': 10} : {}                                            custom builds only
order.items.exists(i, i.type == 'ip_range') ? {'percent': 15} : {}  a product type
```

CEL's `exists`, `all`, `exists_one`, `map` and `filter` macros are available, as is `size()`.

### Context

All money is minor units (cents, millisats) as integers. There is no `f64` anywhere in the path.

| Variable | Fields |
|---|---|
| `order` | `amount`, `currency`, `intervals`, `interval_type` (`day`/`month`/`year`), `is_new`, `items` |
| `user` | `id`, `country` (ISO alpha-3, may be null) |
| `history` | `orders` — settled payment count |
| `now` | unix timestamp in seconds |

### `order.items`

Each line of the order, carrying the properties of the product it bills for, so a rule can target
the thing being bought instead of a single scalar the engine picked on its behalf. Common fields:
`line_item_id`, `name`, `type`, `amount`, `setup_amount`.

| `type` | Fields |
|---|---|
| `vm` | `vm_id`, `template_id` (null for a custom build — that is how a rule tells the two apart), `region_id`, `cpu`, `memory` (bytes), `disk_size` (bytes), `disk_type` (`ssd`/`hdd`), `ip4_count`, `ip6_count` |
| `app` | `deployment_id`, `app_id`, `cluster_id`, `resource_multiplier` |
| `ip_range` | `subscription_id`, `cidr` |
| `asn_sponsoring` | `subscription_id`, `asn`, `registry` |
| `dns_hosting` | — |
| `marketplace_node_fee` | `node_id` |

**Type is certain, detail is best-effort.** The line item itself says what it bills for, so `type`
is always right; the detail comes from the product row behind it, which may not exist yet (an IP
range or an ASN is allocated only when the first payment settles). Unknown detail is **null**, and
the line is never dropped — dropping it would make `i.type == 'ip_range'` false on the very order
buying one. Comparing against a null detail fails the rule, which applies no discount, so "unknown"
never costs money.

**Per-item money is a list price.** `amount` is the line's recurring price for **one interval** and
`setup_amount` its one-off fee, both converted into the payment currency when the context is built,
so every figure a rule sees is in one currency. For non-VPS lines this is exactly what is charged —
the renewal sums `amount * intervals`. For a VPS line it is the base price recorded at order (and
rewritten on upgrade), while the actual charge is recomputed at payment time from the cost plan or
custom pricing including the machine's IP assignments, and a later cost-plan change does not rewrite
it. Use `i.amount` for "this line is worth about X"; use `order.amount` — the actual net being
charged — for a minimum-spend threshold.

Lifetime spend is deliberately **not** exposed: a customer's payments span currencies, so any
single number is either wrong or costs a full payment-history conversion at every quote.

Adding a field is a deliberate act — this is the security boundary. Never serialize a DB row into
the context wholesale.

### Decision

`{'percent': int}`, `{'amount': int, 'currency': str}`, or both. `{}`, `null` and `false` all mean
"does not apply". **Any other return type is an error**, applying no discount: treating a bare `10`
as "10 percent" would let a typo change what customers are charged.

Clamping happens in Rust, so a rule can never over-discount: percent to `0..=100`, a fixed amount
to `>= 0`, and the total to at most the order amount. Percent rounding is floor. A fixed amount in
another currency is converted by the pricing engine (floored), which is why that conversion lives
in `engine.rs` and not in `decision.rs` — only the engine owns an exchange-rate service.

## Rules of the road

- **A discount applies to the order, not to a line item.** An order aggregates line items plus
  setup fees; discounting one `NewPaymentInfo` would miss the rest of the bill.
- **Subtract before tax and fees.** `discount_tax_lines` attributes the discount across lines
  proportionally and recomputes each line's tax as `floor(net * rate)`. A customer must never be
  taxed — or charged a provider fee — on money they do not pay.
- **Quote-time guards, settlement-time redemption.** Limits are checked when a discount is quoted
  and consumed when the payment settles (`SubscriptionHandler::apply_payment`, which every payment
  method reaches, including the admin override via `WorkJob::ApplySubscriptionPayment`). An
  abandoned invoice burns no stock. Settlement increments `used_count` unconditionally: the
  customer has already paid a discounted invoice and must be honoured, so the count records what
  really happened and can sit at or past the limit, refusing every later quote.
- **A discounted order is priced fresh.** `get_vm_cost_for_intervals_fresh` skips the pending-payment
  reuse, or a code entered after an invoice was created would hand back the full-price one.
- **One discount per payment**, enforced by `UNIQUE (subscription_payment_id)` on
  `discount_redemption`. That is the no-stacking rule in a place it cannot be bypassed, and it is
  what makes settlement idempotent under replayed webhooks.
- **Errors do not leak.** Every rejection (unknown, expired, exhausted, wrong company, rule
  declined) returns one generic message, so the endpoint cannot enumerate valid codes. But an
  unusable code *does* fail the request: the customer typed something and is owed an answer.
- **A broken rule is not a discount and not a 500.** `evaluate_rule_or_none` logs and returns
  nothing, so a bad campaign can never stop a customer paying.
- **Referral needs no special handling.** Commission is computed from the recorded payment amount,
  which is already net of the discount.
- **Amount-already-paid paths take no discount** (`get_cost_by_amount`,
  `get_subscription_cost_by_amount`): there a discount could only mean "more time for the same
  money", which is not what a code promises.
