-- Discount engine, phase 1: discount codes.
--
-- A discount's *eligibility* and its *effect* are both a single CEL expression
-- (`rule`) that returns a decision map, e.g.
--   {'percent': 10}
--   order.amount >= 10000 ? {'amount': 500, 'currency': 'EUR'} : {}
-- The expression is evaluated by `lnvps_api_common::discount` and its result is
-- clamped in Rust (percent 0..=100, amount >= 0 and <= order total), so a badly
-- written rule cannot over-discount an order.
--
-- Only the *integrity guards* are columns: the validity window and the usage
-- limits. Those need atomic enforcement at redemption time and cannot be
-- expressed inside a side-effect-free expression, because counting redemptions
-- is a read of state the expression must not be given. Everything else —
-- minimum spend, country, product, term length, tiering — lives in `rule`,
-- which is why no new column is needed as new discount shapes appear.
--
-- See `work/discount-engine.md` and issue #57.

CREATE TABLE discount
(
    id            INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    -- Discounts are per-company, like every other pricing object: a code
    -- created for one company must not silently apply to another company's
    -- orders.
    company_id    INTEGER UNSIGNED NOT NULL,
    -- The code a customer types. NULL is reserved for phase 2 *automatic*
    -- discounts, which are evaluated on every order with no code entered.
    -- Unique across companies rather than per company: a customer types a code
    -- without choosing a company, so a code shared between two companies would
    -- be ambiguous at exactly the moment it is used. MySQL treats NULLs as
    -- distinct in a unique key, so any number of automatic discounts coexist.
    code          VARCHAR(64)      NULL     DEFAULT NULL,
    -- Admin-facing label, e.g. "Black Friday 2026". Not shown to customers.
    name          VARCHAR(100)     NOT NULL,
    -- The CEL expression. TEXT rather than VARCHAR because a templated rule
    -- from the admin condition builder can be long; the API caps it at
    -- `lnvps_api_common::discount::MAX_RULE_LEN` (4096 bytes).
    rule          TEXT             NOT NULL,
    -- Validity window. NULL `valid_to` means "no end date".
    valid_from    DATETIME         NOT NULL DEFAULT NOW(),
    valid_to      DATETIME         NULL     DEFAULT NULL,
    -- Total redemptions allowed across all users. NULL = unlimited.
    usage_limit   INTEGER UNSIGNED NULL     DEFAULT NULL,
    -- Redemptions so far. Incremented atomically against `usage_limit` when a
    -- discounted payment settles, never when an invoice is merely created —
    -- an unpaid invoice must not consume stock.
    used_count    INTEGER UNSIGNED NOT NULL DEFAULT 0,
    -- Redemptions allowed per user. NULL = unlimited. Enforced by counting
    -- rows in `discount_redemption`, not by a counter, because the count is
    -- per (discount, user) and must survive user deletion of nothing.
    per_user_limit INTEGER UNSIGNED NULL    DEFAULT NULL,
    -- Kill switch: an inactive discount is never a candidate, whatever its
    -- window and limits say.
    active        BOOLEAN          NOT NULL DEFAULT TRUE,
    created       DATETIME         NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE KEY uk_discount_code (code),
    -- Candidate lookup for phase 2 automatic discounts.
    KEY ix_discount_active (company_id, active),
    CONSTRAINT fk_discount_company FOREIGN KEY (company_id) REFERENCES company (id)
);

-- One row per discount applied to a payment.
--
-- This carries three jobs, which is why it is one table and not three:
--
--  1. **Provenance.** It is the record of which discount reduced which payment
--     and by how much. That fact deliberately lives here rather than as columns
--     on `subscription_payment`: the payment's `amount` is already net of the
--     discount, so tax, refunds and referral commission are correct without it,
--     and one 1:1 row keeps `amount_off` recorded exactly once.
--  2. **Limit enforcement.** Per-user limits count the *settled* rows here.
--  3. **Reporting.** What a campaign cost is the sum of settled `amount_off`,
--     not a percentage inferred from a rule that may since have been edited.
--
-- A row is written unsettled when the discounted invoice is created, and
-- settled when the payment is actually paid. Only settled rows consume limits,
-- so an invoice that is never paid does not burn a campaign's stock.
CREATE TABLE discount_redemption
(
    id                      INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    discount_id             INTEGER UNSIGNED NOT NULL,
    user_id                 INTEGER UNSIGNED NOT NULL,
    -- The payment this discount was applied to. `subscription_payment.id` is a
    -- BINARY(32) payment hash, matching the referral/payment tables. No FK: the
    -- row is written in the same breath as the payment, and a settlement path
    -- must never fail because of ordering between the two writes.
    subscription_payment_id BINARY(32)       NOT NULL,
    -- What the customer saved, in minor units of `currency`. Recorded rather
    -- than recomputed: the rule may be edited or deactivated later, and
    -- historic reporting must still show what was given away.
    amount_off              BIGINT UNSIGNED  NOT NULL,
    currency                VARCHAR(4)       NOT NULL,
    -- False until the payment settles. Unsettled rows count for nothing.
    settled                 BOOLEAN          NOT NULL DEFAULT FALSE,
    created                 DATETIME         NOT NULL DEFAULT NOW(),
    settled_at              DATETIME         NULL     DEFAULT NULL,
    PRIMARY KEY (id),
    -- One discount per payment. This is the no-stacking rule expressed where it
    -- cannot be bypassed, and it also makes settlement idempotent: a replayed
    -- webhook or a listener resuming from its cursor cannot add a second row.
    UNIQUE KEY uk_discount_redemption_payment (subscription_payment_id),
    -- Per-user limit checks, which only look at settled rows.
    KEY ix_discount_redemption_user (discount_id, user_id, settled),
    CONSTRAINT fk_discount_redemption_discount FOREIGN KEY (discount_id) REFERENCES discount (id),
    CONSTRAINT fk_discount_redemption_user FOREIGN KEY (user_id) REFERENCES users (id)
);
