-- Account credit: a balance a customer tops up and spends against purchases,
-- renewals and upgrades, in the same flow as a NWC payment. See
-- `work/account-credit.md` and issue #145.
--
-- The balance is denominated in BTC (msat)
-- regardless of the payment currency of any given invoice. Conversion to the
-- payment currency happens at quote time via the pricing engine, matching how
-- a discount's fixed amount is converted per-order.

-- One row per user. `balance` always equals the sum of `account_credit_event.amount`
-- for the user; the row exists for O(1) reads rather than a ledger scan.
CREATE TABLE account_credit
(
    user_id   INTEGER UNSIGNED NOT NULL,
    -- Minor units (msat for BTC) of `currency`. Never negative.
    balance   BIGINT UNSIGNED  NOT NULL DEFAULT 0,
    -- ISO currency code of the balance. Stored rather than hard-coded so a
    -- future company on a different base currency does not require a schema
    -- change.
    currency  VARCHAR(4)       NOT NULL DEFAULT 'BTC',
    -- Opt-in to auto-applying the balance against quotes. When true, every
    -- quote for a purchase, renewal or upgrade subtracts min(balance, total)
    -- before tax and processing fee are finalised. When false, the balance
    -- sits there untouched until the customer tops up again.
    auto_apply BOOLEAN         NOT NULL DEFAULT FALSE,
    -- Last time the balance or `auto_apply` changed. Informational only: the
    -- ledger is the audit trail, not this column.
    updated   DATETIME         NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_account_credit_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Append-only ledger. `balance` is the sum of `amount` over a user's rows.
--   * `topup`  -- customer bought credit, or an admin topped them up (positive).
--   * `spend`  -- credit covered part or all of a `subscription_payment` (negative).
--   * `refund` -- credit returned to the customer (positive).
--   * `admin`  -- manual adjustment, either sign, with a `note`.
CREATE TABLE account_credit_event
(
    id                       INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id                  INTEGER UNSIGNED NOT NULL,
    kind                     VARCHAR(16)      NOT NULL,
    amount                   BIGINT           NOT NULL,
    currency                 VARCHAR(4)       NOT NULL,
    subscription_payment_id  BINARY(32)       NULL     DEFAULT NULL,
    note                     VARCHAR(255)     NULL     DEFAULT NULL,
    created                  DATETIME         NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    KEY ix_account_credit_event_user (user_id, created),
    CONSTRAINT fk_account_credit_event_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Credit held against an order. A row is a reservation from the moment the
-- order is priced until `expires`: unsettled rows that have not expired are
-- subtracted from the balance when quoting, so the same credit cannot be
-- promised to two orders. `subscription_payment_id` is attached once the
-- payment row exists. Settling moves the balance and writes a `spend` event.
CREATE TABLE account_credit_debit
(
    id                       INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id                  INTEGER UNSIGNED NOT NULL,
    subscription_payment_id  BINARY(32)       NULL     DEFAULT NULL,
    -- Minor units of `currency` (the balance currency) taken off the balance.
    amount                   BIGINT UNSIGNED  NOT NULL,
    currency                 VARCHAR(4)       NOT NULL,
    -- The same value in the payment's currency, as shown to the customer.
    payment_amount           BIGINT UNSIGNED  NOT NULL,
    settled                  BOOLEAN          NOT NULL DEFAULT FALSE,
    expires                  DATETIME         NOT NULL,
    created                  DATETIME         NOT NULL DEFAULT NOW(),
    settled_at               DATETIME         NULL     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_account_credit_debit_payment (subscription_payment_id),
    KEY ix_account_credit_debit_user (user_id, settled, expires),
    CONSTRAINT fk_account_credit_debit_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Top-up invoices. A top-up is not a `subscription_payment`: it does not
-- belong to a subscription, it does not extend anything, and it must never
-- appear in referral commission or the VM payment history. It lives in its
-- own table so the Lightning listener can tell the two apart.
CREATE TABLE account_credit_topup
(
    id            INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id       INTEGER UNSIGNED NOT NULL,
    -- Minor units of `currency` the customer paid.
    amount        BIGINT UNSIGNED  NOT NULL,
    currency      VARCHAR(4)       NOT NULL,
    -- BOLT11 payment hash of the top-up invoice. The Lightning listener's
    -- `mark_paid` looks up here before `subscription_payment`, so a top-up
    -- invoice can never be mistaken for a VM renewal.
    invoice_hash  BINARY(32)       NOT NULL,
    external_data TEXT             NOT NULL,
    is_paid       BOOLEAN          NOT NULL DEFAULT FALSE,
    paid_at       DATETIME         NULL     DEFAULT NULL,
    created       DATETIME         NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE KEY uk_account_credit_topup_hash (invoice_hash),
    KEY ix_account_credit_topup_user (user_id, is_paid),
    CONSTRAINT fk_account_credit_topup_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
