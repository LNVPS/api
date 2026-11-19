ALTER TABLE account_credit_topup
    ADD COLUMN payment_method SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER currency,
    ADD COLUMN external_id    VARCHAR(255)      NULL DEFAULT NULL AFTER external_data,
    ADD KEY ix_account_credit_topup_method (payment_method, is_paid),
    ADD UNIQUE KEY uk_account_credit_topup_external_id (external_id);
