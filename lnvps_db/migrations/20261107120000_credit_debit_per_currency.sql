ALTER TABLE account_credit_debit
    DROP INDEX uk_account_credit_debit_payment,
    ADD UNIQUE KEY uk_account_credit_debit_payment_currency (subscription_payment_id, currency);
