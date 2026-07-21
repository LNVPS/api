-- Add a minimum processable amount to payment method configs.
-- For providers with a flat base fee (e.g. Revolut's 20c) it makes no sense to
-- process very small payments, since the fee would be a large fraction of the
-- charge. `min_amount` is stored in the smallest unit of `min_amount_currency`
-- (cents for fiat, millisats for BTC), mirroring `processing_fee_base`.
ALTER TABLE payment_method_config
    ADD COLUMN min_amount BIGINT UNSIGNED NULL,
    ADD COLUMN min_amount_currency VARCHAR(4) NULL;
