-- Refund accounting (issue #193).
--
-- `subscription_payment.payment_type` gains value 3 = Refund. The amount and
-- tax columns are BIGINT UNSIGNED and stay that way: a refund stores the
-- magnitude returned and the sign lives in the type, so every existing row and
-- every existing INSERT keeps working. Aggregations subtract Refund rows.
--
-- A refund is always recorded against the payment it reverses, so its frozen
-- `rate`, `tax` and place-of-supply are the ones from that sale rather than
-- today's rates. NULL on every non-refund row.
ALTER TABLE subscription_payment
    ADD COLUMN refunded_payment_id BINARY(32) NULL AFTER tax_breakdown,
    ADD CONSTRAINT fk_subscription_payment_refunded
        FOREIGN KEY (refunded_payment_id) REFERENCES subscription_payment (id);

CREATE INDEX idx_subscription_payment_refunded ON subscription_payment (refunded_payment_id);
