ALTER TABLE user_payment_method
    ADD COLUMN gateway_method_id BIGINT UNSIGNED NULL DEFAULT NULL AFTER external_id,
    ADD INDEX idx_user_payment_method_gateway (gateway_method_id);
