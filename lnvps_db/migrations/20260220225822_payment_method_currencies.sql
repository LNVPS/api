-- Add supported currencies column to payment_method_config
-- Stores comma-separated currency codes (e.g., "EUR,USD" or "BTC")
-- Empty string means use default currencies based on payment method type

ALTER TABLE payment_method_config
ADD COLUMN supported_currencies VARCHAR(100) NOT NULL DEFAULT '';
