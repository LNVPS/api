-- Re-add interval columns to subscription (were dropped in 20260130000003)
-- Needed so VMs can use subscriptions with configurable billing intervals
ALTER TABLE subscription
    ADD COLUMN interval_amount INTEGER UNSIGNED NOT NULL DEFAULT 1 AFTER currency,
    ADD COLUMN interval_type SMALLINT UNSIGNED NOT NULL DEFAULT 1 AFTER interval_amount;
-- interval_type: 0=Day, 1=Month, 2=Year (default Month)

-- Re-add time_value and add metadata to subscription_payment
-- time_value: seconds this payment adds to expiry (was dropped in 20260130000003)
-- metadata: JSON for upgrade params, etc.
ALTER TABLE subscription_payment
    ADD COLUMN time_value BIGINT UNSIGNED AFTER rate,
    ADD COLUMN metadata JSON AFTER time_value;

-- Link VMs to subscriptions (nullable during migration)
ALTER TABLE vm
    ADD COLUMN subscription_id INTEGER UNSIGNED AFTER custom_template_id,
    ADD CONSTRAINT fk_vm_subscription FOREIGN KEY (subscription_id) REFERENCES subscription (id);
CREATE INDEX idx_vm_subscription ON vm (subscription_id);
