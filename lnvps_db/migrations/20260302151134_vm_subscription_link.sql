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

-- Link VMs to their subscription line item (mirrors ip_range_subscription pattern).
-- A VM belongs to exactly one line item, and the subscription is found via the line item.
-- Run migrate_vm_subscriptions binary to backfill existing rows before applying NOT NULL.
ALTER TABLE vm
    ADD COLUMN subscription_line_item_id INTEGER UNSIGNED AFTER custom_template_id,
    ADD CONSTRAINT fk_vm_subscription_line_item
        FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id);
CREATE INDEX idx_vm_subscription_line_item ON vm (subscription_line_item_id);

-- Add VmRenewal(3) and VmUpgrade(4) to the subscription_type enum stored in
-- subscription_line_item.subscription_type. No DDL change needed — the column
-- is SMALLINT UNSIGNED, so the new values are valid immediately.
