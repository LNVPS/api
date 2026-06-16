-- Re-add interval columns to subscription (were dropped in 20260130000003)
-- Needed so VMs can use subscriptions with configurable billing intervals.
-- Add is_setup flag: true once the first (purchase) payment has been confirmed.
-- Replaces scanning payment history to determine whether setup fees apply.
ALTER TABLE subscription
    ADD COLUMN interval_amount INTEGER UNSIGNED NOT NULL DEFAULT 1 AFTER currency,
    ADD COLUMN interval_type SMALLINT UNSIGNED NOT NULL DEFAULT 1 AFTER interval_amount,
    ADD COLUMN is_setup BIT(1) NOT NULL DEFAULT 0 AFTER is_active;
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

-- Relax the legacy vm.expires / vm.auto_renewal_enabled columns so that new VM inserts
-- (which no longer set these columns) succeed, while the existing data is preserved for
-- the migrate_vm_subscriptions backfill. These columns are dropped only at finalization,
-- AFTER the data migration has run and been verified in production (see
-- docs/agents/migrations.md). Dropping them before the backfill runs would discard every
-- VM's billing expiry and auto-renewal preference.
ALTER TABLE vm
    MODIFY COLUMN expires TIMESTAMP NULL DEFAULT NULL,
    MODIFY COLUMN auto_renewal_enabled BIT(1) NOT NULL DEFAULT 0;

-- Add VmRenewal(3) and VmUpgrade(4) to the subscription_type enum stored in
-- subscription_line_item.subscription_type. No DDL change needed — the column
-- is SMALLINT UNSIGNED, so the new values are valid immediately.
