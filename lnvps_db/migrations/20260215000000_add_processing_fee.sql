-- Add processing_fee column to vm_payment table
ALTER TABLE vm_payment ADD COLUMN processing_fee BIGINT UNSIGNED NOT NULL DEFAULT 0;

-- Add processing_fee column to subscription_payment table
ALTER TABLE subscription_payment ADD COLUMN processing_fee BIGINT UNSIGNED NOT NULL DEFAULT 0;
