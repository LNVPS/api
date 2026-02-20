-- Add paid_at timestamp to vm_payment table to track when payments were completed
ALTER TABLE vm_payment ADD COLUMN paid_at TIMESTAMP NULL DEFAULT NULL;

-- Backfill existing paid payments with their created timestamp as a best-effort approximation
UPDATE vm_payment SET paid_at = created WHERE is_paid = 1;

-- Add paid_at timestamp to subscription_payment table to track when payments were completed
ALTER TABLE subscription_payment ADD COLUMN paid_at TIMESTAMP NULL DEFAULT NULL;

-- Backfill existing paid subscription payments with their created timestamp as a best-effort approximation
UPDATE subscription_payment SET paid_at = created WHERE is_paid = 1;
