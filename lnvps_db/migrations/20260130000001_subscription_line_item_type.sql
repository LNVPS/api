-- Add subscription_type to subscription_line_item table
-- Allows different types of services: IP ranges, ASN sponsoring, etc.

ALTER TABLE subscription_line_item
ADD COLUMN subscription_type SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER subscription_id;

-- 0=IpRange, 1=AsnSponsoring, 2=DnsHosting, etc.

CREATE INDEX idx_line_item_type ON subscription_line_item (subscription_type);
