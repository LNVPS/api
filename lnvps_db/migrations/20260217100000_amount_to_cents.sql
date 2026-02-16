-- Convert all monetary amounts from FLOAT (human-readable) to BIGINT UNSIGNED (smallest units)
-- This is a BREAKING CHANGE - all amounts are now stored as cents (fiat) or millisats (BTC)
-- Example: 1.32 EUR becomes 132 cents

-- Convert vm_cost_plan.amount from float to bigint unsigned
-- First, update existing values by multiplying by 100 (assuming 2 decimal places for fiat)
-- Then change the column type
UPDATE vm_cost_plan SET amount = ROUND(amount * 100);
ALTER TABLE vm_cost_plan MODIFY COLUMN amount BIGINT UNSIGNED NOT NULL;

-- Convert vm_custom_pricing costs from float to bigint unsigned
UPDATE vm_custom_pricing SET 
    cpu_cost = ROUND(cpu_cost * 100),
    memory_cost = ROUND(memory_cost * 100),
    ip4_cost = ROUND(ip4_cost * 100),
    ip6_cost = ROUND(ip6_cost * 100);
ALTER TABLE vm_custom_pricing MODIFY COLUMN cpu_cost BIGINT UNSIGNED NOT NULL;
ALTER TABLE vm_custom_pricing MODIFY COLUMN memory_cost BIGINT UNSIGNED NOT NULL;
ALTER TABLE vm_custom_pricing MODIFY COLUMN ip4_cost BIGINT UNSIGNED NOT NULL;
ALTER TABLE vm_custom_pricing MODIFY COLUMN ip6_cost BIGINT UNSIGNED NOT NULL;

-- Convert vm_custom_pricing_disk.cost from float to bigint unsigned
UPDATE vm_custom_pricing_disk SET cost = ROUND(cost * 100);
ALTER TABLE vm_custom_pricing_disk MODIFY COLUMN cost BIGINT UNSIGNED NOT NULL;
