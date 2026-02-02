-- Remove interval columns from subscription table
-- All subscriptions are monthly recurring

ALTER TABLE subscription 
    DROP COLUMN interval_amount,
    DROP COLUMN interval_type,
    DROP COLUMN time_value;
