-- Remove interval columns from subscription table
-- All subscriptions are monthly recurring

ALTER TABLE subscription 
    DROP COLUMN interval_amount,
    DROP COLUMN interval_type;
ALTER TABLE subscription_payment
    DROP COLUMN time_value;

