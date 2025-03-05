-- Add migration script here
ALTER TABLE vm_cost_plan MODIFY COLUMN amount float NOT NULL;
