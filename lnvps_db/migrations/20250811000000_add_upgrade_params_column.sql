-- Add upgrade_params column to store upgrade-specific parameters
-- This separates upgrade parameters from payment provider data in external_data
ALTER TABLE vm_payment 
ADD COLUMN upgrade_params TEXT;

-- Add comment to clarify the column purpose
ALTER TABLE vm_payment 
MODIFY COLUMN upgrade_params TEXT COMMENT 'JSON-encoded upgrade parameters (CPU, memory, disk) for upgrade payments';