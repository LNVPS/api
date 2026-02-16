-- Make company_id required on vm_host_region, subscription, and available_ip_space

-- First, ensure at least one company exists for default assignment
INSERT INTO company (name, email, base_currency)
SELECT 'Default Company', 'admin@example.com', 'EUR'
WHERE NOT EXISTS (SELECT 1 FROM company LIMIT 1);

-- Get the first company id for default assignment
SET @default_company_id = (SELECT MIN(id) FROM company);

-- Update regions with NULL company_id to use the default company
UPDATE vm_host_region SET company_id = @default_company_id WHERE company_id IS NULL;

-- Now make the column NOT NULL
ALTER TABLE vm_host_region MODIFY COLUMN company_id integer unsigned NOT NULL;

-- Add company_id to subscription table
ALTER TABLE subscription ADD COLUMN company_id integer unsigned NOT NULL AFTER user_id;

-- Update any existing subscriptions to use the default company
UPDATE subscription SET company_id = @default_company_id;

-- Add foreign key constraint for subscription
ALTER TABLE subscription ADD CONSTRAINT fk_subscription_company FOREIGN KEY (company_id) REFERENCES company (id);

-- Add company_id to available_ip_space table
ALTER TABLE available_ip_space ADD COLUMN company_id integer unsigned NOT NULL AFTER id;

-- Update any existing IP spaces to use the default company
UPDATE available_ip_space SET company_id = @default_company_id;

-- Add foreign key constraint for available_ip_space
ALTER TABLE available_ip_space ADD CONSTRAINT fk_available_ip_space_company FOREIGN KEY (company_id) REFERENCES company (id);

-- Add index for company lookups on available_ip_space
CREATE INDEX idx_available_ip_space_company ON available_ip_space(company_id);
