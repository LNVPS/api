-- Add base currency support for companies
ALTER TABLE company ADD COLUMN base_currency VARCHAR(3) NOT NULL DEFAULT 'EUR' AFTER tax_id;