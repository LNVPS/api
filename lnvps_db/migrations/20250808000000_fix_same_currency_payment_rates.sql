-- Fix payment rates where payment currency matches company base currency
-- These should have rate = 1.0, not 0.01 or other incorrect values

-- Update EUR payments for companies with EUR base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'EUR' 
  AND c.base_currency = 'EUR'
  AND vp.rate != 1.0;

-- Update USD payments for companies with USD base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'USD' 
  AND c.base_currency = 'USD'
  AND vp.rate != 1.0;

-- Update GBP payments for companies with GBP base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'GBP' 
  AND c.base_currency = 'GBP'
  AND vp.rate != 1.0;

-- Update CAD payments for companies with CAD base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'CAD' 
  AND c.base_currency = 'CAD'
  AND vp.rate != 1.0;

-- Update CHF payments for companies with CHF base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'CHF' 
  AND c.base_currency = 'CHF'
  AND vp.rate != 1.0;

-- Update AUD payments for companies with AUD base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'AUD' 
  AND c.base_currency = 'AUD'
  AND vp.rate != 1.0;

-- Update JPY payments for companies with JPY base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'JPY' 
  AND c.base_currency = 'JPY'
  AND vp.rate != 1.0;

-- Update BTC payments for companies with BTC base currency
UPDATE vm_payment vp
JOIN vm v ON vp.vm_id = v.id
JOIN vm_host vh ON v.host_id = vh.id
JOIN vm_host_region vhr ON vh.region_id = vhr.id
JOIN company c ON vhr.company_id = c.id
SET vp.rate = 1.0
WHERE vp.currency = 'BTC' 
  AND c.base_currency = 'BTC'
  AND vp.rate != 1.0;