-- Add min/max limits to custom pricing to replace dependency on regular template limits
-- This allows custom templates to have their own capacity limits based on host capacity calculations

-- Add min/max CPU limits to custom pricing
ALTER TABLE vm_custom_pricing 
ADD COLUMN min_cpu tinyint unsigned NOT NULL DEFAULT 1;

ALTER TABLE vm_custom_pricing 
ADD COLUMN max_cpu tinyint unsigned NOT NULL DEFAULT 32;

-- Add min/max memory limits (in bytes) to custom pricing
ALTER TABLE vm_custom_pricing 
ADD COLUMN min_memory bigint unsigned NOT NULL DEFAULT 1073741824; -- 1GB default

ALTER TABLE vm_custom_pricing 
ADD COLUMN max_memory bigint unsigned NOT NULL DEFAULT 68719476736; -- 64GB default

-- Add min/max disk limits (in bytes) per disk type/interface to custom pricing disk
ALTER TABLE vm_custom_pricing_disk 
ADD COLUMN min_disk_size bigint unsigned NOT NULL DEFAULT 5368709120; -- 5GB default

ALTER TABLE vm_custom_pricing_disk 
ADD COLUMN max_disk_size bigint unsigned NOT NULL DEFAULT 2199023255552; -- 2TB default

-- Update existing custom pricing with reasonable defaults based on typical host capacity
-- These will be properly calculated from host capacity in the application code
UPDATE vm_custom_pricing SET
  min_cpu = 1,
  max_cpu = 32,  -- Will be calculated from host capacity
  min_memory = 1073741824,  -- 1GB
  max_memory = 68719476736  -- 64GB, will be calculated from host capacity
WHERE id > 0;

-- Update existing custom pricing disks with reasonable defaults
UPDATE vm_custom_pricing_disk SET
  min_disk_size = 5368709120,  -- 5GB minimum
  max_disk_size = CASE 
    WHEN kind = 1 THEN 2199023255552  -- 2TB for SSD
    ELSE 10995116277760  -- 10TB for HDD
  END
WHERE id > 0;