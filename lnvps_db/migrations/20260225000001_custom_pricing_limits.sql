-- Add resource limit columns to vm_custom_pricing
-- These are the default limits copied into vm_custom_template when a new VM is provisioned.
-- NULL = uncapped (no limit applied).

ALTER TABLE vm_custom_pricing ADD COLUMN disk_iops_read  int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_pricing ADD COLUMN disk_iops_write int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_pricing ADD COLUMN disk_mbps_read  int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_pricing ADD COLUMN disk_mbps_write int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_pricing ADD COLUMN network_mbps    int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_pricing ADD COLUMN cpu_limit       float        NULL DEFAULT NULL;
