-- Add resource limit columns to vm_template and vm_custom_template
-- These limits are applied at VM create/configure time for fair-use and SLA enforcement.
-- NULL = uncapped (preserves existing behaviour for all current templates).

-- vm_template limits
ALTER TABLE vm_template ADD COLUMN disk_iops_read  int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_template ADD COLUMN disk_iops_write int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_template ADD COLUMN disk_mbps_read  int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_template ADD COLUMN disk_mbps_write int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_template ADD COLUMN network_mbps    int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_template ADD COLUMN cpu_limit       float        NULL DEFAULT NULL;

-- vm_custom_template limits (per-VM custom plan limits)
ALTER TABLE vm_custom_template ADD COLUMN disk_iops_read  int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_template ADD COLUMN disk_iops_write int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_template ADD COLUMN disk_mbps_read  int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_template ADD COLUMN disk_mbps_write int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_template ADD COLUMN network_mbps    int unsigned NULL DEFAULT NULL;
ALTER TABLE vm_custom_template ADD COLUMN cpu_limit       float        NULL DEFAULT NULL;
