-- Add disabled column to vm table
-- Allows admins to disable a VM without deleting it
ALTER TABLE vm ADD COLUMN disabled BIT(1) NOT NULL DEFAULT 0;

-- Add mtu column to vm_host table (after vlan_id)
-- Optional MTU setting for network configuration on this host
ALTER TABLE vm_host ADD COLUMN mtu SMALLINT UNSIGNED NULL AFTER vlan_id;
