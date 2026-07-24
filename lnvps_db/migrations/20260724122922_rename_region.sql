-- `vm_host_region` holds only {id, name, enabled, company_id} — a neutral
-- location + billing anchor with no VM-specific columns. Rename it to `region`
-- so non-VM resources (e.g. app deployments) can share the same location concept
-- without depending on VM infrastructure. Foreign keys and `region_id` columns
-- on referencing tables are preserved by RENAME TABLE.
RENAME TABLE vm_host_region TO region;
