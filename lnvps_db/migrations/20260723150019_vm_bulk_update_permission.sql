-- RBAC permission for fleet-wide VM mutations (AdminAction::BulkUpdate = 4).
--
-- Backs POST /api/admin/v1/vms/extend-all (bulk-extend all non-expired VMs).
-- This is a powerful, fleet-wide action, so it is granted only to the default
-- super_admin role. Operators can additionally grant
-- `virtual_machines::bulk_update` to custom roles via the roles API.
--
-- AdminResource::VirtualMachines = 1, AdminAction::BulkUpdate = 4
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 1, 4, NOW() FROM admin_roles WHERE name = 'super_admin';
