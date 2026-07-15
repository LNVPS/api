-- RBAC permissions for cost tracking (issue #82).
--
-- Adds AdminResource::ResourceCost = 24. Cost data is admin-only, so grant the
-- full permission set to the default super_admin role.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 24, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 24, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 24, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 24, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
