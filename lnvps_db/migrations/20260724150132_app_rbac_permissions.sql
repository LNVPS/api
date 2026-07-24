-- RBAC permissions for managed-app catalog + cluster administration.
--
-- Adds AdminResource::App = 26. Managing the app catalog (create/update/delete
-- predefined apps) and app clusters is admin-only, so grant the full permission
-- set to the default super_admin role, following the per-feature grant
-- convention.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 26, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 26, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 26, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 26, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
