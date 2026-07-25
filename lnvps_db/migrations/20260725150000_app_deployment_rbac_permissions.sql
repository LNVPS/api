-- RBAC permissions for customer app-deployment administration.
--
-- Adds AdminResource::AppDeployment = 27, distinct from the catalog
-- AdminResource::App = 26. Reading a deployment (including its decrypted
-- config, which may hold secret values) uses action View; writing name /
-- custom_domain / config uses action Update. Grant the full set to the default
-- super_admin role, following the per-feature grant convention.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 27, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 27, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 27, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 27, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
