-- RBAC permissions for referral program management.
--
-- Adds AdminResource::Referral = 25. Referral administration (viewing referrers,
-- setting per-referrer commission overrides, creating/reconciling payouts) is
-- admin-only, so grant the full permission set to the default super_admin role,
-- following the established per-feature grant convention.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 25, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 25, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 25, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 25, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
