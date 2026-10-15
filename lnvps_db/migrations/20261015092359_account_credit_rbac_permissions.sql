-- RBAC permissions for account credit administration.
--
-- Adds AdminResource::AccountCredit = 34 to the default super_admin role,
-- following the per-feature grant convention. Without this the endpoints are
-- unreachable by anybody: there is no super-admin bypass in the permission
-- check, so a resource with no grants means the feature is simply unusable.
--
-- Its own resource rather than part of `Payments` because adjusting a balance
-- is authority to create or destroy money a customer can spend against
-- invoices.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 34, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 34, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 34, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 34, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
