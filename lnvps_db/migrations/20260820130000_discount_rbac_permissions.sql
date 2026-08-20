-- RBAC permissions for discount administration.
--
-- Adds AdminResource::Discount = 31 to the default super_admin role, following
-- the per-feature grant convention. Without this the endpoints are unreachable
-- by anybody: there is no super-admin bypass in the permission check, so a
-- resource with no grants means the feature is simply unusable.
--
-- Its own resource rather than part of `Payments` because creating a discount
-- is authority to give money away — a pricing decision — while `Payments`
-- covers administering money that has already moved. An operator should be able
-- to grant one without the other.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 31, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 31, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 31, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 31, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
