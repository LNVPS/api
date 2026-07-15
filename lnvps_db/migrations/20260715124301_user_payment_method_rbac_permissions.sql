-- RBAC permissions for user payment method management
--
-- Adds the UserPaymentMethod admin resource (AdminResource::UserPaymentMethod = 23)
-- which the admin endpoints in `lnvps_api_admin/src/admin/user_payment_methods.rs`
-- gate on (list / get / update / delete of users' saved payment methods).
-- This grants the full set so super_admin can manage them.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
-- Note: there is no admin Create endpoint (methods are added by users), but we
-- grant the full set for consistency with the other resources.

INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 23, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 23, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 23, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 23, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
