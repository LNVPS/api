-- RBAC permissions for VPN administration.
--
-- Adds AdminResource::VpnService = 32 and VpnSubscription = 33 to the default
-- super_admin role, following the per-feature grant convention. Without this
-- the endpoints are unreachable by anybody: there is no super-admin bypass in
-- the permission check, so a resource with no grants means the feature is
-- simply unusable.
--
-- Two resources rather than one. `vpn_service` is the product: its price, the
-- regions it is sold in, and how many devices a plan allows. `vpn_subscription`
-- is a customer's plan and their devices, where the operational action is
-- revoking one -- a lost phone, a key that has to stop working now. Support
-- needs the second without the first, because repricing a service affects
-- everyone who has already bought it.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 32, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 32, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 32, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 32, 3, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 33, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 33, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 33, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 33, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
