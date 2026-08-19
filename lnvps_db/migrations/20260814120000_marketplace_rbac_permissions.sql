-- RBAC permissions for marketplace administration.
--
-- Adds AdminResource::MarketplaceNode = 28 and MarketplaceOperator = 29 to the
-- default super_admin role, following the per-feature grant convention.
--
-- Without this the marketplace admin API is unreachable by anybody. There is no
-- super-admin bypass in the permission check — `has_permission` is a set lookup
-- against the tuples a role was granted — so every endpoint added by the
-- marketplace work has been answering 403 to every caller, including the role
-- that is supposed to be able to do anything. Nothing failed at the point the
-- resources were introduced, because a resource with no grants is a valid state:
-- it simply means nobody may use it.
--
-- The two resources stay separate on purpose. MarketplaceNode is operational —
-- approve, suspend, drain, reject a machine — and MarketplaceOperator is money:
-- revenue share and payouts. An admin who can bring a misbehaving node out of
-- service should not thereby be able to change what its owner is paid.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 28, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 28, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 28, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 28, 3, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 29, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 29, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 29, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 29, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
