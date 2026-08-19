-- RBAC permissions for support-agent conversation administration.
--
-- Adds AdminResource::SupportAgent = 30 to the default super_admin role,
-- following the per-feature grant convention. Without this the endpoints are
-- unreachable by anybody: there is no super-admin bypass in the permission
-- check, so a resource with no grants means the feature is simply unusable.
--
-- Its own resource rather than folding into Users because a transcript is raw
-- customer PII — addresses, IPs, hostnames, and whatever a customer pasted into
-- a support request — which is a wider disclosure than the account fields
-- `users::view` implies today. Reading support history should be a decision an
-- operator makes on purpose.
--
-- Only super_admin is granted. Delete is included for completeness of the
-- resource even though no endpoint currently deletes a conversation: the
-- transcript is the training corpus and is append-only by design.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 30, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 30, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 30, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 30, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
