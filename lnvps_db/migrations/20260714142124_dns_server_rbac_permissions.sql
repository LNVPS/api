-- RBAC permissions for DNS server management
--
-- The `20260710121414_dns_server.sql` migration added the DnsServer admin
-- resource (AdminResource::DnsServer = 22) and the admin endpoints in
-- `lnvps_api_admin/src/admin/dns_servers.rs` gate on it, but no migration ever
-- granted the default super_admin role permissions for it. This grants the full
-- set so super_admin can manage DNS servers.
--
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3

-- Grant all permissions on dns_server to the super_admin role
INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 22, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 22, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 22, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 22, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
