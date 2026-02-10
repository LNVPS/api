-- RBAC permissions for IP space management system

-- Add IP space resource to AdminResource enum:
-- IpSpace = 20

-- Grant all permissions on IP space to SuperAdmin role (role_id = 1)
-- Resource: IpSpace (20)
INSERT INTO admin_role_permissions (role_id, resource, action, created_at)
VALUES 
    (1, 20, 0, NOW()), -- Create
    (1, 20, 1, NOW()), -- View
    (1, 20, 2, NOW()), -- Update
    (1, 20, 3, NOW()); -- Delete
