-- RBAC permissions for subscription billing system

-- Add subscription resources to AdminResource enum:
-- Subscriptions = 17
-- SubscriptionLineItems = 18
-- SubscriptionPayments = 19

-- Grant all permissions on subscriptions to SuperAdmin role (role_id = 1)
-- Resource: Subscriptions (17)
INSERT INTO admin_role_permissions (role_id, resource, action, created_at)
VALUES 
    (1, 17, 0, NOW()), -- Create
    (1, 17, 1, NOW()), -- View
    (1, 17, 2, NOW()), -- Update
    (1, 17, 3, NOW()); -- Delete

-- Resource: SubscriptionLineItems (18)
INSERT INTO admin_role_permissions (role_id, resource, action, created_at)
VALUES 
    (1, 18, 0, NOW()), -- Create
    (1, 18, 1, NOW()), -- View
    (1, 18, 2, NOW()), -- Update
    (1, 18, 3, NOW()); -- Delete

-- Resource: SubscriptionPayments (19)
INSERT INTO admin_role_permissions (role_id, resource, action, created_at)
VALUES 
    (1, 19, 0, NOW()), -- Create
    (1, 19, 1, NOW()), -- View
    (1, 19, 2, NOW()), -- Update
    (1, 19, 3, NOW()); -- Delete
