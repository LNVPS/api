-- RBAC System Database Migration for LNVPS Admin API
-- This script creates the Role-Based Access Control tables and default data

-- Roles table - stores role definitions
CREATE TABLE admin_roles (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_system_role (is_system_role)
);

-- Role permissions - maps roles to specific resource+action combinations  
CREATE TABLE admin_role_permissions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    role_id BIGINT UNSIGNED NOT NULL,
    resource SMALLINT UNSIGNED NOT NULL,  -- AdminResource enum value (0-16)
    action SMALLINT UNSIGNED NOT NULL,    -- AdminAction enum value (0-3)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE CASCADE,
    UNIQUE KEY unique_role_permission (role_id, resource, action),
    INDEX idx_role_id (role_id),
    INDEX idx_resource_action (resource, action)
);

-- User role assignments - which users have which roles
CREATE TABLE admin_role_assignments (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INTEGER UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    assigned_by INTEGER UNSIGNED,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE KEY unique_user_role (user_id, role_id),
    INDEX idx_user_id (user_id),
    INDEX idx_role_id (role_id),
    INDEX idx_active (is_active),
    INDEX idx_expires (expires_at)
);

-- Insert default system roles
INSERT INTO admin_roles (name, description, is_system_role) VALUES
('super_admin', 'Super Administrator with full system access', TRUE),
('admin', 'Administrator with most system access (except role management)', TRUE),
('user_manager', 'Can manage users and view analytics', TRUE),
('vm_manager', 'Can manage VMs, hosts, and view related data', TRUE),
('payment_manager', 'Can manage payments and view related data', TRUE),
('read_only', 'Read-only access to admin interface', TRUE);

-- Get role IDs for permission assignments
SET @super_admin_id = (SELECT id FROM admin_roles WHERE name = 'super_admin');
SET @admin_id = (SELECT id FROM admin_roles WHERE name = 'admin');
SET @user_manager_id = (SELECT id FROM admin_roles WHERE name = 'user_manager');
SET @vm_manager_id = (SELECT id FROM admin_roles WHERE name = 'vm_manager');
SET @payment_manager_id = (SELECT id FROM admin_roles WHERE name = 'payment_manager');
SET @read_only_id = (SELECT id FROM admin_roles WHERE name = 'read_only');

-- Super Admin permissions - all resources, all actions
INSERT INTO admin_role_permissions (role_id, resource, action) VALUES
-- Users (resource=0)
(@super_admin_id, 0, 0), (@super_admin_id, 0, 1), (@super_admin_id, 0, 2), (@super_admin_id, 0, 3),
-- VirtualMachines (resource=1) 
(@super_admin_id, 1, 0), (@super_admin_id, 1, 1), (@super_admin_id, 1, 2), (@super_admin_id, 1, 3),
-- Hosts (resource=2)
(@super_admin_id, 2, 0), (@super_admin_id, 2, 1), (@super_admin_id, 2, 2), (@super_admin_id, 2, 3),
-- Payments (resource=3)
(@super_admin_id, 3, 0), (@super_admin_id, 3, 1), (@super_admin_id, 3, 2), (@super_admin_id, 3, 3),
-- Analytics (resource=4)
(@super_admin_id, 4, 0), (@super_admin_id, 4, 1), (@super_admin_id, 4, 2), (@super_admin_id, 4, 3),
-- System (resource=5)
(@super_admin_id, 5, 0), (@super_admin_id, 5, 1), (@super_admin_id, 5, 2), (@super_admin_id, 5, 3),
-- Roles (resource=6)
(@super_admin_id, 6, 0), (@super_admin_id, 6, 1), (@super_admin_id, 6, 2), (@super_admin_id, 6, 3),
-- Audit (resource=7)
(@super_admin_id, 7, 0), (@super_admin_id, 7, 1), (@super_admin_id, 7, 2), (@super_admin_id, 7, 3),
-- AccessPolicy (resource=8)
(@super_admin_id, 8, 0), (@super_admin_id, 8, 1), (@super_admin_id, 8, 2), (@super_admin_id, 8, 3),
-- Company (resource=9)
(@super_admin_id, 9, 0), (@super_admin_id, 9, 1), (@super_admin_id, 9, 2), (@super_admin_id, 9, 3),
-- IpRange (resource=10)
(@super_admin_id, 10, 0), (@super_admin_id, 10, 1), (@super_admin_id, 10, 2), (@super_admin_id, 10, 3),
-- Router (resource=11)
(@super_admin_id, 11, 0), (@super_admin_id, 11, 1), (@super_admin_id, 11, 2), (@super_admin_id, 11, 3),
-- VmCustomPricing (resource=12)
(@super_admin_id, 12, 0), (@super_admin_id, 12, 1), (@super_admin_id, 12, 2), (@super_admin_id, 12, 3),
-- HostRegion (resource=13)
(@super_admin_id, 13, 0), (@super_admin_id, 13, 1), (@super_admin_id, 13, 2), (@super_admin_id, 13, 3),
-- VmOsImage (resource=14)
(@super_admin_id, 14, 0), (@super_admin_id, 14, 1), (@super_admin_id, 14, 2), (@super_admin_id, 14, 3),
-- VmPayment (resource=15)
(@super_admin_id, 15, 0), (@super_admin_id, 15, 1), (@super_admin_id, 15, 2), (@super_admin_id, 15, 3),
-- VmTemplate (resource=16)
(@super_admin_id, 16, 0), (@super_admin_id, 16, 1), (@super_admin_id, 16, 2), (@super_admin_id, 16, 3);

-- Admin permissions - most resources except role management (create/update/delete)
INSERT INTO admin_role_permissions (role_id, resource, action) VALUES
-- Users (resource=0) - all actions
(@admin_id, 0, 0), (@admin_id, 0, 1), (@admin_id, 0, 2), (@admin_id, 0, 3),
-- VirtualMachines (resource=1) - all actions
(@admin_id, 1, 0), (@admin_id, 1, 1), (@admin_id, 1, 2), (@admin_id, 1, 3),
-- Hosts (resource=2) - all actions
(@admin_id, 2, 0), (@admin_id, 2, 1), (@admin_id, 2, 2), (@admin_id, 2, 3),
-- Payments (resource=3) - all actions
(@admin_id, 3, 0), (@admin_id, 3, 1), (@admin_id, 3, 2), (@admin_id, 3, 3),
-- Analytics (resource=4) - all actions
(@admin_id, 4, 0), (@admin_id, 4, 1), (@admin_id, 4, 2), (@admin_id, 4, 3),
-- System (resource=5) - all actions
(@admin_id, 5, 0), (@admin_id, 5, 1), (@admin_id, 5, 2), (@admin_id, 5, 3),
-- Roles (resource=6) - view only
(@admin_id, 6, 1),
-- Audit (resource=7) - view only
(@admin_id, 7, 1),
-- AccessPolicy (resource=8) - all actions
(@admin_id, 8, 0), (@admin_id, 8, 1), (@admin_id, 8, 2), (@admin_id, 8, 3),
-- Company (resource=9) - view and update only (no create/delete)
(@admin_id, 9, 1), (@admin_id, 9, 2),
-- IpRange (resource=10) - all actions
(@admin_id, 10, 0), (@admin_id, 10, 1), (@admin_id, 10, 2), (@admin_id, 10, 3),
-- Router (resource=11) - all actions
(@admin_id, 11, 0), (@admin_id, 11, 1), (@admin_id, 11, 2), (@admin_id, 11, 3),
-- VmCustomPricing (resource=12) - all actions
(@admin_id, 12, 0), (@admin_id, 12, 1), (@admin_id, 12, 2), (@admin_id, 12, 3),
-- HostRegion (resource=13) - all actions
(@admin_id, 13, 0), (@admin_id, 13, 1), (@admin_id, 13, 2), (@admin_id, 13, 3),
-- VmOsImage (resource=14) - all actions
(@admin_id, 14, 0), (@admin_id, 14, 1), (@admin_id, 14, 2), (@admin_id, 14, 3),
-- VmPayment (resource=15) - view and update only
(@admin_id, 15, 1), (@admin_id, 15, 2),
-- VmTemplate (resource=16) - all actions
(@admin_id, 16, 0), (@admin_id, 16, 1), (@admin_id, 16, 2), (@admin_id, 16, 3);

-- User Manager permissions - users + read-only analytics/audit
INSERT INTO admin_role_permissions (role_id, resource, action) VALUES
-- Users (resource=0) - all actions
(@user_manager_id, 0, 0), (@user_manager_id, 0, 1), (@user_manager_id, 0, 2), (@user_manager_id, 0, 3),
-- Analytics (resource=4) - view only
(@user_manager_id, 4, 1),
-- Audit (resource=7) - view only
(@user_manager_id, 7, 1);

-- VM Manager permissions - VMs, hosts + read-only users/analytics/system
INSERT INTO admin_role_permissions (role_id, resource, action) VALUES
-- Users (resource=0) - view only (to see VM owners)
(@vm_manager_id, 0, 1),
-- VirtualMachines (resource=1) - all actions
(@vm_manager_id, 1, 0), (@vm_manager_id, 1, 1), (@vm_manager_id, 1, 2), (@vm_manager_id, 1, 3),
-- Hosts (resource=2) - all actions
(@vm_manager_id, 2, 0), (@vm_manager_id, 2, 1), (@vm_manager_id, 2, 2), (@vm_manager_id, 2, 3),
-- Analytics (resource=4) - view only
(@vm_manager_id, 4, 1),
-- System (resource=5) - view only
(@vm_manager_id, 5, 1),
-- HostRegion (resource=13) - view only (needed to see host regions)
(@vm_manager_id, 13, 1),
-- VmOsImage (resource=14) - all actions (managing VM images)
(@vm_manager_id, 14, 0), (@vm_manager_id, 14, 1), (@vm_manager_id, 14, 2), (@vm_manager_id, 14, 3),
-- VmTemplate (resource=16) - all actions (managing VM templates)
(@vm_manager_id, 16, 0), (@vm_manager_id, 16, 1), (@vm_manager_id, 16, 2), (@vm_manager_id, 16, 3);

-- Payment Manager permissions - payments + read-only users/analytics
INSERT INTO admin_role_permissions (role_id, resource, action) VALUES
-- Users (resource=0) - view only
(@payment_manager_id, 0, 1),
-- Payments (resource=3) - all actions
(@payment_manager_id, 3, 0), (@payment_manager_id, 3, 1), (@payment_manager_id, 3, 2), (@payment_manager_id, 3, 3),
-- Analytics (resource=4) - view only
(@payment_manager_id, 4, 1),
-- Company (resource=9) - view only (needed for billing context)
(@payment_manager_id, 9, 1),
-- VmCustomPricing (resource=12) - all actions (managing pricing models)
(@payment_manager_id, 12, 0), (@payment_manager_id, 12, 1), (@payment_manager_id, 12, 2), (@payment_manager_id, 12, 3),
-- VmPayment (resource=15) - all actions (managing VM payments)
(@payment_manager_id, 15, 0), (@payment_manager_id, 15, 1), (@payment_manager_id, 15, 2), (@payment_manager_id, 15, 3);

-- Read-only permissions - view only on all resources
INSERT INTO admin_role_permissions (role_id, resource, action) VALUES
-- All resources - view only (action=1)
(@read_only_id, 0, 1), -- Users
(@read_only_id, 1, 1), -- VirtualMachines
(@read_only_id, 2, 1), -- Hosts
(@read_only_id, 3, 1), -- Payments
(@read_only_id, 4, 1), -- Analytics
(@read_only_id, 5, 1), -- System
(@read_only_id, 6, 1), -- Roles
(@read_only_id, 7, 1), -- Audit
(@read_only_id, 8, 1), -- AccessPolicy
(@read_only_id, 9, 1), -- Company
(@read_only_id, 10, 1), -- IpRange
(@read_only_id, 11, 1), -- Router
(@read_only_id, 12, 1), -- VmCustomPricing
(@read_only_id, 13, 1), -- HostRegion
(@read_only_id, 14, 1), -- VmOsImage
(@read_only_id, 15, 1), -- VmPayment
(@read_only_id, 16, 1); -- VmTemplate

-- Create indexes for performance
CREATE INDEX idx_admin_role_permissions_lookup ON admin_role_permissions (role_id, resource, action);
CREATE INDEX idx_admin_role_assignments_lookup ON admin_role_assignments (user_id, is_active, expires_at);

-- Add comments for documentation
ALTER TABLE admin_roles COMMENT = 'Administrative roles definition';
ALTER TABLE admin_role_permissions COMMENT = 'Role to permission mappings using enum values';
ALTER TABLE admin_role_assignments COMMENT = 'User role assignments with expiration support';

-- Resource enum values (for reference):
-- 0=Users, 1=VirtualMachines, 2=Hosts, 3=Payments, 4=Analytics, 5=System, 6=Roles, 7=Audit,
-- 8=AccessPolicy, 9=Company, 10=IpRange, 11=Router, 12=VmCustomPricing, 13=HostRegion,
-- 14=VmOsImage, 15=VmPayment, 16=VmTemplate
-- Action enum values (for reference):  
-- 0=Create, 1=View, 2=Update, 3=Delete