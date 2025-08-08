-- Remove is_active column from admin_role_assignments table
-- Since we're now doing hard deletes instead of soft deletes, this column is no longer needed

-- Drop the index that includes is_active
DROP INDEX IF EXISTS idx_admin_role_assignments_lookup ON admin_role_assignments;

-- Remove the is_active column
ALTER TABLE admin_role_assignments DROP COLUMN is_active;

-- Create new index without is_active
CREATE INDEX idx_admin_role_assignments_lookup ON admin_role_assignments (user_id, expires_at);