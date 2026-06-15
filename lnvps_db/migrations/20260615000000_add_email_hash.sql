-- Add email_hash column for efficient email lookup
-- email_hash is SHA-256 of lowercased+trimmed email, stored as 32-byte BINARY
ALTER TABLE users ADD COLUMN email_hash BINARY(32) DEFAULT NULL;
CREATE INDEX idx_users_email_hash ON users(email_hash);
