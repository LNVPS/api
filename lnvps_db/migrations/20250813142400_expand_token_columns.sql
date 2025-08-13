-- Expand encrypted columns to accommodate encrypted data
-- Encrypted data has "ENC:" prefix + base64 encoding which significantly increases size
-- Using TEXT type to handle encrypted data of any reasonable size

-- Token columns
ALTER TABLE router MODIFY COLUMN token TEXT not null;
ALTER TABLE vm_host MODIFY COLUMN api_token TEXT not null;
ALTER TABLE users MODIFY COLUMN email TEXT;
ALTER TABLE user_ssh_key MODIFY COLUMN key_data TEXT not null;
ALTER TABLE vm_payment MODIFY COLUMN external_data TEXT not null;