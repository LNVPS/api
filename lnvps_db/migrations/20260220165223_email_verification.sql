DROP INDEX ix_user_email ON users;
UPDATE users SET email = '' WHERE email IS NULL;
ALTER TABLE users MODIFY COLUMN email VARCHAR(255) NOT NULL DEFAULT '';
CREATE INDEX ix_user_email ON users (email);
ALTER TABLE users ADD COLUMN email_verified BIT(1) NOT NULL DEFAULT 0 AFTER email;
ALTER TABLE users ADD COLUMN email_verify_token VARCHAR(64) NOT NULL DEFAULT '' AFTER email_verified;
