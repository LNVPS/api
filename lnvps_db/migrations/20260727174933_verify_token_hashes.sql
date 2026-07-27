-- Store verification secrets as SHA-256 hashes instead of plaintext.
--
-- `users.email_verify_token` and `users.whatsapp_verify_code` are
-- password-reset-class secrets: anyone holding the value can confirm the
-- action it guards. Persisting them in the clear meant a read-only DB leak
-- exposed live tokens. The API now writes the lowercase-hex SHA-256 of the
-- secret and looks users up by hash, so the raw value only ever exists in
-- the email/WhatsApp message and in flight.
--
-- Any verification pending at deploy time is invalidated (the stored plaintext
-- can no longer be matched); affected users simply re-request verification.
UPDATE users SET email_verify_token = '' WHERE email_verify_token != '';
UPDATE users SET whatsapp_verify_code = NULL WHERE whatsapp_verify_code IS NOT NULL;

-- Failed WhatsApp confirmation attempts since the code was issued. The API
-- increments on each wrong code and invalidates the code after a small limit,
-- so the 6-digit code cannot be brute-forced online.
ALTER TABLE users
    ADD COLUMN whatsapp_verify_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0 AFTER whatsapp_verify_code;
