-- Add last_status_change column to track when domain activation state was last modified
ALTER TABLE nostr_domain ADD COLUMN last_status_change timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Initialize existing records with current timestamp
UPDATE nostr_domain SET last_status_change = CURRENT_TIMESTAMP;