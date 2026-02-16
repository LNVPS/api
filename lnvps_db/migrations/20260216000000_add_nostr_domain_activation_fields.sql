-- Add activation_hash and http_only columns to nostr_domain table for path-based activation
ALTER TABLE nostr_domain ADD COLUMN activation_hash varchar(64) DEFAULT NULL;
ALTER TABLE nostr_domain ADD COLUMN http_only bit(1) NOT NULL DEFAULT 1;

-- Create index on activation_hash for faster lookups
CREATE INDEX ix_nostr_domain_activation_hash ON nostr_domain(activation_hash);
