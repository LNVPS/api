-- Distinguishes native Nostr accounts (pubkey is a real schnorr x-only key)
-- from external OAuth/OIDC accounts (pubkey is a synthetic
-- sha256("{provider}:{subject}") identifier, not a real Nostr key).
-- Existing rows are all Nostr accounts (0).
alter table users
    add column account_type smallint unsigned not null default 0;
