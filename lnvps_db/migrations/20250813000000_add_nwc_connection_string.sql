-- Add nwc_connection_string to users table for automatic VM renewal via Nostr Wallet Connect
ALTER TABLE users 
ADD COLUMN nwc_connection_string TEXT COMMENT 'Encrypted Nostr Wallet Connect connection string for automatic renewals';
ALTER TABLE vm
    ADD COLUMN auto_renewal_enabled bit(1) not null COMMENT 'Enable automatic renewal via NWC for this VM';