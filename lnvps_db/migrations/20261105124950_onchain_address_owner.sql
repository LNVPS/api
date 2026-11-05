-- Who an on-chain receive address belongs to, kept after the payment that
-- issued it is purged. A never-paid VM or subscription is hard deleted with its
-- `subscription_payment` rows, but the address stays in the wallet and the
-- customer can still pay it. The purge copies each on-chain or FixedFloat
-- payment's address here, so a late deposit is credited to the owner (#220).
--
-- No foreign keys: the rows this points at are the ones being purged.
-- `address` is encrypted like `subscription_payment.external_data`, so lookups
-- go through `address_hash` (SHA-256 of the address).
CREATE TABLE onchain_address_owner
(
    id                INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT,
    address           VARCHAR(512)      NOT NULL,
    address_hash      BINARY(32)        NOT NULL,
    user_id           INTEGER UNSIGNED  NOT NULL,
    subscription_id   INTEGER UNSIGNED  NULL DEFAULT NULL,
    payment_id        BINARY(32)        NULL DEFAULT NULL,
    vm_id             INTEGER UNSIGNED  NULL DEFAULT NULL,
    created           DATETIME          NOT NULL DEFAULT NOW(),
    -- Expiry of the quote the address was issued for.
    expires           DATETIME          NULL DEFAULT NULL,
    -- What the customer was asked to send (msat for BTC).
    currency          VARCHAR(4)        NULL DEFAULT NULL,
    amount            BIGINT UNSIGNED   NULL DEFAULT NULL,
    -- 0 = open, 1 = credited
    status            SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    credited_outpoint VARCHAR(255)      NULL DEFAULT NULL,
    -- Outpoint of the unconfirmed deposit the owner was last told about.
    notified_outpoint VARCHAR(255)      NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_onchain_address_owner_address (address_hash),
    UNIQUE KEY uk_onchain_address_owner_outpoint (credited_outpoint),
    KEY ix_onchain_address_owner_user (user_id)
);
