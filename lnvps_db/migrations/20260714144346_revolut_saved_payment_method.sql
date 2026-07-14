-- Unified saved payment methods for automatic renewals.
--
-- Provider-agnostic (nwc, revolut now; stripe/paypal later). Stores only opaque
-- provider token references (encrypted) plus non-sensitive card metadata
-- (brand/last4/expiry) for display and expiry management. No PAN/CVV is stored.
--
-- NWC (Nostr Wallet Connect) is modelled as a payment method too: external_id
-- holds the connection string and external_customer_id is NULL. This lets users
-- keep multiple methods and pick a default between their Lightning wallet (NWC)
-- and a saved card.
CREATE TABLE user_payment_method
(
    id                   INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id              INTEGER UNSIGNED NOT NULL,
    created              TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Payment processor: 'nwc', 'revolut'
    provider             VARCHAR(20)      NOT NULL,
    -- Optional user-defined label to distinguish multiple methods
    name                 VARCHAR(100)     NULL,
    -- Encrypted provider customer id (NULL for providers without one, e.g. nwc)
    external_customer_id TEXT             NULL,
    -- Encrypted reusable token charged for renewals: Revolut payment method id,
    -- or the NWC connection string
    external_id          TEXT             NOT NULL,
    -- Non-sensitive card metadata (PCI-safe) for display + expiry handling
    card_brand           VARCHAR(32)      NULL,
    card_last_four       VARCHAR(4)       NULL,
    exp_month            SMALLINT UNSIGNED NULL,
    exp_year             SMALLINT UNSIGNED NULL,
    -- Whether this is the user's default method
    is_default           BIT(1)           NOT NULL DEFAULT 0,
    -- Whether this method is usable (disabled when expired/revoked)
    enabled              BIT(1)           NOT NULL DEFAULT 1,
    CONSTRAINT fk_user_payment_method_user
        FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_user_payment_method_user (user_id, provider, enabled)
) DEFAULT CHARSET = utf8mb4;

-- Migrate existing NWC connection strings into the unified table. The stored
-- value (encrypted ciphertext or plaintext) is copied verbatim; the
-- EncryptedString decoder transparently handles either form on read.
INSERT INTO user_payment_method (user_id, provider, external_id, is_default, enabled)
SELECT id, 'nwc', nwc_connection_string, 1, 1
FROM users
WHERE nwc_connection_string IS NOT NULL
  AND nwc_connection_string != '';

-- NWC is now represented as a payment method; drop the legacy column.
ALTER TABLE users
    DROP COLUMN nwc_connection_string;
