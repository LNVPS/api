-- Saved payment methods for off-session (merchant-initiated) automatic renewals.
--
-- Provider-agnostic (revolut now, stripe/paypal later). Stores only opaque
-- provider token references (encrypted) plus non-sensitive card metadata
-- (brand/last4/expiry) for display and expiry management. No PAN/CVV is stored.
CREATE TABLE user_payment_method
(
    id                   INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id              INTEGER UNSIGNED NOT NULL,
    created              TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Payment processor: e.g. 'revolut'
    provider             VARCHAR(20)      NOT NULL,
    -- Encrypted provider customer id owning the saved method
    external_customer_id TEXT             NOT NULL,
    -- Encrypted reusable payment method id charged off-session
    external_id          TEXT             NOT NULL,
    -- Non-sensitive card metadata (PCI-safe) for display + expiry handling
    card_brand           VARCHAR(32)      NULL,
    card_last_four       VARCHAR(4)       NULL,
    exp_month            SMALLINT UNSIGNED NULL,
    exp_year             SMALLINT UNSIGNED NULL,
    -- Whether this is the user's default method for this provider
    is_default           BIT(1)           NOT NULL DEFAULT 0,
    -- Whether this method is usable (disabled when expired/revoked)
    enabled              BIT(1)           NOT NULL DEFAULT 1,
    CONSTRAINT fk_user_payment_method_user
        FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_user_payment_method_user (user_id, provider, enabled)
) DEFAULT CHARSET = utf8mb4;
