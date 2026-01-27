-- Subscription billing system for recurring services (LIR, etc.)
-- Mirrors the VM billing structure but more generic

-- Main subscription table (similar to vm table)
CREATE TABLE subscription (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INTEGER UNSIGNED NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires TIMESTAMP,
    is_active BIT(1) NOT NULL DEFAULT 1,
    
    -- Billing cycle (same for all line items)
    currency VARCHAR(4) NOT NULL,
    interval_amount INTEGER UNSIGNED NOT NULL,
    interval_type SMALLINT UNSIGNED NOT NULL, -- 0=Day, 1=Month, 2=Year
    
    -- Setup fee (one-time, charged with first payment)
    setup_fee BIGINT UNSIGNED NOT NULL DEFAULT 0,
    
    -- Auto-renewal
    auto_renewal_enabled BIT(1) NOT NULL DEFAULT 0,
    
    -- External ID for third-party integrations (Stripe subscription ID, etc.)
    external_id VARCHAR(255),
    
    CONSTRAINT fk_subscription_user FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_subscription_user (user_id),
    INDEX idx_subscription_active (is_active),
    INDEX idx_subscription_expires (expires),
    INDEX idx_subscription_external_id (external_id)
);

-- Line items within a subscription
CREATE TABLE subscription_line_item (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    subscription_id INTEGER UNSIGNED NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    
    -- Recurring cost for this line item (stored in cents/millisats)
    amount BIGINT UNSIGNED NOT NULL,
    
    -- Setup cost for this line item (optional, stored in cents/millisats)
    setup_amount BIGINT UNSIGNED NOT NULL DEFAULT 0,
    
    -- Service-specific configuration (JSON)
    -- For LIR: {"type": "ipv4", "prefix_size": 24, "ip_range": "1.2.3.0/24"}
    -- For ASN: {"asn": 64512}
    configuration JSON,
    
    CONSTRAINT fk_line_item_subscription FOREIGN KEY (subscription_id) REFERENCES subscription (id) ON DELETE CASCADE,
    INDEX idx_line_item_subscription (subscription_id)
);

-- Subscription payment table (mirrors vm_payment)
CREATE TABLE subscription_payment (
    id BINARY(32) NOT NULL,
    subscription_id INTEGER UNSIGNED NOT NULL,
    user_id INTEGER UNSIGNED NOT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires TIMESTAMP NOT NULL,
    amount BIGINT UNSIGNED NOT NULL,
    currency VARCHAR(5) NOT NULL,
    payment_method SMALLINT UNSIGNED NOT NULL, -- 0=Lightning, 1=Revolut, 2=Paypal
    payment_type SMALLINT UNSIGNED NOT NULL, -- 0=Purchase (initial+setup), 1=Renewal
    
    -- Payment processing
    external_data TEXT NOT NULL, -- Invoice/payment data (encrypted)
    external_id VARCHAR(255),
    is_paid BIT(1) NOT NULL DEFAULT 0,
    
    -- Billing calculations
    rate FLOAT NOT NULL, -- Exchange rate to base currency
    time_value BIGINT UNSIGNED, -- Seconds added to subscription
    tax BIGINT UNSIGNED NOT NULL,
    
    CONSTRAINT fk_subscription_payment_subscription FOREIGN KEY (subscription_id) REFERENCES subscription (id),
    CONSTRAINT fk_subscription_payment_user FOREIGN KEY (user_id) REFERENCES users (id),
    INDEX idx_subscription_payment_subscription (subscription_id),
    INDEX idx_subscription_payment_user (user_id),
    INDEX idx_subscription_payment_is_paid (is_paid),
    INDEX idx_subscription_payment_expires (expires),
    INDEX idx_subscription_payment_external_id (external_id)
);

CREATE UNIQUE INDEX ix_subscription_payment_id ON subscription_payment (id);
