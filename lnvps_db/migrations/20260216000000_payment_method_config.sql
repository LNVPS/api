-- Payment method configuration table
-- Stores payment provider configurations that were previously in YAML config
-- Each row represents a single payment method configuration per company

CREATE TABLE payment_method_config (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- Company that owns this payment method configuration
    company_id INTEGER UNSIGNED NOT NULL,
    -- Payment method type: 0=Lightning, 1=Revolut, 2=Paypal, 3=Stripe
    payment_method SMALLINT UNSIGNED NOT NULL,
    -- Display name for this configuration (e.g., "Primary LND Node", "Revolut EU")
    name VARCHAR(255) NOT NULL,
    -- Whether this payment method is enabled
    enabled BIT(1) NOT NULL DEFAULT 1,
    -- Provider type for the payment method (e.g., "lnd", "bitvora" for Lightning)
    provider_type VARCHAR(50) NOT NULL,
    -- JSON configuration specific to the provider type
    -- Lightning/LND: {"url": "...", "cert_path": "...", "macaroon_path": "..."}
    -- Lightning/Bitvora: {"token": "...", "webhook_secret": "..."}
    -- Revolut: {"url": "...", "token": "...", "api_version": "...", "public_key": "..."}
    -- Stripe: {"secret_key": "...", "publishable_key": "...", "webhook_secret": "..."}
    -- PayPal: {"client_id": "...", "client_secret": "...", "mode": "sandbox|live"}
    config JSON NOT NULL,
    -- Processing fee percentage rate (e.g., 1.0 for 1%)
    -- NULL means no processing fee configuration
    processing_fee_rate FLOAT,
    -- Processing fee base amount in smallest currency unit (e.g., cents)
    processing_fee_base BIGINT UNSIGNED,
    -- Currency for the processing fee base (e.g., "EUR", "USD")
    processing_fee_currency VARCHAR(5),
    -- Created timestamp
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Last modified timestamp
    modified TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- Foreign key to company
    CONSTRAINT fk_payment_method_config_company FOREIGN KEY (company_id) REFERENCES company(id)
);

-- Index for quick lookups by company
CREATE INDEX idx_company_id ON payment_method_config(company_id);

-- Index for finding enabled payment methods
CREATE INDEX idx_enabled ON payment_method_config(enabled);

-- RBAC permissions for payment method configuration management
-- AdminResource::PaymentMethodConfig = 21
-- AdminAction: Create = 0, View = 1, Update = 2, Delete = 3

-- Grant all permissions on payment_method_config to SuperAdmin role (role_id = 1)
INSERT INTO admin_role_permissions (role_id, resource, action, created_at)
VALUES 
    (1, 21, 0, NOW()), -- Create
    (1, 21, 1, NOW()), -- View
    (1, 21, 2, NOW()), -- Update
    (1, 21, 3, NOW()); -- Delete
