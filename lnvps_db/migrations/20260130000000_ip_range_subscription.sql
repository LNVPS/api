-- Available IP Space table
-- Stores inventory of IP ranges available for sale

CREATE TABLE available_ip_space (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    cidr VARCHAR(200) NOT NULL, -- CIDR notation (e.g., 192.168.1.0/22 or 2001:db8::/29)
    min_prefix_size SMALLINT UNSIGNED NOT NULL, -- Smallest subdivision allowed (e.g., 24 for /24, 48 for /48)
    max_prefix_size SMALLINT UNSIGNED NOT NULL, -- Largest subdivision allowed (e.g., 22 for /22, 32 for /32)
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Registry information
    registry SMALLINT UNSIGNED NOT NULL, -- 0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC
    external_id VARCHAR(255), -- RIPE/ARIN allocation ID
    
    -- Availability status
    is_available BIT(1) NOT NULL DEFAULT 1,
    is_reserved BIT(1) NOT NULL DEFAULT 0,
    
    -- Additional metadata (JSON)
    -- Can store routing requirements, upstream provider info, etc.
    metadata JSON,
    
    UNIQUE INDEX idx_available_ip_space_cidr (cidr),
    INDEX idx_available_ip_space_available (is_available),
    INDEX idx_available_ip_space_reserved (is_reserved),
    INDEX idx_available_ip_space_registry (registry),
    INDEX idx_available_ip_space_external_id (external_id)
);

-- IP Space Pricing table
-- Stores pricing for different prefix sizes from the same IP block

CREATE TABLE ip_space_pricing (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    available_ip_space_id INTEGER UNSIGNED NOT NULL,
    prefix_size SMALLINT UNSIGNED NOT NULL, -- Size of the prefix being priced (e.g., 24 for /24, 23 for /23)
    
    -- Pricing (stored in cents/millisats per month)
    price_per_month BIGINT UNSIGNED NOT NULL,
    currency VARCHAR(4) NOT NULL DEFAULT 'USD',
    
    -- Setup fee (one-time, stored in cents/millisats)
    setup_fee BIGINT UNSIGNED NOT NULL DEFAULT 0,
    
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_ip_space_pricing_available_space FOREIGN KEY (available_ip_space_id) REFERENCES available_ip_space (id) ON DELETE CASCADE,
    INDEX idx_ip_space_pricing_available_space (available_ip_space_id),
    INDEX idx_ip_space_pricing_prefix_size (prefix_size),
    UNIQUE INDEX idx_ip_space_pricing_unique (available_ip_space_id, prefix_size)
);

-- IP Range Subscription table
-- Stores IP ranges sold to users via subscriptions for monthly billing

CREATE TABLE ip_range_subscription (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    subscription_line_item_id INTEGER UNSIGNED NOT NULL,
    available_ip_space_id INTEGER UNSIGNED NOT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- IP Range details
    cidr VARCHAR(200) NOT NULL, -- CIDR notation (e.g., 192.168.1.0/24 or 2001:db8::/64)
    
    -- Status tracking
    is_active BIT(1) NOT NULL DEFAULT 1,
    
    -- When the subscription started for this IP range
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- When the subscription ended (NULL if still active)
    ended_at TIMESTAMP NULL,
    
    -- Additional metadata (JSON)
    -- Can store routing info, ASN assignment, etc.
    metadata JSON,
    
    CONSTRAINT fk_ip_range_subscription_line_item FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id) ON DELETE CASCADE,
    CONSTRAINT fk_ip_range_subscription_available_space FOREIGN KEY (available_ip_space_id) REFERENCES available_ip_space (id) ON DELETE RESTRICT,
    INDEX idx_ip_range_subscription_line_item (subscription_line_item_id),
    INDEX idx_ip_range_subscription_available_space (available_ip_space_id),
    INDEX idx_ip_range_subscription_active (is_active),
    INDEX idx_ip_range_subscription_cidr (cidr),
    UNIQUE INDEX idx_ip_range_subscription_unique_cidr (cidr)
);
