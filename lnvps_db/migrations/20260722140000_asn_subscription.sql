-- ASN Sponsoring subscriptions
--
-- Unlike IP ranges (which sub-allocate from an owned block), a sponsored ASN is
-- a unique registry resource requested per-customer from the RIR. The number is
-- assigned by the RIR (an async, admin-in-the-loop process), so `asn` is NULL
-- until assigned and `status` tracks the request lifecycle. Once assigned, the
-- `aut-num` object is created in the whois DB and its primary key stored in
-- `aut_num_ref`.

CREATE TABLE asn_subscription (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    subscription_line_item_id INTEGER UNSIGNED NOT NULL,

    -- Registry the ASN is (to be) sponsored under (0=ARIN, 1=RIPE, ...).
    registry SMALLINT UNSIGNED NOT NULL,

    -- Assigned AS number (NULL until the RIR assigns it).
    asn INTEGER UNSIGNED NULL,

    -- Request lifecycle: 0=Requested, 1=Assigned, 2=Failed.
    status SMALLINT UNSIGNED NOT NULL DEFAULT 0,

    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- When the RIR assigned the number (NULL while pending).
    assigned_at TIMESTAMP NULL,

    -- Status tracking (mirrors ip_range_subscription).
    is_active BIT(1) NOT NULL DEFAULT 1,
    ended_at TIMESTAMP NULL,

    -- Primary key of the created `aut-num` whois object, once created.
    aut_num_ref VARCHAR(255) NULL,

    -- Additional metadata (JSON): NCC ticket id, maintainer, etc.
    metadata JSON,

    CONSTRAINT fk_asn_subscription_line_item FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id) ON DELETE CASCADE,
    INDEX idx_asn_subscription_line_item (subscription_line_item_id),
    INDEX idx_asn_subscription_status (status),
    INDEX idx_asn_subscription_active (is_active),
    UNIQUE INDEX idx_asn_subscription_asn (asn)
);
