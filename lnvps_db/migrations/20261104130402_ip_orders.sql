CREATE TABLE ip_order (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    provider VARCHAR(100) NOT NULL,
    region_id INTEGER UNSIGNED NOT NULL,
    idempotency_key VARCHAR(200),
    country VARCHAR(10),
    destination VARCHAR(200),
    prefix_len SMALLINT UNSIGNED NOT NULL DEFAULT 32,
    quantity INTEGER UNSIGNED NOT NULL DEFAULT 1,
    state SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    provider_order_id VARCHAR(200),
    cost BIGINT UNSIGNED NOT NULL DEFAULT 0,
    currency VARCHAR(10) NOT NULL DEFAULT '',
    auto BIT(1) NOT NULL DEFAULT 0,
    requested_by INTEGER UNSIGNED,
    approved_by INTEGER UNSIGNED,
    approved_at DATETIME,
    error TEXT,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ordered_at DATETIME,
    delivered_at DATETIME,
    UNIQUE KEY uq_ip_order_idempotency_key (idempotency_key),
    INDEX ix_ip_order_state (state),
    INDEX ix_ip_order_region (region_id),
    CONSTRAINT fk_ip_order_region FOREIGN KEY (region_id) REFERENCES region (id)
);

CREATE TABLE ip_order_range (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip_order_id INTEGER UNSIGNED NOT NULL,
    ip_range_id INTEGER UNSIGNED NOT NULL,
    cidr VARCHAR(200) NOT NULL,
    released_at DATETIME,
    UNIQUE KEY uq_ip_order_range_range (ip_range_id),
    UNIQUE KEY uq_ip_order_range_cidr (cidr),
    INDEX ix_ip_order_range_order (ip_order_id),
    CONSTRAINT fk_ip_order_range_order FOREIGN KEY (ip_order_id) REFERENCES ip_order (id),
    CONSTRAINT fk_ip_order_range_range FOREIGN KEY (ip_range_id) REFERENCES ip_range (id)
);

CREATE TABLE ip_order_audit (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ip_order_id INTEGER UNSIGNED NOT NULL,
    event VARCHAR(50) NOT NULL,
    detail TEXT,
    actor_user_id INTEGER UNSIGNED,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX ix_ip_order_audit_order (ip_order_id),
    CONSTRAINT fk_ip_order_audit_order FOREIGN KEY (ip_order_id) REFERENCES ip_order (id) ON DELETE CASCADE
);

INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 37, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 37, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 37, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 37, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
