CREATE TABLE ip_provider (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    kind SMALLINT UNSIGNED NOT NULL,
    enabled BIT(1) NOT NULL DEFAULT 0,
    url VARCHAR(255) NOT NULL DEFAULT '',
    token VARCHAR(1024) NOT NULL,
    subsidiary VARCHAR(10) NOT NULL DEFAULT 'IE',
    rir VARCHAR(20) NOT NULL DEFAULT 'ripe',
    gateway VARCHAR(100) NOT NULL DEFAULT '',
    access_policy_id INTEGER UNSIGNED,
    approval_required BIT(1) NOT NULL DEFAULT 1,
    monthly_spend_cap BIGINT UNSIGNED NOT NULL DEFAULT 0,
    currency VARCHAR(10) NOT NULL DEFAULT 'EUR',
    enable_ranges_on_delivery BIT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY uq_ip_provider_name (name),
    CONSTRAINT fk_ip_provider_access_policy FOREIGN KEY (access_policy_id) REFERENCES access_policy (id)
);

CREATE TABLE ip_provider_region (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    provider_id INTEGER UNSIGNED NOT NULL,
    region_id INTEGER UNSIGNED NOT NULL,
    country VARCHAR(10),
    destination VARCHAR(200),
    prefix_len SMALLINT UNSIGNED NOT NULL DEFAULT 32,
    quantity INTEGER UNSIGNED NOT NULL DEFAULT 1,
    auto_threshold BIGINT UNSIGNED,
    enabled BIT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY uq_ip_provider_region (provider_id, region_id),
    CONSTRAINT fk_ip_provider_region_provider FOREIGN KEY (provider_id) REFERENCES ip_provider (id) ON DELETE CASCADE,
    CONSTRAINT fk_ip_provider_region_region FOREIGN KEY (region_id) REFERENCES region (id)
);
