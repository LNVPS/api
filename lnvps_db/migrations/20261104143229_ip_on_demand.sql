ALTER TABLE ip_provider_region
    ADD COLUMN when_no_ip SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN sell_without_capacity BIT(1) NOT NULL DEFAULT 0,
    ADD COLUMN wait_refund_hours INTEGER UNSIGNED NOT NULL DEFAULT 0;

CREATE TABLE vm_ip_wait (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vm_id INTEGER UNSIGNED NOT NULL,
    region_id INTEGER UNSIGNED NOT NULL,
    ip4_needed SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    ip_order_id INTEGER UNSIGNED,
    released BIT(1) NOT NULL DEFAULT 0,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_vm_ip_wait_vm (vm_id),
    INDEX ix_vm_ip_wait_region (region_id),
    CONSTRAINT fk_vm_ip_wait_vm FOREIGN KEY (vm_id) REFERENCES vm (id) ON DELETE CASCADE,
    CONSTRAINT fk_vm_ip_wait_region FOREIGN KEY (region_id) REFERENCES region (id),
    CONSTRAINT fk_vm_ip_wait_order FOREIGN KEY (ip_order_id) REFERENCES ip_order (id) ON DELETE SET NULL
);
