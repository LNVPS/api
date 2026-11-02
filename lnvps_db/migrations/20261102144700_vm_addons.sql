CREATE TABLE vm_addon_price (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    region_id INTEGER UNSIGNED NOT NULL,
    kind SMALLINT UNSIGNED NOT NULL,
    currency VARCHAR(10) NOT NULL,
    monthly_amount BIGINT UNSIGNED NOT NULL,
    max_quantity INTEGER UNSIGNED NOT NULL,
    enabled BIT(1) NOT NULL DEFAULT 1,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_vm_addon_price_region_kind (region_id, kind),
    CONSTRAINT fk_vm_addon_price_region FOREIGN KEY (region_id) REFERENCES region (id)
);

CREATE TABLE vm_addon (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    vm_id INTEGER UNSIGNED NOT NULL,
    kind SMALLINT UNSIGNED NOT NULL,
    quantity INTEGER UNSIGNED NOT NULL,
    subscription_line_item_id INTEGER UNSIGNED NOT NULL,
    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_vm_addon_vm_kind (vm_id, kind),
    UNIQUE KEY uq_vm_addon_line_item (subscription_line_item_id),
    CONSTRAINT fk_vm_addon_vm FOREIGN KEY (vm_id) REFERENCES vm (id) ON DELETE CASCADE,
    CONSTRAINT fk_vm_addon_line_item FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id) ON DELETE CASCADE
);

INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 36, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 36, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 36, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 36, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
