-- Add CPU type columns to vm_host
ALTER TABLE vm_host
    ADD COLUMN cpu_mfg SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_arch SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_features VARCHAR(255) NOT NULL DEFAULT '';

-- Add CPU type columns to vm_template
ALTER TABLE vm_template
    ADD COLUMN cpu_mfg SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_arch SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_features VARCHAR(255) NOT NULL DEFAULT '';

-- Add CPU type columns to vm_custom_pricing
ALTER TABLE vm_custom_pricing
    ADD COLUMN cpu_mfg SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_arch SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_features VARCHAR(255) NOT NULL DEFAULT '';

-- Add CPU type columns to vm_custom_template
ALTER TABLE vm_custom_template
    ADD COLUMN cpu_mfg SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_arch SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN cpu_features VARCHAR(255) NOT NULL DEFAULT '';

-- Add SSH credentials to vm_host for running host utilities
ALTER TABLE vm_host
    ADD COLUMN ssh_user VARCHAR(255) NULL,
    ADD COLUMN ssh_key TEXT NULL;
