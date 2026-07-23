-- Add CPU architecture to vm_os_image so images are architecture-aware.
-- Default 1 = x86_64, which is correct for all existing images.
ALTER TABLE vm_os_image
    ADD COLUMN cpu_arch SMALLINT UNSIGNED NOT NULL DEFAULT 1;
