-- Free-form admin-only notes about a VM (not exposed to the customer).
ALTER TABLE vm
    ADD COLUMN admin_notes TEXT NULL;
