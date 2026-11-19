-- An add-on line item belongs to another line item on the same subscription
-- (e.g. paid VM snapshots on a VM's line item). When the parent's resource is
-- deleted its add-ons stop billing with it, and their unused time is refunded
-- with it. NULL = a standalone product.
ALTER TABLE subscription_line_item
    ADD COLUMN parent_line_item_id INTEGER UNSIGNED NULL DEFAULT NULL,
    ADD CONSTRAINT fk_line_item_parent FOREIGN KEY (parent_line_item_id)
        REFERENCES subscription_line_item (id) ON DELETE CASCADE;
