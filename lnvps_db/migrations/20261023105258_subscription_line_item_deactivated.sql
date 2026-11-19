-- A line item can stop billing on its own, without ending the whole
-- subscription: deleting one VM from a subscription that also carries other
-- products (IP ranges, apps, ...) deactivates just that VM's line item.
-- NULL = active. Renewals skip deactivated items; the subscription itself is
-- only deactivated once no active line item remains.
ALTER TABLE subscription_line_item
    ADD COLUMN deactivated_at TIMESTAMP NULL DEFAULT NULL;
