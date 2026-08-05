-- Marketplace node listing fee.
--
-- A node is registered for free and reviewed for free, but an admin cannot
-- approve it until its fee is paid. The fee is per node, so paying once does
-- not let an operator list an unlimited number of machines, and it is
-- non-refundable: it buys the review and the listing, not a deposit LNVPS has
-- to custody and return.
--
-- The fee reuses the subscription machinery rather than adding a second
-- invoice-backed payments table. That is not a shortcut: `subscription_payment`
-- is the only table the Lightning settlement listener resolves against, and its
-- resume cursor is `last_paid_subscription_invoice`. A separate table would
-- have to extend both, and a paid fee that missed either would settle into a
-- "not found" log line and be lost.

-- The default fee for nodes listed under this company, in the company's
-- `base_currency` (same convention as `marketplace_rate`). 0 means no fee is
-- required, which makes the approval gate a no-op — the intended state for a
-- company that does not run a marketplace.
ALTER TABLE company
    ADD COLUMN marketplace_node_fee BIGINT UNSIGNED NOT NULL DEFAULT 0;

-- The line item whose payment covers this node's listing fee.
--
-- Follows the established back-reference direction (`vm.subscription_line_item_id`,
-- `ip_range_subscription.subscription_line_item_id`): the product row points at
-- its line item, never the other way round, so `subscription_line_item` stays
-- free of per-product columns.
--
-- Unique: one line item bills for exactly one node. Without this, two nodes
-- could point at the same paid fee and the per-node gate would silently become
-- a per-operator one — precisely the model that was rejected.
ALTER TABLE marketplace_node
    ADD COLUMN subscription_line_item_id INTEGER UNSIGNED NULL DEFAULT NULL,
    ADD UNIQUE KEY uk_marketplace_node_line_item (subscription_line_item_id),
    ADD CONSTRAINT fk_marketplace_node_line_item
        FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id);
