-- A customer's VPN plan, and the devices registered against it.

-- One VPN plan per account.
--
-- Billing is one flat line item, not one per region: a device works everywhere,
-- so there is nothing per-region to charge for, and nothing to prorate or
-- refund when a customer starts using a different one. What is sold is the
-- number of devices.
CREATE TABLE vpn_subscription (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Which service, and therefore which address block, this plan's devices are
    -- allocated from.
    vpn_service_id INTEGER UNSIGNED NOT NULL,

    -- The account. Unique, and the row is **reused** when a lapsed customer
    -- comes back rather than a second one being created.
    --
    -- MariaDB has no partial unique index, so a plain UNIQUE cannot be narrowed
    -- to "active" rows. Reuse is the better answer anyway: the customer's
    -- devices keep their keys and addresses across the gap, so paying again is
    -- all it takes to be working, with no configs to redistribute.
    user_id INTEGER UNSIGNED NOT NULL,

    -- The line item billing for this plan. Follows the established
    -- back-reference direction (`vm.subscription_line_item_id`,
    -- `marketplace_node.subscription_line_item_id`): the product row points at
    -- its line item, never the reverse, so `subscription_line_item` stays free
    -- of per-product columns.
    --
    -- Repointed, not duplicated, when a lapsed plan is resubscribed: the old
    -- line item stays as billing history and this column names the current one.
    subscription_line_item_id INTEGER UNSIGNED NOT NULL,

    -- How many devices this account may register. Seeded from the service's
    -- default and then owned by this row, because it is the thing being sold:
    -- a larger tier is a write here plus the existing proration path, with no
    -- migration and no second definition of the limit.
    --
    -- Deliberately not `subscription_line_item.configuration`. That column is
    -- upgrade bookkeeping only and explicitly never describes the resource a
    -- line item bills for.
    device_limit TINYINT UNSIGNED NOT NULL DEFAULT 5,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id),

    -- One plan per account, per the reuse rule above.
    UNIQUE KEY uk_vpn_subscription_user (user_id),

    -- One line item bills for exactly one plan. Without this, two plans could
    -- point at the same payment.
    UNIQUE KEY uk_vpn_subscription_line_item (subscription_line_item_id),

    KEY ix_vpn_subscription_service (vpn_service_id),

    FOREIGN KEY (vpn_service_id) REFERENCES vpn_service (id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id)
);

-- Notice there is no `active` or `suspended` column here. Whether a plan is
-- paid for is `subscription.is_setup` and `subscription.expires`, reachable
-- through the line item, and copying that here would create a second answer
-- free to disagree with the first. Suspension for non-payment is therefore not
-- a write at all: the planner that decides which peers a route server carries
-- reads the billing state, so a lapsed plan stops being configured on the next
-- reconcile and a paid one comes back without anything having to remember to
-- re-enable it.

-- One registered device: a phone, a laptop.
--
-- Not a `tunnel` row. That table pins a peer to one route server through
-- `(pool_id, router_id)` and makes its key and addresses globally unique, all
-- of which is correct for a marketplace node terminated in exactly one place
-- and wrong for a device that is a peer on every route server at once.
-- `20260805130000_tunnel.sql` says a tunnel's purpose is decided by whichever
-- table links to it; this links differently enough to be its own table.
CREATE TABLE vpn_device (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    vpn_subscription_id INTEGER UNSIGNED NOT NULL,

    -- Which of the plan's device slots this occupies, counted from zero.
    --
    -- This exists to make the device limit unforgeable. Counting the rows and
    -- then inserting is a race that two concurrent registrations win together,
    -- producing a sixth device on a five-device plan; claiming the lowest free
    -- slot below `device_limit` against the unique key below means the database
    -- rejects the loser. The upper bound is the allocator's to enforce, because
    -- MariaDB cannot check a column against another table's value.
    slot TINYINT UNSIGNED NOT NULL,

    -- The customer's label for the device. Not an identifier, and never sent to
    -- a route server.
    name VARCHAR(100) NOT NULL,

    -- The device's public key. The customer generates the pair and presents
    -- only this half, so a private key belonging to a machine LNVPS does not
    -- own never exists here. NOT NULL because, unlike a tunnel, a device is
    -- created *by* presenting a key; there is no earlier state to model.
    --
    -- BINARY(32) (the raw key) rather than its base64 text, for the same reason
    -- as `tunnel.peer_pubkey`: the database collation compares
    -- case-insensitively while base64 is case-sensitive, so a text column would
    -- let two distinct keys collide in the unique index and let a lookup by key
    -- match a different customer's device.
    peer_pubkey BINARY(32) NOT NULL,

    -- The device's inner addresses, carved from `vpn_service`, as CIDR host
    -- prefixes. The same values on every route server: that is the whole point.
    --
    -- Unique because two devices sharing an inner address delivers one
    -- customer's traffic to another. Unique across services as well as within
    -- one, which is the stronger constraint and costs nothing while the blocks
    -- do not overlap.
    address4 VARCHAR(64) NULL DEFAULT NULL,
    address6 VARCHAR(64) NULL DEFAULT NULL,

    -- Whether the customer wants this device configured. Their own switch, not
    -- a billing one: see the note above about suspension.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id),

    -- The device limit, enforced where it cannot be raced.
    UNIQUE KEY uk_vpn_device_slot (vpn_subscription_id, slot),

    UNIQUE KEY uk_vpn_device_pubkey (peer_pubkey),
    UNIQUE KEY uk_vpn_device_address4 (address4),
    UNIQUE KEY uk_vpn_device_address6 (address6),

    FOREIGN KEY (vpn_subscription_id) REFERENCES vpn_subscription (id)
);
