-- A customer's VPN plan, and the devices registered against it.

-- One VPN plan per account.
--
-- Billing is one flat line item, not one per region: a device works everywhere,
-- so there is nothing per-region to charge for, and nothing to prorate or
-- refund when a customer starts using a different one. What is sold is the
-- number of devices.
--
-- This is the same back-reference shape every other product uses
-- (`vm.subscription_line_item_id`, `ip_range_subscription.subscription_line_item_id`,
-- `marketplace_node.subscription_line_item_id`): the product row points at its
-- line item, so `subscription_line_item` never grows per-product columns and
-- never has to know that a VPN exists.
CREATE TABLE vpn_subscription (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Which service, and therefore which address block and which regions.
    -- This is the one fact that has nowhere else to live: the line item cannot
    -- hold it without learning what a VPN is, and the devices cannot, because
    -- the service is chosen when the plan is bought and before any device
    -- exists.
    vpn_service_id INTEGER UNSIGNED NOT NULL,

    -- The account. Unique, and unlike every other product's back-reference row
    -- this one carries a user at all -- a customer may hold many IP ranges but
    -- exactly one VPN plan, and this is what makes that true rather than
    -- something the application has to remember to check.
    user_id INTEGER UNSIGNED NOT NULL,

    -- The line item billing for this plan.
    --
    -- Stable for the life of the plan. A renewal is a payment against the
    -- existing subscription, which extends its expiry; it does not create a new
    -- line item. So a customer who lapses and comes back renews what they
    -- already have, their devices keep pointing at the same plan, and there is
    -- nothing to repoint.
    subscription_line_item_id INTEGER UNSIGNED NOT NULL,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id),

    -- One plan per account.
    UNIQUE KEY uk_vpn_subscription_user (user_id),

    -- One line item bills for exactly one plan. Without this, two plans could
    -- point at the same payment.
    UNIQUE KEY uk_vpn_subscription_line_item (subscription_line_item_id),

    KEY ix_vpn_subscription_service (vpn_service_id),

    FOREIGN KEY (vpn_service_id) REFERENCES vpn_service (id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id)
);

-- Notice there is no device limit here, and no `active` or `suspended` column.
--
-- The allowance is `vpn_service.default_device_limit`, because one flat price
-- per service is what is sold; a per-plan override would be a number with no
-- price attached to it. Add one here when there is a tier to charge for.
--
-- Whether a plan is paid for is `subscription.is_setup` and
-- `subscription.expires`, reachable through the line item, and copying that
-- here would create a second answer free to disagree with the first.
-- Suspension for non-payment is therefore not a write at all: the planner that
-- decides which peers a route server carries reads the billing state, so a
-- lapsed plan stops being configured on the next reconcile and a paid one comes
-- back without anything having to remember to re-enable it.

-- One registered device: a phone, a laptop.
--
-- The device's key and addresses are not here. A device is a WireGuard peer,
-- and a peer is a `tunnel` row -- the same table that carries a marketplace
-- node's peer, terminated by the same interfaces, planned by the same code and
-- protected by the same unique indexes. That last part is not incidental: one
-- set of indexes across every peer LNVPS terminates is what makes it impossible
-- for a VPN device and a node to be handed the same address, which two separate
-- tables could not prevent.
--
-- What is left here is only what makes it a *device*: which plan it belongs to,
-- which of that plan's slots it occupies, and what the customer calls it. That
-- is `marketplace_node.tunnel_id` again -- the consumer points at the tunnel,
-- and the tunnel stays free of any opinion about what it is for.
--
-- The tunnel it points at has a NULL `pool_id` and `router_id`, which
-- `20260805130000_tunnel.sql` already describes as the case for "a VPN on a
-- router with no pool": a device is a peer on *every* interface terminating its
-- service at once, so pinning it to one would be false.
CREATE TABLE vpn_device (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    vpn_subscription_id INTEGER UNSIGNED NOT NULL,

    -- Which of the plan's device slots this occupies, counted from zero.
    --
    -- This exists to make the device limit unforgeable. Counting the rows and
    -- then inserting is a race that two concurrent registrations win together,
    -- producing a sixth device on a five-device plan; claiming the lowest free
    -- slot below the service's limit against the unique key below means the
    -- database rejects the loser. The upper bound is the allocator's to
    -- enforce, because MariaDB cannot check a column against another table.
    slot TINYINT UNSIGNED NOT NULL,

    -- The customer's label for the device. Not an identifier, and never sent to
    -- a route server -- `tunnel.name` is what the route server sees.
    name VARCHAR(100) NOT NULL,

    -- The peer this device is.
    tunnel_id INTEGER UNSIGNED NOT NULL,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id),

    -- The device limit, enforced where it cannot be raced.
    UNIQUE KEY uk_vpn_device_slot (vpn_subscription_id, slot),

    -- A tunnel terminates exactly one peer, so two devices sharing one would be
    -- two machines answering to a single key and address.
    UNIQUE KEY uk_vpn_device_tunnel (tunnel_id),

    FOREIGN KEY (vpn_subscription_id) REFERENCES vpn_subscription (id),
    -- RESTRICT (the default), matching `marketplace_node.tunnel_id`: a tunnel
    -- still carrying a customer's traffic cannot be deleted out from under it.
    FOREIGN KEY (tunnel_id) REFERENCES tunnel (id)
);
