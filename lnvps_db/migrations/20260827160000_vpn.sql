-- Consumer VPN: services, plans, devices, and what is routed behind a peer.
--
-- One file because it is one change. None of these tables is useful without the
-- others, and a reader asking why `vpn_device` has no key or address column
-- ends up in `tunnel` and `tunnel_route` regardless.

-- What is routed behind a tunnel's peer.
--
-- A WireGuard peer's `AllowedIPs` is two things at once: the routing table for
-- that peer, and the anti-spoof boundary, since an inbound packet whose source
-- is not listed is dropped. It is therefore the peer's own inner addresses plus
-- whatever prefixes live behind it.
--
-- Until now the planner worked out "behind it" by asking whether a marketplace
-- node claimed the tunnel, then finding that node's host, then the VMs on it,
-- then their IP assignments. That is marketplace knowledge inside the generic
-- tunnel planner, and it made the planner unusable for any other kind of peer:
-- a consumer VPN device has nothing behind it, and asking the marketplace about
-- it is both wrong and a query per peer per reconcile.
--
-- So the prefixes are recorded here and the planner just reads them. It no
-- longer knows, or needs to know, what a tunnel is for -- the same rule the
-- `tunnel` table itself follows.
--
-- This is a **cache of desired state**, not an authority. Whoever owns a
-- tunnel's purpose recomputes its routes from the source of truth before each
-- reconcile: for a marketplace node that is the guest addresses currently
-- assigned to the VMs on its host. Recomputing rather than writing at each
-- point a guest address changes is deliberate: a missed write would silently
-- black-hole a customer's VM until somebody noticed, whereas a recompute is
-- self-correcting in the same way the rest of the reconcile is.
CREATE TABLE tunnel_route (
    tunnel_id INTEGER UNSIGNED NOT NULL,

    -- A prefix routed down this peer, as CIDR. Host prefixes (`/32`, `/128`)
    -- for individual guest addresses, but nothing here requires that: a peer
    -- carrying a whole delegated block is the same statement.
    prefix VARCHAR(64) NOT NULL,

    created DATETIME NOT NULL DEFAULT NOW(),

    -- One row per prefix per tunnel. Stating the same route twice would be
    -- pushed twice and compared twice for no gain.
    PRIMARY KEY (tunnel_id, prefix),

    -- Deleting a tunnel takes its routes with it. Unlike the tunnel itself
    -- these are derived, so there is nothing here worth keeping once the peer
    -- they describe is gone.
    FOREIGN KEY (tunnel_id) REFERENCES tunnel (id) ON DELETE CASCADE
);

-- The address space a VPN device lives in, and which interfaces terminate it.
--
-- A marketplace node's tunnel is terminated by exactly one route server, which
-- is why `tunnel` pins `(pool_id, router_id)` and why its inner addresses are
-- carved out of that one pool's `cidr4`/`cidr6`. A consumer VPN device is the
-- opposite: one keypair and one inner address that are valid on *every* region
-- at once, with the region chosen client-side by pointing at a different
-- endpoint and server key. That is what makes switching regions instant and
-- stateless on our side.
--
-- So a device's address cannot come from `tunnel_pool`. Two pools carving from
-- their own blocks would hand the same device two different addresses, and a
-- device that is `10.64.0.7` in Dublin and `10.71.3.2` in Amsterdam is two
-- devices wearing one name. The block has to live in exactly one place, above
-- the pools, and that place is this table.
--
-- A table rather than a singleton row or a config key: a singleton needs a
-- "there is exactly one of these" invariant that SQL cannot express, and this
-- shape costs nothing extra while leaving room for a second service (a business
-- tier on its own route servers, a separate block after a renumber) without a
-- migration.
CREATE TABLE vpn_service (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Admin label. Not an identifier.
    name VARCHAR(100) NOT NULL,

    -- The selling company. Every other product takes this from its region
    -- (`app` via `region.company_id`, a VM via its host's), but a VPN plan has
    -- no region: a device works in all of them, which is the point. So the
    -- service names the company directly, and it is what the subscription,
    -- its tax treatment and its invoice are booked against.
    company_id INTEGER UNSIGNED NOT NULL,

    -- What a plan on this service costs, in the same shape as `app`: the
    -- recurring amount, its currency, and how long one interval is. Stored here
    -- rather than on `vpn_subscription` so a price change applies to new
    -- customers without rewriting anybody's existing plan, which is how the
    -- catalog tables already behave.
    --
    -- One flat price per service, not one per device tier. A tier would need a
    -- price of its own, and there is nothing to sell it against yet; see
    -- `default_device_limit` below.
    amount BIGINT UNSIGNED NOT NULL DEFAULT 0,
    currency VARCHAR(4) NOT NULL DEFAULT 'EUR',
    interval_amount INTEGER UNSIGNED NOT NULL DEFAULT 1,
    interval_type SMALLINT UNSIGNED NOT NULL DEFAULT 1, -- 0=Day, 1=Month, 2=Year
    setup_amount BIGINT UNSIGNED NOT NULL DEFAULT 0,

    -- There is no address block here. A device is addressed from the block on
    -- the interfaces that terminate it, like every other peer: `tunnel_pool`
    -- already means "the block this interface's peers come from", and a second
    -- column meaning the same thing in another table is one more place for the
    -- answer to differ.
    --
    -- What is specific to a VPN is that every interface on the service shares
    -- one block, so a device keeps one address in every region. That is
    -- enforced on `vpn_service_pool`: a pool cannot be linked to a service
    -- whose other pools carry a different block, and a linked pool's block
    -- cannot be edited away from theirs.

    -- Resolvers handed to clients in the generated config, comma-separated.
    --
    -- A device on this service has a private inner address and reaches the
    -- internet through the route server's own NAT, so it has no resolver of its
    -- own to fall back on: without this the client keeps using whatever its
    -- local network gave it, which leaks every lookup around the tunnel.
    dns VARCHAR(255) NULL DEFAULT NULL,

    -- How many devices an account on this service may register.
    --
    -- Per service, not per plan, because one flat price per service is what is
    -- sold and a per-plan allowance would be a number with no price attached.
    -- A tier is a second service, or a column on `vpn_subscription` once there
    -- is something to charge for it.
    default_device_limit TINYINT UNSIGNED NOT NULL DEFAULT 5,

    -- Whether new subscriptions and devices may be created here. Disabling
    -- stops sales without touching what is already allocated or configured.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id),

    KEY ix_vpn_service_company (company_id),


    FOREIGN KEY (company_id) REFERENCES company (id)
);

-- Which interfaces terminate a service.
--
-- The link lives here and not as a `vpn_service_id` column on `tunnel_pool`.
-- A pool is an opaque managed WireGuard interface on a route server: a socket,
-- a keypair, an MTU. It is not concerned with what is carried over it, exactly
-- as `tunnel` has no `purpose` column and is pointed *at* by
-- `marketplace_node.tunnel_id` rather than describing itself. A column on
-- `tunnel_pool` would put VPN vocabulary in a table that has nothing to do with
-- VPNs, and the next consumer would add a second one beside it.
--
-- `tunnel_pool_id` is the primary key rather than a composite: an interface
-- terminates at most one service, because its peer set has to come from
-- somewhere definite. Two services on one interface would be two peer sets
-- reconciling against each other, each removing the other's peers as unclaimed.
--
-- A pool with no row here is a marketplace pool and behaves exactly as it did
-- before this migration existed.
CREATE TABLE vpn_service_pool (
    vpn_service_id INTEGER UNSIGNED NOT NULL,
    tunnel_pool_id INTEGER UNSIGNED NOT NULL,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tunnel_pool_id),
    KEY ix_vpn_service_pool_service (vpn_service_id),

    -- Both sides cascade, because this row is pure association: it owns
    -- nothing, and nothing is identified by it. Decommissioning an interface
    -- should drop the link rather than be refused by it, and the guard against
    -- deleting a service out from under paying customers belongs on
    -- `vpn_subscription`, which is the row that represents them.
    FOREIGN KEY (vpn_service_id) REFERENCES vpn_service (id) ON DELETE CASCADE,
    FOREIGN KEY (tunnel_pool_id) REFERENCES tunnel_pool (id) ON DELETE CASCADE
);

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

    -- RESTRICT, deliberately: a service with subscribers cannot be deleted.
    -- Taking one off sale is `enabled = 0`, which stops new plans without
    -- touching the ones already paid for.
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

    -- RESTRICT on both, deliberately.
    --
    -- A plan cannot be deleted while it has devices, because this row is the
    -- only thing that knows which `tunnel` belongs to the customer: cascading
    -- it away would leave that tunnel orphaned, invisible to every query that
    -- reaches it through this table, and still holding a public key. Removing
    -- a device deletes both, in `delete_vpn_device`, which is a transaction
    -- because a foreign key cannot express ownership in that direction.
    --
    -- The tunnel side matches `marketplace_node.tunnel_id`: a tunnel still
    -- carrying a customer's traffic cannot be deleted out from under it.
    FOREIGN KEY (vpn_subscription_id) REFERENCES vpn_subscription (id),
    FOREIGN KEY (tunnel_id) REFERENCES tunnel (id)
);
