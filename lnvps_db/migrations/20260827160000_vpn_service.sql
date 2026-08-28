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

    -- The blocks device addresses are carved from, shared by every interface
    -- that terminates this service. Both nullable so a service can be v4-only
    -- or v6-only, but one with neither can allocate nothing, which is enforced
    -- below rather than left for the allocator to discover when a customer is
    -- waiting.
    --
    -- Size these generously. At the default five devices per account a /16 is
    -- roughly 13k customers, and widening the block later is an edit here that
    -- leaves every existing allocation where it is, whereas running out is not.
    device_cidr4 VARCHAR(64) NULL DEFAULT NULL,
    device_cidr6 VARCHAR(64) NULL DEFAULT NULL,

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

    CONSTRAINT ck_vpn_service_has_a_block
        CHECK (device_cidr4 IS NOT NULL OR device_cidr6 IS NOT NULL),

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

    FOREIGN KEY (vpn_service_id) REFERENCES vpn_service (id),
    FOREIGN KEY (tunnel_pool_id) REFERENCES tunnel_pool (id)
);
