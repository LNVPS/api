-- Where tunnel inner addresses come from.
--
-- `tunnel` (2026-08) records what was assigned to whom, but nothing said what
-- there was to assign *from*: `router` carries no region, no endpoint, no
-- server public key and no address block, so an allocator had nothing to pick
-- or carve. This table supplies all four, and is the tunnel equivalent of
-- `ip_range` for guest addresses — same shape, same job, and the same
-- `allocate_subnet` carving both.
--
-- A pool is deliberately *not* a column set on `router`. A route server can
-- terminate more than one WireGuard interface (different regions, different
-- purposes, a migration from one block to another), and a peer belongs to an
-- interface, not to a machine. Columns on `router` would force one pool per
-- router and make "which interface is this peer on?" unanswerable.

CREATE TABLE tunnel_pool (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    -- The route server terminating peers allocated from this pool.
    router_id INTEGER UNSIGNED NOT NULL,

    -- The region whose nodes this pool serves. A node's region lives on its
    -- backing `vm_host`, and its guest addresses come from an `ip_range` in
    -- that region, so the tunnel carrying that traffic has to be terminated by
    -- a route server that serves the same region — otherwise the guest's own
    -- IP is routed to the wrong place.
    region_id INTEGER UNSIGNED NOT NULL,

    -- Admin label. Not an identifier.
    name VARCHAR(100) NOT NULL,

    -- The WireGuard interface on the route server that peers are added to.
    -- Correlates with `router_tunnel.name` once the interface is observed.
    interface VARCHAR(64) NOT NULL,

    -- What a peer dials: `host:port`. Held here rather than derived from
    -- `router.url`, which is a *management* endpoint (an SSH or REST URL, often
    -- on a different address and always on a different port) and says nothing
    -- about where the data plane listens.
    endpoint VARCHAR(255) NOT NULL,

    -- The interface's public key, handed to peers so they can configure their
    -- end. BINARY(32) for the same reason as `tunnel.peer_pubkey`: the database
    -- collation compares text case-insensitively and base64 is case-sensitive.
    --
    -- The private half is on the route server and is never stored here.
    public_key BINARY(32) NOT NULL,

    -- Inner address blocks that point-to-point links are carved out of. Both
    -- nullable so a pool can be v4-only or v6-only, but a pool with neither
    -- can allocate nothing — enforced below rather than left to the allocator
    -- to discover at the worst moment.
    cidr4 VARCHAR(64) NULL DEFAULT NULL,
    cidr6 VARCHAR(64) NULL DEFAULT NULL,

    -- Persistent keepalive handed to peers, in seconds. NULL leaves it to the
    -- peer. Nodes dial out from behind NAT and normally want one set.
    keepalive SMALLINT UNSIGNED NULL DEFAULT NULL,

    -- MTU peers should use inside the tunnel. WireGuard's overhead means the
    -- guest MTU is not 1500, and getting it wrong produces the classic
    -- "small requests work, large ones hang" failure rather than an outage
    -- anybody notices quickly.
    mtu SMALLINT UNSIGNED NOT NULL DEFAULT 1420,

    -- Whether new allocations may be made from this pool. Disabling stops new
    -- placements without touching the tunnels already carved out of it.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created DATETIME NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id),

    -- One interface on one router is one pool. Two pools sharing an interface
    -- would each carve addresses the other does not know about, onto the same
    -- link.
    UNIQUE KEY uk_tunnel_pool_router_interface (router_id, interface),

    -- Referenced by the composite foreign key on `tunnel` below, which is what
    -- keeps a tunnel's router and its pool's router from disagreeing.
    UNIQUE KEY uk_tunnel_pool_id_router (id, router_id),

    KEY ix_tunnel_pool_region (region_id),

    CONSTRAINT ck_tunnel_pool_has_a_block CHECK (cidr4 IS NOT NULL OR cidr6 IS NOT NULL),

    FOREIGN KEY (router_id) REFERENCES router (id),
    FOREIGN KEY (region_id) REFERENCES region (id)
);

-- Which pool a tunnel's addresses were carved from, and therefore which
-- interface its peer belongs to.
--
-- NULL for a tunnel allocated outside a pool — a hand-configured peering, or a
-- customer VPN on a router with no pool — which is why `tunnel.router_id`
-- stays and is not replaced by this column.
--
-- The foreign key is composite, `(pool_id, router_id)` against the pool's
-- `(id, router_id)`, so the two copies of "which router" cannot drift: pointing
-- a tunnel at a pool on a different router is rejected by the database rather
-- than by whichever code path happens to check. A NULL `pool_id` (or
-- `router_id`) skips the constraint entirely, which is exactly the pool-less
-- case above.
ALTER TABLE tunnel
    ADD COLUMN pool_id INTEGER UNSIGNED NULL DEFAULT NULL,
    ADD KEY ix_tunnel_pool (pool_id),
    ADD CONSTRAINT fk_tunnel_pool
        FOREIGN KEY (pool_id, router_id) REFERENCES tunnel_pool (id, router_id);
