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

    -- Where the data plane listens, stated in full: the address on the route
    -- server that peers send to, and the UDP port the interface listens on.
    --
    -- Not derived from `router.url`, which is a *management* endpoint (an SSH
    -- or REST URL, on a different port and often a different address) and says
    -- nothing about the data plane. Kept as two columns rather than one
    -- `host:port` string because the port is also what LNVPS configures on the
    -- interface, and an address has to be parsed back out of a joined string to
    -- be checked — badly, for IPv6.
    --
    -- A route server carries several interfaces (different regions, different
    -- purposes, a migration from one block to another), so the socket has to be
    -- pinned per pool rather than assumed to be the default port.
    listen_addr VARCHAR(255) NOT NULL,
    listen_port SMALLINT UNSIGNED NOT NULL DEFAULT 51820,

    -- The interface's key material.
    --
    -- LNVPS **generates** this pair and configures the interface itself. A pool
    -- that only recorded somebody else's public key could describe an
    -- interface but never create one, which makes bringing up a route server a
    -- manual job with a database row bolted on afterwards — and leaves no way
    -- to rebuild the interface after the machine is reinstalled.
    --
    -- The private key is stored the same way as every other credential in this
    -- schema (`router.token`, `vm_host.api_token`): encrypted at rest by the
    -- application, base64 inside, because base64 is the form `wg` reads and
    -- writes.
    --
    -- The public key is BINARY(32) for the same reason as `tunnel.peer_pubkey`:
    -- the database collation compares text case-insensitively and base64 is
    -- case-sensitive. It is derived from the private key, so the two can be
    -- checked against each other rather than trusted.
    --
    -- Peers are the other way round — a node generates its own keypair and
    -- presents only the public half, so the private key of a machine LNVPS does
    -- not own is never stored anywhere.
    private_key TEXT NOT NULL,
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

    -- A WireGuard interface listens on *every* local address at its port, on
    -- both Linux and RouterOS, so the port — not the address — is what two
    -- interfaces on one machine collide over. Recording a second pool on the
    -- same port would produce an interface that cannot come up, discovered at
    -- the point somebody's node fails to hand shake.
    UNIQUE KEY uk_tunnel_pool_router_port (router_id, listen_port),

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
