-- A VPN device is one peer row per interface it is carried on.
--
-- It was one `tunnel` row with `pool_id` NULL, on the reasoning that a device
-- belongs to no single interface: it holds one key and one address that work in
-- every region at once. That is true of the *device*, but a `tunnel` row does
-- not mean a device. It means **a peer on an interface**, which is why it
-- carries `pool_id`, `router_id` and a composite foreign key tying the two
-- together. A device carried on three interfaces is three peers, and modelling
-- it as one row left `pool_id` NULL on a column whose entire purpose is saying
-- which interface a peer belongs to.
--
-- Everything that asks a pool what it carries was wrong as a result.
-- `links_used` reported an empty interface however many customers were on it,
-- and the guard that stops a block being shrunk out from under live allocations
-- saw nothing to protect. Both had to special-case VPN pools, or be wrong.
--
-- There is no data migration. The one device in existence is being re-created.

-- ---------------------------------------------------------------------------
-- Peer identity is unique per interface, not globally.
--
-- These were global, which forbade exactly the shape above: one key, or one
-- address, could exist only once across every route server LNVPS runs.
--
-- Global was never the right scope. An address has to be unique within the
-- interface that routes it; two customers on 10.21.74.165 behind different
-- route servers, each masquerading its own traffic, is ordinary RFC1918 and
-- concerns nobody. The same is true of a key: WireGuard identifies a peer
-- within an interface.
--
-- What is given up is a backstop. With a global index, two services configured
-- with overlapping blocks collided on insert and failed loudly, because the
-- allocator only ever looks at its own service's addresses. Now they would not.
-- That check belongs where the mistake is made -- linking a pool to a service --
-- rather than in an index that also forbids the normal case.
ALTER TABLE tunnel
    DROP INDEX uk_tunnel_peer_pubkey,
    DROP INDEX uk_tunnel_address4,
    DROP INDEX uk_tunnel_address6,
    ADD UNIQUE KEY uk_tunnel_pool_peer_pubkey (pool_id, peer_pubkey),
    ADD UNIQUE KEY uk_tunnel_pool_address4 (pool_id, address4),
    ADD UNIQUE KEY uk_tunnel_pool_address6 (pool_id, address6);

-- ---------------------------------------------------------------------------
-- A device's peers.
--
-- The link points from the device at its tunnels, never the reverse: a tunnel
-- does not know what it is for, which is what lets one table carry marketplace
-- links, hand-configured peerings and VPN devices without knowing the
-- difference. Same direction as `marketplace_node.tunnel_id`.
--
-- One row per (device, interface). `uk_vpn_device_tunnel` keeps a tunnel from
-- being claimed by two devices; the primary key keeps a device from being
-- linked to one interface twice.
CREATE TABLE vpn_device_tunnel (
    vpn_device_id INTEGER UNSIGNED NOT NULL,
    tunnel_id INTEGER UNSIGNED NOT NULL,

    PRIMARY KEY (vpn_device_id, tunnel_id),
    UNIQUE KEY uk_vpn_device_tunnel (tunnel_id),

    -- Deleting a device takes its link rows with it. The tunnels themselves are
    -- deleted explicitly and in order, because `tunnel` is what the route
    -- server is told about and orphaning one leaves a key configured on a
    -- machine after LNVPS has forgotten it.
    CONSTRAINT fk_vpn_device_tunnel_device FOREIGN KEY (vpn_device_id)
        REFERENCES vpn_device (id) ON DELETE CASCADE,
    CONSTRAINT fk_vpn_device_tunnel_tunnel FOREIGN KEY (tunnel_id)
        REFERENCES tunnel (id) ON DELETE RESTRICT
);

-- Every device's peers go with the old column; the one device that existed is
-- being re-created rather than migrated.
--
-- Staged, and in this order, because `vpn_device.tunnel_id` is RESTRICT: the
-- tunnels cannot be deleted while the devices still point at them, and once the
-- devices are gone there is nothing left to say which tunnels were theirs.
CREATE TEMPORARY TABLE _vpn_device_tunnels AS
    SELECT tunnel_id FROM vpn_device;

DELETE FROM vpn_device;

DELETE FROM tunnel WHERE id IN (SELECT tunnel_id FROM _vpn_device_tunnels);

DROP TEMPORARY TABLE _vpn_device_tunnels;

-- The constraint is `2` because the original migration wrote a bare
-- FOREIGN KEY and MariaDB numbers them per table. Naming them would have made
-- this line say what it means.
ALTER TABLE vpn_device
    DROP FOREIGN KEY `2`,
    DROP INDEX uk_vpn_device_tunnel,
    DROP COLUMN tunnel_id;
