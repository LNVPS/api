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

-- A pool no longer has to carve its peers out of a block of its own.
--
-- `ck_tunnel_pool_has_a_block` was right while every pool handed out
-- point-to-point links from its own `cidr4`/`cidr6`. An interface terminating a
-- consumer VPN does not: its peers are addressed from the VPN service's block,
-- which is one block shared by every region so that a device keeps one address
-- everywhere. Such a pool would have had to carry a block it never reads, which
-- is worse than carrying none -- a column that must be set and must be ignored
-- is one somebody will eventually believe.
--
-- The check cannot simply be widened to "a block or a service", because the
-- service is in another table and MariaDB cannot see it. So it is dropped, and
-- the invariant it protected moves to where it can be stated in full: an
-- allocator asked to carve a link from a pool with no block fails, naming the
-- pool, instead of quietly returning a tunnel with no addresses.
ALTER TABLE tunnel_pool DROP CONSTRAINT ck_tunnel_pool_has_a_block;
