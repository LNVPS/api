-- Per-peer traffic reported by route servers, and the concurrency rule it pays
-- for.
--
-- A device holds one address that works in every region, which is the whole
-- point: switching region is a client-side choice and nothing on the server
-- side moves. The cost of that is that the same key works in every region *at
-- once*. Five devices was meant to be the cap on simultaneous connections, and
-- one key usable in ten regions turns it into fifty.
--
-- It cannot be stopped at connect time. Both route servers hold the peer, and
-- neither can ask whether the key is live elsewhere before answering a
-- handshake: the kernel offers no hook for that. What it can be is detected,
-- within one reporting cycle, from the counters the route servers already have.

-- The previous raw counter reading for one peer on one interface, which is what
-- a delta is measured against.
--
-- Keyed on the pair, not on the tunnel: a VPN device is a peer on *every*
-- interface of its service at once, and which of them carried the bytes is the
-- entire question here. A marketplace node has one row because it has one
-- interface, and nothing has to special-case that.
--
-- Deliberately separate from the daily rows below, exactly as
-- `vm_traffic_sample` is from `vm_traffic_daily`: this is transient state
-- overwritten on every report, while those are history.
create table tunnel_traffic_sample
(
    tunnel_id      integer unsigned not null,
    tunnel_pool_id integer unsigned not null,
    last_rx_bytes  bigint unsigned  not null default 0,
    last_tx_bytes  bigint unsigned  not null default 0,
    -- Seconds since this peer last completed a handshake at the time of the
    -- reading, or NULL for never. Not used to detect concurrency -- a client
    -- that has switched away leaves a handshake seconds old behind it, so this
    -- fires on every honest region switch -- but it is what tells "configured"
    -- from "working" when a customer says a region is broken.
    last_handshake_secs bigint unsigned null,
    -- Whether this reading showed traffic moving since the one before it. This
    -- is the concurrency signal: a switched-away region has a fresh handshake
    -- and frozen counters, while genuine simultaneous use has bytes advancing
    -- in two regions in the same interval.
    active         boolean          not null default 0,
    -- How many consecutive reports have shown it active. Sustained rather than
    -- instantaneous, because a client that switches region mid-interval
    -- legitimately moves bytes in both within one reading.
    active_streak  integer unsigned not null default 0,
    sampled        timestamp        not null default current_timestamp,
    primary key (tunnel_id, tunnel_pool_id),
    constraint fk_tunnel_traffic_sample_tunnel foreign key (tunnel_id)
        references tunnel (id) on delete cascade,
    constraint fk_tunnel_traffic_sample_pool foreign key (tunnel_pool_id)
        references tunnel_pool (id) on delete cascade
);

-- One row per peer per UTC day, accumulated in place.
--
-- Summed across regions rather than kept per interface: this answers "how much
-- did this customer use", which is one number regardless of where they
-- connected. Per-region load is a different question, and
-- `tunnel_traffic_sample` already carries what it needs.
--
-- Bytes, not GB, for the same reason as `vm_traffic_daily`: rounding each
-- sample would lose almost all of them.
create table tunnel_traffic_daily
(
    tunnel_id integer unsigned not null,
    day       date             not null,
    bytes_in  bigint unsigned  not null default 0,
    bytes_out bigint unsigned  not null default 0,
    updated   timestamp        not null default current_timestamp on update current_timestamp,
    primary key (tunnel_id, day),
    constraint fk_tunnel_traffic_daily_tunnel foreign key (tunnel_id)
        references tunnel (id) on delete cascade
);

create index ix_tunnel_traffic_daily_day on tunnel_traffic_daily (day);

-- A peer that is not to be published to one interface for now.
--
-- What enforcement looks like, given it cannot happen at connect time: the
-- region carrying the most traffic keeps the peer, the others stop being told
-- about it, and their route servers drop it within a round trip.
--
-- `until` is not optional, and that is the important part. Suppressing a peer
-- forever would mean the customer could never use that region again: they would
-- dial it, the key would not be there, the handshake would fail, and a failed
-- handshake produces no signal that could ever restore it. The same deadlock
-- makes "publish the peer only to the region it was last seen in" unworkable,
-- which is why this is a temporary hold rather than a permanent placement.
--
-- With an expiry, an account sharing one key across regions gets one detection
-- window of multi-region use per cooldown and is otherwise cut back to one, and
-- a customer who simply switched region never notices, because one client
-- cannot move bytes in two places at once.
create table tunnel_suppression
(
    tunnel_id      integer unsigned not null,
    tunnel_pool_id integer unsigned not null,
    -- When the peer becomes publishable here again.
    until          timestamp        not null,
    -- Why, for the support conversation that starts with "my VPN dropped".
    reason         varchar(200)     not null,
    created        timestamp        not null default current_timestamp,
    primary key (tunnel_id, tunnel_pool_id),
    constraint fk_tunnel_suppression_tunnel foreign key (tunnel_id)
        references tunnel (id) on delete cascade,
    constraint fk_tunnel_suppression_pool foreign key (tunnel_pool_id)
        references tunnel_pool (id) on delete cascade
);

-- The planner reads this per pool on every document build, so it is indexed the
-- way it is read rather than the way it is written.
create index ix_tunnel_suppression_pool on tunnel_suppression (tunnel_pool_id, until);
