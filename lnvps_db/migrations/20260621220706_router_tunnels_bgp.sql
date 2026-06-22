-- Cached tunnel inventory discovered on routers (GRE/VXLAN/WireGuard)
create table router_tunnel
(
    id          integer unsigned  not null auto_increment primary key,
    router_id   integer unsigned  not null,
    name        varchar(100)      not null,
    kind        smallint unsigned not null,
    local_addr  varchar(255),
    remote_addr varchar(255),
    enabled     bit(1)            not null default 1,
    last_seen   timestamp         not null default current_timestamp,
    constraint fk_router_tunnel_router foreign key (router_id) references router (id),
    constraint uq_router_tunnel_name unique (router_id, name)
);

-- Per-tunnel traffic samples (the canonical "per session" traffic for route servers).
-- BGP sessions have no byte counters; counters come from the tunnel interfaces.
create table router_tunnel_traffic
(
    id          bigint unsigned  not null auto_increment primary key,
    router_id   integer unsigned not null,
    tunnel_name varchar(100)     not null,
    rx_bytes    bigint unsigned  not null default 0,
    tx_bytes    bigint unsigned  not null default 0,
    sampled_at  timestamp        not null default current_timestamp,
    constraint fk_router_tunnel_traffic_router foreign key (router_id) references router (id)
);
create index ix_router_tunnel_traffic_lookup on router_tunnel_traffic (router_id, tunnel_name, sampled_at);

-- Cached BGP session discovery state (no byte counters)
create table router_bgp_session
(
    id                integer unsigned  not null auto_increment primary key,
    router_id         integer unsigned  not null,
    name              varchar(100)      not null,
    peer_ip           varchar(64),
    peer_asn          integer unsigned,
    local_asn         integer unsigned,
    state             varchar(32)       not null,
    prefixes_received bigint unsigned,
    prefixes_sent     bigint unsigned,
    enabled           bit(1)            not null default 1,
    direction         smallint unsigned not null default 0,
    last_seen         timestamp         not null default current_timestamp,
    constraint fk_router_bgp_session_router foreign key (router_id) references router (id),
    constraint uq_router_bgp_session_name unique (router_id, name)
);
