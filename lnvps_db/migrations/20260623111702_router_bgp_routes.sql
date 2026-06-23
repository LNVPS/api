-- Cached BGP route table state for routers: prefixes the router originates/announces
-- plus a detected default route. Refreshed by the worker; admin reads this cache.
create table router_bgp_route
(
    id         integer unsigned not null auto_increment primary key,
    router_id  integer unsigned not null,
    prefix     varchar(64)      not null,
    next_hop   varchar(64),
    is_default bit(1)           not null default 0,
    last_seen  timestamp        not null default current_timestamp,
    constraint fk_router_bgp_route_router foreign key (router_id) references router (id),
    constraint uq_router_bgp_route unique (router_id, prefix)
);
