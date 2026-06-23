-- A router's route table can hold multiple routes to the same prefix (differing
-- next-hops / metrics / ECMP), so prefix is not unique per router. Drop the
-- unique constraint; the route cache is now refreshed by replacing the whole
-- per-router snapshot rather than upserting by prefix.
--
-- The unique index (router_id, prefix) also serves the fk_router_bgp_route_router
-- foreign key (router_id is its leftmost column). InnoDB will not drop an index
-- still required by a FK, so the replacement router_id index MUST be created
-- first, then the unique index can be dropped.
create index ix_router_bgp_route_router on router_bgp_route (router_id);
alter table router_bgp_route drop index uq_router_bgp_route;
