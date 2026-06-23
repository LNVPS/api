-- A router's route table can hold multiple routes to the same prefix (differing
-- next-hops / metrics / ECMP), so prefix is not unique per router. Drop the
-- unique constraint; the route cache is now refreshed by replacing the whole
-- per-router snapshot rather than upserting by prefix.
alter table router_bgp_route drop index uq_router_bgp_route;
-- The dropped unique index also served as the (router_id, ...) lookup index, so
-- add a plain index for the list-by-router query.
create index ix_router_bgp_route_router on router_bgp_route (router_id);
