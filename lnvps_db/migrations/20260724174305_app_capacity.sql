-- Resource footprint of a catalog app (computed from its compose: sum of
-- service CPU/memory requests + volume sizes), stored denormalized so cluster
-- capacity accounting is a cheap sum over deployments.
ALTER TABLE app
    ADD COLUMN cpu_milli     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN memory_bytes  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN storage_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0;

-- Static per-cluster capacity (admin-configured; 1:1, no overcommit). A cluster
-- with 0 capacity accepts no deployments until an admin sets real values.
ALTER TABLE app_cluster
    ADD COLUMN capacity_cpu_milli     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN capacity_memory_bytes  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN capacity_storage_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0;
