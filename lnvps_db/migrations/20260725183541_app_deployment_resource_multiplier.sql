-- Per-deployment resource multiplier, so a managed app can be upgraded to a
-- larger size without changing the catalog app itself.
--
-- The deployment's effective footprint is the catalog app's footprint (CPU,
-- memory and storage) multiplied by this value, and its recurring price is the
-- app's `amount` multiplied by it too. 1 = the base app size, which is what
-- every existing deployment is, hence the DEFAULT.
--
-- Upgrade-only by design: PersistentVolumeClaims cannot shrink, so the value is
-- never allowed to decrease (see the API layer, which rejects a lower value).
ALTER TABLE app_deployment
    ADD COLUMN resource_multiplier INTEGER UNSIGNED NOT NULL DEFAULT 1 AFTER cluster_id;
