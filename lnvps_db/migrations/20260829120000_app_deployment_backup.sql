-- Backups of an app deployment's data (work/app-deployments.md increment 6).
--
-- One row per artifact, not per run: two services in one deployment back up
-- with different images and different volumes, so a run fans out to one
-- Kubernetes Job (and one uploaded object) per service. `run_id` groups the
-- artifacts that belong to the same point in time.
--
-- `object_key` is server-derived and never client-supplied; the customer API
-- addresses a backup only by `id`.
CREATE TABLE app_deployment_backup
(
    id            INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT PRIMARY KEY,
    deployment_id INTEGER UNSIGNED  NOT NULL,
    -- Groups the artifacts captured by one run. UUID text so the operator can
    -- mint it without a round-trip and use it in the object key.
    run_id        VARCHAR(36)       NOT NULL,
    -- Compose service this artifact came from.
    service       VARCHAR(64)       NOT NULL,
    -- 0 = command (logical dump), 1 = volume (raw tar).
    method        SMALLINT UNSIGNED NOT NULL,
    -- Download filename shown to the customer.
    artifact      VARCHAR(128)      NOT NULL,
    -- Object storage key; NULL until the run has been given one.
    object_key    VARCHAR(255)      NULL     DEFAULT NULL,
    -- Uploaded size, once observed.
    size_bytes    BIGINT UNSIGNED   NULL     DEFAULT NULL,
    -- 0 = pending, 1 = running, 2 = completed, 3 = failed.
    state         SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    -- Failure detail, or any note the operator wants to surface.
    message       VARCHAR(500)      NULL     DEFAULT NULL,
    -- 1 when this run was started by the app's schedule rather than by the
    -- customer. Retention prunes both, but only scheduled runs answer "when
    -- was the last automatic backup".
    scheduled     BIT(1)            NOT NULL DEFAULT 0,
    created       TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started       TIMESTAMP         NULL     DEFAULT NULL,
    completed     TIMESTAMP         NULL     DEFAULT NULL,
    -- Soft delete: the row outlives the object so a pruned or customer-deleted
    -- backup cannot be re-listed while its object is still being removed.
    deleted       BIT(1)            NOT NULL DEFAULT 0,
    CONSTRAINT fk_app_deployment_backup_deployment FOREIGN KEY (deployment_id)
        REFERENCES app_deployment (id) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

-- Listing a deployment's backups newest-first is the only read the API makes.
CREATE INDEX ix_app_deployment_backup_deployment ON app_deployment_backup (deployment_id, created);
-- The operator sweeps for work by state across every deployment on its cluster.
CREATE INDEX ix_app_deployment_backup_state ON app_deployment_backup (state);
CREATE INDEX ix_app_deployment_backup_run ON app_deployment_backup (run_id);
