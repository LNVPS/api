-- Per-service and per-volume usage, beside the namespace totals already on
-- app_deployment.
--
-- The totals answer "am I outgrowing this size"; they cannot answer "which
-- container is at its limit" or "which volume is full", because limits are
-- enforced per container and per PVC, not per namespace. Those are the failures
-- that take an app down, so the breakdown is stored with the same keys the
-- limits use: the compose service name, and (service, volume name).
--
-- Rewritten wholesale on each observation rather than appended: this is a
-- current reading, not a history, and a service or volume removed from the
-- compose must stop being reported rather than linger at its last value.
CREATE TABLE app_deployment_service_usage
(
    deployment_id INTEGER UNSIGNED NOT NULL,
    service       VARCHAR(64)      NOT NULL,
    cpu_milli     INTEGER UNSIGNED NOT NULL,
    memory_bytes  BIGINT UNSIGNED  NOT NULL,
    collected     TIMESTAMP        NOT NULL,
    PRIMARY KEY (deployment_id, service),
    CONSTRAINT fk_service_usage_deployment FOREIGN KEY (deployment_id)
        REFERENCES app_deployment (id) ON DELETE CASCADE
);

-- Volume usage is keyed by (service, name) because that pair is the PVC the
-- operator creates, and the size limit is on that PVC.
CREATE TABLE app_deployment_volume_usage
(
    deployment_id INTEGER UNSIGNED NOT NULL,
    service       VARCHAR(64)      NOT NULL,
    name          VARCHAR(64)      NOT NULL,
    storage_bytes BIGINT UNSIGNED  NOT NULL,
    collected     TIMESTAMP        NOT NULL,
    PRIMARY KEY (deployment_id, service, name),
    CONSTRAINT fk_volume_usage_deployment FOREIGN KEY (deployment_id)
        REFERENCES app_deployment (id) ON DELETE CASCADE
);
