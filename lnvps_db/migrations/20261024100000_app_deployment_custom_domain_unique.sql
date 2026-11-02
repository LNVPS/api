UPDATE app_deployment d
    JOIN app_deployment keep
        ON keep.custom_domain = d.custom_domain
        AND keep.deleted = 0
        AND keep.id < d.id
SET d.custom_domain = NULL, d.custom_domain_verified = 0
WHERE d.deleted = 0 AND d.custom_domain IS NOT NULL;

ALTER TABLE app_deployment
    ADD COLUMN custom_domain_active VARCHAR(255)
        GENERATED ALWAYS AS (IF(deleted = 0, custom_domain, NULL)) STORED,
    ADD UNIQUE INDEX ux_app_deployment_custom_domain_active (custom_domain_active);
