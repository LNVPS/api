-- App catalog: predefined managed applications offered on shared k8s infra.
-- Each app is defined by a docker-compose-style YAML blob; the operator
-- translates it (merged with a deployment's config) into Kubernetes objects.
CREATE TABLE app
(
    id              INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(64)      NOT NULL,
    display_name    VARCHAR(200)     NOT NULL,
    description     TEXT             NULL DEFAULT NULL,
    icon            VARCHAR(500)     NULL DEFAULT NULL,
    -- docker-compose-style YAML (image / ports / env / volumes)
    compose         MEDIUMTEXT       NOT NULL,
    -- recurring price in the smallest currency unit (cents / millisats)
    amount          BIGINT UNSIGNED  NOT NULL,
    currency        VARCHAR(10)      NOT NULL,
    interval_amount BIGINT UNSIGNED  NOT NULL,
    interval_type   SMALLINT UNSIGNED NOT NULL,
    setup_amount    BIGINT UNSIGNED  NOT NULL DEFAULT 0,
    enabled         BIT(1)           NOT NULL DEFAULT 1,
    created         TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_app_name UNIQUE (name)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

-- A Kubernetes cluster where apps can be deployed. Linked to a region so
-- location / company / tax / currency resolve exactly like VMs. The operator
-- that runs *inside* a cluster is configured with its own cluster id and only
-- reconciles that cluster's deployments; no kube credentials are stored here.
CREATE TABLE app_cluster
(
    id             INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name           VARCHAR(100)     NOT NULL,
    region_id      INTEGER UNSIGNED NOT NULL,
    -- wildcard base domain for ingress hostnames on this cluster
    -- (hostname = "{deployment.name}.{ingress_domain}")
    ingress_domain VARCHAR(255)     NOT NULL,
    enabled        BIT(1)           NOT NULL DEFAULT 1,
    created        TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_app_cluster_region FOREIGN KEY (region_id) REFERENCES region (id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

-- A customer's running instance of an app, billed via the subscription engine
-- (subscription_line_item_id, type=App) and reconciled into its own namespace
-- on the chosen cluster.
CREATE TABLE app_deployment
(
    id                        INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id                   INTEGER UNSIGNED NOT NULL,
    app_id                    INTEGER UNSIGNED NOT NULL,
    cluster_id                INTEGER UNSIGNED NOT NULL,
    subscription_line_item_id INTEGER UNSIGNED NOT NULL,
    name                      VARCHAR(64)      NOT NULL,
    namespace                 VARCHAR(64)      NOT NULL,
    hostname                  VARCHAR(255)     NULL DEFAULT NULL,
    -- encrypted JSON of resolved per-deployment config (env values, secrets);
    -- EncryptedString serializes as an encoded string, so store as TEXT
    config                    TEXT             NULL DEFAULT NULL,
    desired_state             SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    status                    SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    status_message            VARCHAR(500)     NULL DEFAULT NULL,
    created                   TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted                   BIT(1)           NOT NULL DEFAULT 0,
    CONSTRAINT fk_app_deployment_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_app_deployment_app FOREIGN KEY (app_id) REFERENCES app (id),
    CONSTRAINT fk_app_deployment_cluster FOREIGN KEY (cluster_id) REFERENCES app_cluster (id),
    CONSTRAINT fk_app_deployment_line_item FOREIGN KEY (subscription_line_item_id) REFERENCES subscription_line_item (id),
    CONSTRAINT uq_app_deployment_namespace UNIQUE (namespace)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;

CREATE INDEX ix_app_deployment_user ON app_deployment (user_id);
CREATE INDEX ix_app_deployment_app ON app_deployment (app_id);
CREATE INDEX ix_app_deployment_cluster ON app_deployment (cluster_id);
CREATE INDEX ix_app_deployment_line_item ON app_deployment (subscription_line_item_id);
