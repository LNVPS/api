ALTER TABLE app_deployment
    ADD COLUMN public_port SMALLINT UNSIGNED NULL DEFAULT NULL AFTER hostname;

INSERT INTO app_tag (slug, display_name, description)
VALUES ('game', 'Game servers', 'Dedicated game servers with a public connect address');
CREATE UNIQUE INDEX uq_app_deployment_public_port ON app_deployment (cluster_id, public_port);
