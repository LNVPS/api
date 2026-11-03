ALTER TABLE app_cluster
    ADD COLUMN dns_server_id INTEGER UNSIGNED NULL DEFAULT NULL,
    ADD COLUMN dns_zone_id   VARCHAR(255)     NULL DEFAULT NULL,
    ADD CONSTRAINT fk_app_cluster_dns_server FOREIGN KEY (dns_server_id) REFERENCES dns_server (id);
