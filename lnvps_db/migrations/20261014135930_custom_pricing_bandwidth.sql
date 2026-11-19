ALTER TABLE vm_custom_pricing
    ADD COLUMN min_transfer_gb       integer unsigned not null default 0,
    ADD COLUMN max_transfer_gb       integer unsigned not null default 0,
    ADD COLUMN transfer_cost_per_tb  bigint unsigned  not null default 0,
    ADD COLUMN min_network_mbps      integer unsigned not null default 0,
    ADD COLUMN max_network_mbps      integer unsigned not null default 0,
    ADD COLUMN network_cost_per_gbps bigint unsigned  not null default 0;

UPDATE vm_custom_pricing p
SET p.min_transfer_gb  = LEAST(COALESCE(p.transfer_gb, 0), COALESCE((SELECT MIN(ct.transfer_gb)
                                                                      FROM vm_custom_template ct
                                                                      WHERE ct.pricing_id = p.id), COALESCE(p.transfer_gb, 0))),
    p.max_transfer_gb  = GREATEST(COALESCE(p.transfer_gb, 0), COALESCE((SELECT MAX(ct.transfer_gb)
                                                                        FROM vm_custom_template ct
                                                                        WHERE ct.pricing_id = p.id), 0)),
    p.min_network_mbps = LEAST(COALESCE(p.network_mbps, 0), COALESCE((SELECT MIN(ct.network_mbps)
                                                                       FROM vm_custom_template ct
                                                                       WHERE ct.pricing_id = p.id), COALESCE(p.network_mbps, 0))),
    p.max_network_mbps = GREATEST(COALESCE(p.network_mbps, 0), COALESCE((SELECT MAX(ct.network_mbps)
                                                                         FROM vm_custom_template ct
                                                                         WHERE ct.pricing_id = p.id), 0));
