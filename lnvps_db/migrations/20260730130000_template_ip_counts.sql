-- IP counts as a sellable dimension of an offer, alongside cpu/memory/disk.
--
-- Defaults reproduce the previously implicit offer: exactly one IPv4 and one
-- IPv6 per VM. Custom pricing min/max default to that same single value, so no
-- plan silently starts offering a choice until an operator widens the range.
ALTER TABLE vm_template
    ADD COLUMN ip4_count smallint unsigned not null default 1,
    ADD COLUMN ip6_count smallint unsigned not null default 1;

ALTER TABLE vm_custom_pricing
    ADD COLUMN min_ip4 smallint unsigned not null default 1,
    ADD COLUMN max_ip4 smallint unsigned not null default 1,
    ADD COLUMN min_ip6 smallint unsigned not null default 1,
    ADD COLUMN max_ip6 smallint unsigned not null default 1;

ALTER TABLE vm_custom_template
    ADD COLUMN ip4_count smallint unsigned not null default 1,
    ADD COLUMN ip6_count smallint unsigned not null default 1;

-- Existing custom VMs are billed from what is actually assigned to them, so
-- adopt those counts as the stored spec: the count becomes authoritative for
-- pricing, and this keeps every existing renewal at the same amount. IPv6
-- addresses are the ones containing a colon.
UPDATE vm_custom_template ct
    JOIN vm v ON v.custom_template_id = ct.id
SET ct.ip4_count = GREATEST(1, (SELECT COUNT(*)
                                FROM vm_ip_assignment a
                                WHERE a.vm_id = v.id
                                  AND a.deleted = 0
                                  AND a.ip NOT LIKE '%:%')),
    ct.ip6_count = GREATEST(1, (SELECT COUNT(*)
                                FROM vm_ip_assignment a
                                WHERE a.vm_id = v.id
                                  AND a.deleted = 0
                                  AND a.ip LIKE '%:%'));

-- A plan must be able to price what its existing VMs already hold, otherwise
-- those VMs fail spec validation on upgrade.
UPDATE vm_custom_pricing p
SET p.max_ip4 = GREATEST(p.max_ip4, COALESCE((SELECT MAX(ct.ip4_count)
                                              FROM vm_custom_template ct
                                              WHERE ct.pricing_id = p.id), 1)),
    p.max_ip6 = GREATEST(p.max_ip6, COALESCE((SELECT MAX(ct.ip6_count)
                                              FROM vm_custom_template ct
                                              WHERE ct.pricing_id = p.id), 1)),
    p.min_ip4 = LEAST(p.min_ip4, COALESCE((SELECT MIN(ct.ip4_count)
                                           FROM vm_custom_template ct
                                           WHERE ct.pricing_id = p.id), 1)),
    p.min_ip6 = LEAST(p.min_ip6, COALESCE((SELECT MIN(ct.ip6_count)
                                           FROM vm_custom_template ct
                                           WHERE ct.pricing_id = p.id), 1));
