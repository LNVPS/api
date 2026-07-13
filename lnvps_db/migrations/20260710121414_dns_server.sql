-- DNS provider configuration moved from static settings into the database,
-- mirroring the `router` table. Each row is an external DNS provider (Cloudflare,
-- OVH reverse, ...) with an encrypted credential token.
create table dns_server
(
    id      integer unsigned  not null auto_increment primary key,
    name    varchar(100)      not null,
    enabled bit(1)            not null default 1,
    kind    smallint unsigned not null,
    -- API base url (provider specific, e.g. https://eu.api.ovh.com). May be empty for Cloudflare.
    url     varchar(255)      not null default '',
    -- Encrypted credential token (Cloudflare: bearer token; OVH: app_key:app_secret:consumer_key)
    token   varchar(255)      not null
);

-- Per-IP-range DNS server references + forward zone id.
-- `reverse_zone_id` already exists (added in 20250325113115_extend_ip_range.sql).
alter table ip_range
    add column forward_dns_server_id integer unsigned,
    add column reverse_dns_server_id integer unsigned,
    add column forward_zone_id       varchar(255);

alter table ip_range
    add constraint fk_ip_range_forward_dns_server foreign key (forward_dns_server_id) references dns_server (id),
    add constraint fk_ip_range_reverse_dns_server foreign key (reverse_dns_server_id) references dns_server (id);
