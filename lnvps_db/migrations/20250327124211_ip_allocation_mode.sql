alter table ip_range
    add column allocation_mode smallint unsigned not null default 0,
    add column use_full_range bit(1) not null;