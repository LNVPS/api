-- fix this fk ref
ALTER TABLE vm_template DROP FOREIGN KEY fk_template_region;
alter table vm_template
    add constraint fk_template_region foreign key (region_id) references vm_host_region (id);

create table vm_custom_pricing
(
    id          integer unsigned not null auto_increment primary key,
    name        varchar(100) not null,
    enabled     bit(1)       not null,
    created     timestamp default current_timestamp,
    expires     timestamp,
    region_id   integer unsigned not null,
    currency    varchar(5)   not null,
    cpu_cost    float        not null,
    memory_cost float        not null,
    ip4_cost    float        not null,
    ip6_cost    float        not null,

    constraint fk_custom_pricing_region foreign key (region_id) references vm_host_region (id)
);
create table vm_custom_pricing_disk
(
    id         integer unsigned not null auto_increment primary key,
    pricing_id integer unsigned not null,
    kind       smallint unsigned not null,
    interface  smallint unsigned not null,
    cost       float not null,

    constraint fk_custom_pricing_disk foreign key (pricing_id) references vm_custom_pricing (id)
);
ALTER TABLE vm MODIFY COLUMN template_id int (10) unsigned NULL;
ALTER TABLE vm
    add COLUMN custom_template_id int(10) unsigned NULL;

create table vm_custom_template
(
    id             integer unsigned not null auto_increment primary key,
    cpu            tinyint unsigned not null,
    memory         bigint unsigned not null,
    disk_size      bigint unsigned not null,
    disk_type      smallint unsigned not null,
    disk_interface smallint unsigned not null,
    pricing_id     integer unsigned not null,

    constraint fk_custom_template_pricing foreign key (pricing_id) references vm_custom_pricing (id)
);
alter table vm
    add constraint fk_vm_custom_template foreign key (custom_template_id) references vm_custom_template (id);
