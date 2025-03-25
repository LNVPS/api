create table router
(
    id      integer unsigned not null auto_increment primary key,
    name    varchar(100) not null,
    enabled bit(1)       not null,
    kind    smallint unsigned not null,
    url     varchar(255) not null,
    token   varchar(128) not null
);
create table access_policy
(
    id        integer unsigned not null auto_increment primary key,
    name      varchar(100) not null,
    kind      smallint unsigned not null,
    router_id integer unsigned,
    interface varchar(100),
    constraint fk_access_policy_router foreign key (router_id) references router (id)
);
alter table ip_range
    add column reverse_zone_id varchar(255),
    add column access_policy_id integer unsigned;
alter table ip_range
    add constraint fk_ip_range_access_policy foreign key (access_policy_id) references access_policy (id);
