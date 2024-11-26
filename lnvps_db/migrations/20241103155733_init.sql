create table users
(
    id            integer unsigned not null auto_increment primary key,
    pubkey        binary(32) not null,
    created       timestamp default current_timestamp,
    email         varchar(200),
    contact_nip4  bit(1) not null,
    contact_nip17 bit(1) not null,
    contact_email bit(1) not null
);
create unique index ix_user_pubkey on users (pubkey);
create unique index ix_user_email on users (email);
create table user_ssh_key
(
    id       integer unsigned not null auto_increment primary key,
    name     varchar(100)  not null,
    user_id  integer unsigned not null,
    created  timestamp default current_timestamp,
    key_data varchar(2048) not null,

    constraint fk_ssh_key_user foreign key (user_id) references users (id)
);
create table vm_host_region
(
    id      integer unsigned not null auto_increment primary key,
    name    varchar(100) not null,
    enabled bit(1)       not null
);
create table vm_host
(
    id        integer unsigned not null auto_increment primary key,
    kind      smallint unsigned not null,
    region_id integer unsigned not null,
    name      varchar(100) not null,
    ip        varchar(250) not null,
    cpu       bigint unsigned not null,
    memory    bigint unsigned not null,
    enabled   bit(1)       not null,
    api_token varchar(200) not null,

    constraint fk_host_region foreign key (region_id) references vm_host_region (id)
);
create table vm_host_disk
(
    id        integer unsigned not null auto_increment primary key,
    host_id   integer unsigned not null,
    name      varchar(50) not null,
    size      bigint unsigned not null,
    kind      smallint unsigned not null,
    interface smallint unsigned not null,
    enabled   bit(1)      not null,

    constraint fk_host_disk_host foreign key (host_id) references vm_host (id)
);
create table vm_os_image
(
    id           integer unsigned not null auto_increment primary key,
    distribution smallint unsigned not null,
    flavour      varchar(50)   not null,
    version      varchar(50)   not null,
    enabled      bit(1)        not null,
    release_date timestamp     not null,
    url          varchar(1024) not null
);
create unique index ix_vm_os_image on vm_os_image (distribution, flavour, version);
create table ip_range
(
    id        integer unsigned not null auto_increment primary key,
    cidr      varchar(200) not null,
    enabled   bit(1)       not null,
    region_id integer unsigned not null,

    constraint fk_ip_range_region foreign key (region_id) references vm_host_region (id)
);
create unique index ix_ip_range_cidr on ip_range (cidr);
create table vm_cost_plan
(
    id              integer unsigned not null auto_increment primary key,
    name            varchar(200) not null,
    created         timestamp default current_timestamp,
    amount          integer unsigned not null,
    currency        varchar(4)   not null,
    interval_amount integer unsigned not null,
    interval_type   smallint unsigned not null
);
-- IE. VM Offers
create table vm_template
(
    id             integer unsigned not null auto_increment primary key,
    name           varchar(200) not null,
    enabled        bit(1)       not null,
    created        timestamp default current_timestamp,
    expires        timestamp,
    cpu            tinyint unsigned not null,
    memory         bigint unsigned not null,
    disk_size      bigint unsigned not null,
    disk_type      smallint unsigned not null,
    disk_interface smallint unsigned not null,
    cost_plan_id   integer unsigned not null,
    region_id      integer unsigned not null,

    constraint fk_template_cost_plan foreign key (cost_plan_id) references vm_cost_plan (id),
    constraint fk_template_region foreign key (region_id) references vm_template (id)
);
-- An instance of a VM
create table vm
(
    id          integer unsigned not null auto_increment primary key,
    host_id     integer unsigned not null,
    user_id     integer unsigned not null,
    image_id    integer unsigned not null,
    template_id integer unsigned not null,
    ssh_key_id  integer unsigned not null,
    created     timestamp default current_timestamp,
    expires     timestamp not null,
    cpu         smallint unsigned not null,
    memory      bigint unsigned not null,
    disk_size   bigint unsigned not null,
    disk_id     integer unsigned not null,

    constraint fk_vm_host foreign key (host_id) references vm_host (id),
    constraint fk_vm_user foreign key (user_id) references users (id),
    constraint fk_vm_image foreign key (image_id) references vm_os_image (id),
    constraint fk_vm_host_disk_id foreign key (disk_id) references vm_host_disk (id),
    constraint fk_vm_template_id foreign key (template_id) references vm_template (id),
    constraint fk_vm_ssh_key_id foreign key (ssh_key_id) references user_ssh_key (id)
);
create table vm_ip_assignment
(
    id          integer unsigned not null auto_increment primary key,
    vm_id       integer unsigned not null,
    ip_range_id integer unsigned not null,
    ip          varchar(255) not null,

    constraint fk_vm_ip_assignment_vm foreign key (vm_id) references vm (id),
    constraint fk_vm_ip_range foreign key (ip_range_id) references ip_range (id)
);
create unique index ix_vm_ip_assignment_ip on vm_ip_assignment (ip);
create table vm_payment
(
    id           binary(32) not null,
    vm_id        integer unsigned not null,
    created      timestamp default current_timestamp,
    expires      timestamp     not null,
    amount       bigint unsigned not null,
    invoice      varchar(2048) not null,
    time_value   bigint unsigned not null,
    is_paid      bit(1)        not null,
    settle_index bigint unsigned,

    constraint fk_vm_payment_vm foreign key (vm_id) references vm (id)
);
create unique index ix_vm_payment_id on vm_payment (id);