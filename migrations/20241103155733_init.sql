create table users
(
    id      integer unsigned not null auto_increment primary key,
    pubkey  binary(32) not null,
    created timestamp default current_timestamp
);
create unique index ix_user_pubkey on users (pubkey);
create table vm_host
(
    id      integer unsigned not null auto_increment primary key,
    kind    smallint unsigned not null,
    name    varchar(100) not null,
    ip      varchar(250) not null,
    cpu       bigint unsigned not null,
    memory    bigint unsigned not null,
    enabled bit(1) not null,
    api_token   varchar(200) not null
);
create table vm_host_disk
(
    id      integer unsigned not null auto_increment primary key,
    host_id integer unsigned not null,
    name      varchar(50) not null,
    size      bigint unsigned not null,
    kind      smallint unsigned not null,
    interface smallint unsigned not null,
    enabled bit(1) not null,

    constraint fk_vm_host_disk foreign key (host_id) references vm_host (id)
);
create table vm_os_image
(
    id      integer unsigned not null auto_increment primary key,
    name    varchar(200) not null,
    enabled bit(1) not null
);
create table ip_range
(
    id      integer unsigned not null auto_increment primary key,
    cidr    varchar(200) not null,
    enabled bit(1) not null
);
create table vm
(
    id        integer unsigned not null auto_increment primary key,
    host_id   integer unsigned not null,
    user_id   integer unsigned not null,
    image_id  integer unsigned not null,
    created   timestamp default current_timestamp,
    expires   timestamp not null,
    cpu       smallint unsigned not null,
    memory    bigint unsigned not null,
    disk_size bigint unsigned not null,
    disk_id integer unsigned not null,

    constraint fk_vm_host    foreign key (host_id) references vm_host (id),
    constraint fk_vm_user    foreign key (user_id) references users (id),
    constraint fk_vm_image    foreign key (image_id) references vm_os_image (id),
    constraint fk_vm_host_disk_id    foreign key (disk_id) references vm_host_disk (id)
);
create table vm_ip_assignment
(
    id           integer unsigned not null auto_increment primary key,
    vm_id        integer unsigned not null,
    ip_range_id  integer unsigned not null,

    constraint fk_vm_ip_assignment_vm        foreign key (vm_id) references vm (id),
    constraint fk_vm_ip_range        foreign key (ip_range_id) references ip_range (id)
);
create table vm_payment
(
    id binary(32) not null,
	vm_id integer unsigned not null,
	created timestamp default current_timestamp,
	expires timestamp not null,
	amount bigint unsigned not null,
	invoice varchar(2048) not null,
	time_value integer unsigned not null,
	is_paid bit(1) not null,

    constraint fk_vm_payment_vm foreign key (vm_id) references vm (id)
);