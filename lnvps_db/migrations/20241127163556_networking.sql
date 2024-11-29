alter table ip_range
    add column gateway varchar(255) not null;
alter table vm
    add column mac_address varchar(20) not null;
