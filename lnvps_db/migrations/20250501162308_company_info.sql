-- Add migration script here
create table company
(
    id           integer unsigned not null auto_increment primary key,
    created      timestamp    not null default current_timestamp,
    name         varchar(100) not null,
    email        varchar(100) not null,
    phone        varchar(100),
    address_1    varchar(200),
    address_2    varchar(200),
    city         varchar(100),
    state        varchar(100),
    postcode     varchar(50),
    country_code varchar(3),
    tax_id       varchar(50)
);
alter table vm_host_region
    add column company_id integer unsigned,
    add constraint fk_host_region_company foreign key (company_id) references company (id);