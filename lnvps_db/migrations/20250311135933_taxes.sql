alter table vm_payment
    add column tax bigint unsigned not null;
alter table users
    add column country_code varchar(3) not null default 'USA';