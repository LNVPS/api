-- Add migration script here
alter table users
    add column billing_name varchar(200),
    add column billing_address_1 varchar(200),
    add column billing_address_2 varchar(200),
    add column billing_city varchar(100),
    add column billing_state varchar(100),
    add column billing_postcode varchar(50),
    add column billing_tax_id varchar(50);