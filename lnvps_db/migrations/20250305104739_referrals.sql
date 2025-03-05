-- Add migration script here
alter table users
    drop column contact_nip4;
alter table vm
    add column ref_code varchar(20);