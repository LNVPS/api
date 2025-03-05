-- Add migration script here
alter table vm_host
    add column load_factor float not null default 1.0;