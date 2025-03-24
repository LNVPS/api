-- Add migration script here
alter table vm_host
    add column load_memory float not null default 1.0,
    add column load_disk float not null default 1.0,
    change column load_factor load_cpu float not null default 1.0