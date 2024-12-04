-- Add migration script here
alter table vm
    add column deleted bit(1) not null default 0;
alter table vm_ip_assignment
    add column deleted bit(1) not null default 0;