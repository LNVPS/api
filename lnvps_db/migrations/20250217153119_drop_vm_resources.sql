-- Add migration script here
alter table vm
    drop column cpu,
    drop column memory,
    drop column disk_size;