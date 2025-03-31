-- Add migration script here
ALTER TABLE vm_ip_assignment DROP KEY ix_vm_ip_assignment_ip;
alter table vm_os_image
    add column default_username varchar(50);