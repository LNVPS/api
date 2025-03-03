-- Add migration script here
alter table vm_ip_assignment
    add column arp_ref varchar(50),
    add column dns_reverse varchar(255),
    add column dns_reverse_ref varchar(50),
    add column dns_forward varchar(255),
    add column dns_forward_ref varchar(50);