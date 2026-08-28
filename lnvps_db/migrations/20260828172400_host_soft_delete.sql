-- Soft delete for hosts. A decommissioned host cannot be removed outright once
-- it has run VMs: `vm.host_id` and `vm.disk_id` are foreign keys and those rows
-- are billing history. Flagging the host as deleted hides it from every listing
-- while keeping the id resolvable for historical joins.
alter table vm_host
    add column deleted bit(1) not null default 0;
