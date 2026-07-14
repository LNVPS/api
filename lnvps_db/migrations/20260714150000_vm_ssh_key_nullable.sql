-- Allow a VM's ssh_key_id to be NULL so that when a VM is soft-deleted we can
-- detach its SSH key. This lets users delete SSH keys that were only ever used
-- by now-deleted VMs (soft-deleted VM rows previously kept the foreign-key
-- reference alive, blocking `DELETE /api/v1/ssh-key/{id}` with an FK violation).
alter table vm
    modify column ssh_key_id integer unsigned null;
