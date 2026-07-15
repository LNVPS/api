-- Backfill: detach SSH keys from already soft-deleted VMs.
--
-- The previous migration (20260714150000_vm_ssh_key_nullable.sql) made
-- vm.ssh_key_id nullable and new soft-deletes now null it out, but existing
-- soft-deleted VM rows still held the foreign-key reference. This kept the
-- fk_vm_ssh_key_id constraint alive and blocked users from deleting SSH keys
-- that were only ever used by now-deleted VMs
-- (DELETE /api/v1/ssh-key/{id} failed with a 1451 FK violation).
update vm
    set ssh_key_id = null
    where deleted = 1
      and ssh_key_id is not null;
