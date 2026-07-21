-- Allow "sunsetting" a host: give users until a certain date to migrate their
-- VMs to another host. While `sunset_date` is set the host is effectively
-- disabled for new provisioning, and renewals are blocked once a VM's expiry has
-- reached the sunset date.
alter table vm_host
    add column sunset_date timestamp null;
