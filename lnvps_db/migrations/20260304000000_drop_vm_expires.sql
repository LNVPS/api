-- Remove vm.expires and vm.auto_renewal_enabled from the vm table.
-- Expiry is now read exclusively from subscription.expires.
-- Auto-renewal is managed via subscription.auto_renewal_enabled.

ALTER TABLE vm
    DROP COLUMN expires,
    DROP COLUMN auto_renewal_enabled;
