-- Make vm.subscription_id NOT NULL after data migration backfill.
-- Run migrate_vm_subscriptions binary before applying this migration.
ALTER TABLE vm MODIFY COLUMN subscription_id INTEGER UNSIGNED NOT NULL;
