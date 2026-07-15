-- Retire the defunct `vm_payment` table. All payments now live in
-- `subscription_payment`; historical `vm_payment` rows were copied there by the
-- startup backfill (Phase 2) in earlier releases, which has since been removed.
drop table if exists vm_payment;
