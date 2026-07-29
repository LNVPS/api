-- Whether a deployment's custom domain has been observed resolving to us.
--
-- A domain is accepted the moment the customer sets it and held unserved until
-- the probe passes, rather than refused at set time: the CNAME is usually
-- created after the domain is entered, and refusing would make the customer
-- guess the order. Held means no ingress rule and no certificate request, so an
-- unpointed domain cannot burn failed ACME validations on every reconcile.
--
-- One-way per value: the flag is cleared when the domain changes, and the
-- operator sets it once the probe passes. A later probe failure does not clear
-- it, because tearing down a live customer domain over a transient resolver
-- error is worse than serving a name that has moved away.
--
-- Existing rows are backfilled as verified: they are already being served, and
-- retroactively holding them would take working domains offline.
ALTER TABLE app_deployment
    ADD COLUMN custom_domain_verified BIT(1) NOT NULL DEFAULT 0 AFTER custom_domain;

UPDATE app_deployment SET custom_domain_verified = 1 WHERE custom_domain IS NOT NULL;
