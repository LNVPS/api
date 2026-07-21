-- The origin AS number the customer announces the allocated prefix from.
--
-- This is mutable operational state: a customer can re-home the range to a
-- different ASN over the life of the subscription, which re-issues the IRR
-- route object and RPKI ROA. It therefore lives on the assignment row (not the
-- immutable order-time line-item configuration). NULL = not yet configured, so
-- no registry objects are created until the customer sets it.
ALTER TABLE ip_range_subscription
    ADD COLUMN origin_asn INTEGER UNSIGNED NULL AFTER cidr;
