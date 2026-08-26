-- Record whether a renewal was charged automatically by the worker or paid by
-- the customer.
--
-- The payment row alone could never tell the difference: an NWC auto-renewal
-- settles a Lightning invoice exactly like a customer scanning a QR code, so
-- renewal/churn reporting had no way to separate "the subscription renews
-- itself" from "the customer remembered". Only the initiator knows, so it is
-- recorded at creation time.
--
-- NULL = unknown. Every row that existed before this migration is unknown and
-- stays that way: it is not inferable after the fact, and guessing would put
-- fabricated numbers into a churn report. Reports must show unknown as its own
-- bucket rather than folding it into either side.
--
-- renewal_source: 0 = user-initiated (manual), 1 = worker auto-renewal
ALTER TABLE subscription_payment
    ADD COLUMN renewal_source TINYINT UNSIGNED NULL;
