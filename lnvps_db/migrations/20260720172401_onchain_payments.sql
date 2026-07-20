-- On-chain payments (issue #109)
--
-- Every payment must have a unique external_id; the on-chain watcher stores
-- the bitcoin txid here and relies on uniqueness for at-least-once stream
-- de-duplication (a replayed deposit must not create or settle a second
-- payment). NULLs are exempt from MySQL unique indexes, so pending payments
-- (txid not yet known) are unaffected.
ALTER TABLE subscription_payment
    ADD CONSTRAINT uq_subscription_payment_external_id UNIQUE (external_id);
