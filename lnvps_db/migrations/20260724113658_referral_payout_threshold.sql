-- User-chosen minimum accrued commission (in satoshis) before an automated
-- payout is made to a referrer. Lets referrers (especially on-chain) avoid
-- many tiny payouts by batching up to a larger amount. NULL uses the system
-- minimum; when set it must be >= the system minimum (enforced by the API).
-- The effective threshold at payout time is MAX(system_minimum, this value).
ALTER TABLE referral
    ADD COLUMN payout_threshold BIGINT UNSIGNED NULL DEFAULT NULL;
