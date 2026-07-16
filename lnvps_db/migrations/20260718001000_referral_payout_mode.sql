-- Replace the referral `use_nwc` boolean with a flexible `mode` enum column so
-- new payout methods (e.g. account credit) can be added without further boolean
-- flags.
--
-- ReferralPayoutMode: LightningAddress = 0, Nwc = 1, AccountCredit = 2
--
-- Migrate existing rows: use_nwc = 1 -> Nwc (1); otherwise LightningAddress (0).

ALTER TABLE referral
    ADD COLUMN mode SMALLINT UNSIGNED NOT NULL DEFAULT 0;

UPDATE referral SET mode = 1 WHERE use_nwc = 1;

ALTER TABLE referral
    DROP COLUMN use_nwc;
