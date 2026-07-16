-- Referral commission model: percentage of a referred VM's first payment.
--
-- The effective rate is per-referrer with a company default:
--   * `company.referral_rate`  — default commission % for VMs sold by that
--      company (applies when the referrer has no override). NOT NULL, default 0
--      so the program pays nothing until a rate is configured.
--   * `referral.referral_rate` — optional per-referrer override (NULL = fall
--      back to the referred VM's company default). Applies to all of that
--      referrer's referrals when set.
--
-- Rates are whole percentages (e.g. 10.0 = 10%).

ALTER TABLE company
    ADD COLUMN referral_rate FLOAT NOT NULL DEFAULT 0;

ALTER TABLE referral
    ADD COLUMN referral_rate FLOAT NULL DEFAULT NULL;
