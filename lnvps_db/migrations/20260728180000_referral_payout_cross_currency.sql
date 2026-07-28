-- Record both sides of a referral payout that was settled in one currency and
-- sent in another.
--
-- Commission is earned per currency, and a payout nets against the balance of
-- the currency it settles. A payout sent in a different currency previously had
-- nowhere to say so: either the earned balance was never reduced, or it was
-- reduced by a figure nobody transferred.
--
-- `amount`, `fee` and `currency` keep their meaning and stay the settled side —
-- what this payout discharges against the earned balance. The sent side is what
-- actually left the wallet. `rate` ties the two together and is stored rather
-- than re-derived, so the conversion is reproducible without a historical price
-- feed.

ALTER TABLE referral_payout
    ADD COLUMN sent_amount   BIGINT UNSIGNED NULL DEFAULT NULL,
    -- Network/routing fee as the network charged it. `fee` is the same cost
    -- expressed in the settled currency, which is the one the balance nets in.
    ADD COLUMN sent_fee      BIGINT UNSIGNED NULL DEFAULT NULL,
    ADD COLUMN sent_currency VARCHAR(4)      NULL DEFAULT NULL,
    -- Settled-currency standard units per one sent-currency standard unit, so a
    -- EUR commission sent as BTC stores the EUR/BTC price. 1 when no conversion
    -- happened.
    ADD COLUMN rate           FLOAT          NOT NULL DEFAULT 1,
    -- When the rate was taken. NULL when the two currencies are the same and no
    -- rate was ever quoted; a rate of 1 with no timestamp is an identity, not a
    -- quote that happened to be 1.
    ADD COLUMN rate_collected TIMESTAMP      NULL DEFAULT NULL;

-- Every existing payout is single-currency: it sent exactly what it settled.
UPDATE referral_payout
SET sent_amount   = amount,
    sent_fee      = fee,
    sent_currency = currency
WHERE sent_currency IS NULL;

ALTER TABLE referral_payout
    MODIFY COLUMN sent_amount   BIGINT UNSIGNED NOT NULL,
    MODIFY COLUMN sent_fee      BIGINT UNSIGNED NOT NULL,
    MODIFY COLUMN sent_currency VARCHAR(4)      NOT NULL;
