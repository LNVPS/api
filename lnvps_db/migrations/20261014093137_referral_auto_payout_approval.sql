ALTER TABLE referral
    ADD COLUMN auto_payout_approved BIT(1) NOT NULL DEFAULT 0;
