-- Add on-chain referral payout support.
--
-- ReferralPayoutMode gains OnChain = 3 (append-only; no data migration needed).
--
-- `referral.onchain_address` stores the referrer's on-chain payout address,
-- used when `mode` = OnChain (3). `referral_payout.txid` records the on-chain
-- transaction id once an on-chain payout batch is broadcast; a single
-- transaction may back several payout rows (all referrers are batched into one
-- send-many tx), so the same txid can appear on multiple rows.

ALTER TABLE referral
    ADD COLUMN onchain_address VARCHAR(200) NULL DEFAULT NULL;

ALTER TABLE referral_payout
    ADD COLUMN txid VARCHAR(200) NULL DEFAULT NULL;
