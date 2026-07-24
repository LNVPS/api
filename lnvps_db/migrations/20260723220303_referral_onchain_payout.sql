-- Add on-chain referral payout support.
--
-- ReferralPayoutMode gains OnChain = 3 (append-only; no data migration needed).
--
-- The referrer's payout address is now a single `address` column whose type is
-- determined by `mode` (a Lightning address for LightningAddress, an on-chain
-- Bitcoin address for OnChain), replacing the mode-specific `lightning_address`
-- column. `referral_payout.outpoint` records the on-chain payout outpoint
-- ("{txid}:{vout}") once broadcast; all eligible referrers are batched into one
-- send-many transaction, so rows from one batch share the txid but carry
-- distinct vouts.

ALTER TABLE referral
    CHANGE COLUMN lightning_address address VARCHAR(200) NULL DEFAULT NULL;

ALTER TABLE referral_payout
    ADD COLUMN outpoint VARCHAR(255) NULL DEFAULT NULL;
