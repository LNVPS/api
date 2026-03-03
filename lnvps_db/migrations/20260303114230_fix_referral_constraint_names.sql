-- Fix anonymous FK constraint names on referral and referral_payout tables.
-- MariaDB auto-named both constraints `1` when they were created without explicit
-- names, causing mysqldump re-imports to fail with a duplicate constraint error.
-- On production the constraints were already auto-named referral_ibfk_1 /
-- referral_payout_ibfk_1 by the sequential migration run, so we rename those.
ALTER TABLE referral
    DROP FOREIGN KEY `referral_ibfk_1`,
    ADD CONSTRAINT fk_referral_user FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE referral_payout
    DROP FOREIGN KEY `referral_payout_ibfk_1`,
    ADD CONSTRAINT fk_referral_payout_referral FOREIGN KEY (referral_id) REFERENCES referral(id);
