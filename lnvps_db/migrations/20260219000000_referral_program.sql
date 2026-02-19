-- Referral program tables
CREATE TABLE referral (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    code VARCHAR(20) NOT NULL,
    lightning_address VARCHAR(200),
    use_nwc BOOLEAN NOT NULL DEFAULT FALSE,
    created DATETIME NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE KEY uk_referral_code (code),
    UNIQUE KEY uk_referral_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE referral_payout (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    referral_id BIGINT UNSIGNED NOT NULL,
    amount BIGINT UNSIGNED NOT NULL,
    currency VARCHAR(10) NOT NULL,
    created DATETIME NOT NULL DEFAULT NOW(),
    is_paid BOOLEAN NOT NULL DEFAULT FALSE,
    invoice VARCHAR(600),
    pre_image VARCHAR(64),
    PRIMARY KEY (id),
    FOREIGN KEY (referral_id) REFERENCES referral(id)
);
