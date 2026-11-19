CREATE TABLE api_token (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INTEGER UNSIGNED NOT NULL,
    name VARCHAR(100) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    scope VARCHAR(16) NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires TIMESTAMP NOT NULL,
    last_used TIMESTAMP NULL,
    last_ip VARCHAR(64) NULL,
    CONSTRAINT fk_api_token_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ix_api_token_hash ON api_token (token_hash);
CREATE INDEX ix_api_token_user ON api_token (user_id);
