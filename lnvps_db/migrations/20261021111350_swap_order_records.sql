CREATE TABLE swap_order_client
(
    id              INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         INTEGER UNSIGNED NOT NULL,
    order_id        VARCHAR(64)      NOT NULL,
    payment_id      BINARY(32)       NOT NULL,
    coin            VARCHAR(16)      NOT NULL,
    ip              VARCHAR(45)      NULL,
    user_agent      VARCHAR(512)     NULL,
    accept_language VARCHAR(255)     NULL,
    created         DATETIME         NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE KEY uk_swap_order_client_order (order_id),
    KEY ix_swap_order_client_user (user_id),
    KEY ix_swap_order_client_payment (payment_id),
    KEY ix_swap_order_client_created (created)
);
