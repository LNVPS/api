CREATE TABLE sanctions_list
(
    id          INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    source      VARCHAR(32)      NOT NULL,
    version     VARCHAR(128)     NOT NULL,
    sha256      CHAR(64)         NOT NULL,
    entry_count INTEGER UNSIGNED NOT NULL,
    entries     LONGBLOB         NOT NULL,
    fetched     DATETIME         NOT NULL DEFAULT NOW(),
    checked     DATETIME         NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    KEY ix_sanctions_list_source (source, id)
);

CREATE TABLE sanctions_match
(
    id                INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT,
    created           DATETIME          NOT NULL DEFAULT NOW(),
    subject           SMALLINT UNSIGNED NOT NULL,
    user_id           INTEGER UNSIGNED  NULL,
    payment_ref       VARCHAR(128)      NULL,
    field             SMALLINT UNSIGNED NOT NULL,
    subject_value     TEXT              NOT NULL,
    subject_hash      BINARY(32)        NOT NULL,
    list_id           INTEGER UNSIGNED  NULL,
    list_source       VARCHAR(32)       NOT NULL,
    list_version      VARCHAR(128)      NOT NULL,
    list_fetched      DATETIME          NULL,
    entry_id          VARCHAR(64)       NOT NULL,
    entry_name        VARCHAR(512)      NOT NULL,
    score             FLOAT             NOT NULL,
    status            SMALLINT UNSIGNED NOT NULL,
    resolved_by       INTEGER UNSIGNED  NULL,
    resolved_at       DATETIME          NULL,
    resolution_reason TEXT              NULL,
    PRIMARY KEY (id),
    KEY ix_sanctions_match_status (status, id),
    KEY ix_sanctions_match_user (user_id, status),
    KEY ix_sanctions_match_payment (payment_ref, status),
    UNIQUE KEY ix_sanctions_match_subject (subject_hash, list_source, entry_id)
);

CREATE TABLE payment_screening
(
    id             INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT,
    payment_ref    VARCHAR(128)      NOT NULL,
    payment_id     BINARY(32)        NULL,
    user_id        INTEGER UNSIGNED  NULL,
    payment_method SMALLINT UNSIGNED NOT NULL,
    mode           SMALLINT UNSIGNED NOT NULL,
    provider       VARCHAR(64)       NOT NULL,
    result         TEXT              NULL,
    held           BIT(1)            NOT NULL DEFAULT 0,
    sources        TEXT              NULL,
    address        TEXT              NULL,
    amount_msat    BIGINT UNSIGNED   NULL,
    created        DATETIME          NOT NULL DEFAULT NOW(),
    released_at    DATETIME          NULL,
    PRIMARY KEY (id),
    UNIQUE KEY ix_payment_screening_ref (payment_ref),
    KEY ix_payment_screening_payment (payment_id)
);

INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 38, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 38, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 38, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 38, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
