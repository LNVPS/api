CREATE TABLE abuse_case
(
    id                  INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    vm_id               INTEGER UNSIGNED NULL,
    user_id             INTEGER UNSIGNED NULL,
    kind                SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    reported_ip         VARCHAR(45)      NULL,
    incident_at         DATETIME         NULL,
    reporter_email      VARCHAR(255)     NULL,
    summary             TEXT             NOT NULL,
    proceedings_started BOOLEAN          NOT NULL DEFAULT FALSE,
    created             DATETIME         NOT NULL DEFAULT NOW(),
    closed_at           DATETIME         NULL,
    PRIMARY KEY (id),
    KEY ix_abuse_case_vm (vm_id),
    KEY ix_abuse_case_user (user_id),
    KEY ix_abuse_case_closed (closed_at)
);

CREATE TABLE abuse_action
(
    id                    INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT,
    case_id               INTEGER UNSIGNED  NOT NULL,
    kind                  SMALLINT UNSIGNED NOT NULL,
    reason                TEXT              NOT NULL,
    facts                 TEXT              NOT NULL,
    legal_basis           VARCHAR(255)      NULL,
    followed_report       BOOLEAN           NOT NULL DEFAULT TRUE,
    notice_withheld       VARCHAR(255)      NULL,
    notified_at           DATETIME          NULL,
    admin_user_id         INTEGER UNSIGNED  NOT NULL,
    created               DATETIME          NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    KEY ix_abuse_action_case (case_id),
    CONSTRAINT fk_abuse_action_case FOREIGN KEY (case_id) REFERENCES abuse_case (id) ON DELETE CASCADE
);

CREATE TABLE abuse_challenge
(
    id          INTEGER UNSIGNED  NOT NULL AUTO_INCREMENT,
    case_id     INTEGER UNSIGNED  NOT NULL,
    action_id   INTEGER UNSIGNED  NOT NULL,
    message     TEXT              NOT NULL,
    received_at DATETIME          NOT NULL DEFAULT NOW(),
    outcome     SMALLINT UNSIGNED NULL,
    response    TEXT              NULL,
    decided_at  DATETIME          NULL,
    decided_by  INTEGER UNSIGNED  NULL,
    PRIMARY KEY (id),
    KEY ix_abuse_challenge_case (case_id),
    CONSTRAINT fk_abuse_challenge_case FOREIGN KEY (case_id) REFERENCES abuse_case (id) ON DELETE CASCADE,
    CONSTRAINT fk_abuse_challenge_action FOREIGN KEY (action_id) REFERENCES abuse_action (id) ON DELETE CASCADE
);

INSERT IGNORE INTO admin_role_permissions (role_id, resource, action, created_at)
SELECT id, 35, 0, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 35, 1, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 35, 2, NOW() FROM admin_roles WHERE name = 'super_admin'
UNION ALL
SELECT id, 35, 3, NOW() FROM admin_roles WHERE name = 'super_admin';
