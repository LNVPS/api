CREATE TABLE audit_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created BIGINT NOT NULL,
    actor_type VARCHAR(16) NOT NULL,
    actor_id BIGINT UNSIGNED NULL,
    auth_method VARCHAR(32) NULL,
    credential_id VARCHAR(64) NULL,
    ip VARCHAR(64) NULL,
    user_agent VARCHAR(255) NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(32) NULL,
    target_id VARCHAR(64) NULL,
    before_summary TEXT NULL,
    after_summary TEXT NULL,
    request_id VARCHAR(64) NULL,
    prev_hash CHAR(64) NOT NULL,
    hash CHAR(64) NOT NULL,
    INDEX ix_audit_log_actor (actor_type, actor_id),
    INDEX ix_audit_log_action (action),
    INDEX ix_audit_log_target (target_type, target_id),
    INDEX ix_audit_log_created (created)
);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
