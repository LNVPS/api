DROP TRIGGER audit_log_no_update;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
    IF NOT (OLD.id <=> NEW.id AND OLD.created <=> NEW.created AND OLD.actor_type <=> NEW.actor_type
        AND OLD.actor_id <=> NEW.actor_id AND OLD.auth_method <=> NEW.auth_method
        AND OLD.credential_id <=> NEW.credential_id AND OLD.user_agent <=> NEW.user_agent
        AND OLD.action <=> NEW.action AND OLD.target_type <=> NEW.target_type
        AND OLD.target_id <=> NEW.target_id AND OLD.before_summary <=> NEW.before_summary
        AND OLD.after_summary <=> NEW.after_summary AND OLD.request_id <=> NEW.request_id
        AND OLD.prev_hash <=> NEW.prev_hash AND OLD.hash <=> NEW.hash) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
    END IF;
END;
