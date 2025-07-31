-- Change vm_history.action_type from VARCHAR to SMALLINT UNSIGNED to match Rust enum
ALTER TABLE vm_history MODIFY COLUMN action_type SMALLINT UNSIGNED NOT NULL;