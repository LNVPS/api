ALTER TABLE agent_conversation
    ADD COLUMN escalated_at TIMESTAMP NULL,
    ADD COLUMN escalation_count INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN escalation_reason VARCHAR(200) NULL,
    ADD COLUMN escalation_vm_ids VARCHAR(190) NULL;
