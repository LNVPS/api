-- Support-agent conversation history.
--
-- Two tables rather than a JSON blob on one row, for two reasons that pull in
-- the same direction: the transcript is retained as a training corpus (so it
-- must be append-only and cheap to export), and the LLM only ever replays a
-- bounded tail of it (so the hot read must not drag the whole history along).

-- One row per conversation thread.
--
-- `conversation_key` is the identity the thread hangs off, namespaced by kind:
--   user:<id>      — a resolved LNVPS customer. Shared by every PRIVATE channel
--                    (email, live chat) so the agent has one continuous memory
--                    of that customer regardless of how they got in touch.
--   email:<addr>   — an email sender not matching any account.
--   pubkey:<hex>   — a nostr sender not matching any account.
--   nostr:<hex>    — public kind-1 mentions. Deliberately its OWN namespace and
--                    never merged into user:<id>: kind-1 replies are readable by
--                    the whole relay network, so a thread shared with email
--                    would let the agent quote a privately-reported billing or
--                    account detail into a public post.
--
-- `user_id` is denormalised from the key for joins/reporting and is NULL for
-- unresolved senders. It is intentionally NOT unique — one user legitimately
-- has both a private thread and a separate public nostr thread.
CREATE TABLE agent_conversation (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    conversation_key VARCHAR(190) NOT NULL,
    user_id INTEGER UNSIGNED NULL,

    -- LLM-generated running summary of every message at or below
    -- `compacted_upto`. Injected into the system prompt as the agent's memory.
    summary TEXT NULL,

    -- Watermark: the highest `agent_message.id` folded into `summary`.
    --
    -- Compaction advances this instead of deleting rows. Context for the next
    -- turn is `summary` + messages with id > compacted_upto, so the prompt stays
    -- bounded while the full transcript survives for training and audit. 0 means
    -- nothing has been compacted yet.
    compacted_upto INTEGER UNSIGNED NOT NULL DEFAULT 0,

    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_agent_conversation_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE KEY uk_agent_conversation_key (conversation_key),
    INDEX idx_agent_conversation_user (user_id)
);

-- Append-only message log. Rows are never updated or deleted in normal
-- operation; compaction only moves the watermark on the parent row.
--
-- The log is a faithful chat transcript including tool use, so a turn that
-- called a tool is stored as the assistant message carrying `tool_calls`
-- followed by one `role = 2` row per result. Replaying it reconstructs exactly
-- what the model saw, which is what makes it usable as training data.
CREATE TABLE agent_message (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    conversation_id INTEGER UNSIGNED NOT NULL,

    -- 0=User, 1=Assistant, 2=Tool
    role SMALLINT UNSIGNED NOT NULL,

    -- Which channel the message arrived on / was sent through.
    -- 0=Email, 1=Nostr, 2=WebChat. Kept per-message rather than per-conversation
    -- because a single private thread mixes email and live chat.
    channel SMALLINT UNSIGNED NOT NULL,

    -- Message text. Encrypted at rest via EncryptedString (base64 ciphertext),
    -- because transcripts carry PII: addresses, IPs, hostnames, and whatever a
    -- customer pastes into a support request. MEDIUMTEXT because a tool result
    -- can be a large JSON document and encryption inflates it further.
    --
    -- NULL for an assistant turn that only requested tool calls and produced no
    -- prose, which is distinct from an empty reply.
    content MEDIUMTEXT NULL,

    -- JSON array of {id, name, arguments} for an assistant turn that requested
    -- tools. NULL for plain messages. Not encrypted: these are our own tool
    -- names and model-generated arguments, and keeping them queryable is how we
    -- analyse tool-use quality across the corpus.
    --
    -- MariaDB implements JSON as LONGTEXT plus a `json_valid` CHECK, so a
    -- malformed value is rejected at insert rather than silently poisoning the
    -- corpus. Writers always serialize with serde_json, so this is a safety net.
    tool_calls JSON NULL,

    -- For role=Tool, the `tool_calls[].id` this row is the result of.
    tool_call_id VARCHAR(128) NULL,

    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_agent_message_conversation FOREIGN KEY (conversation_id) REFERENCES agent_conversation (id) ON DELETE CASCADE,
    -- Covers both the hot read (tail above the watermark) and the export scan,
    -- since both walk a single conversation in id order.
    INDEX idx_agent_message_conversation (conversation_id, id)
);
