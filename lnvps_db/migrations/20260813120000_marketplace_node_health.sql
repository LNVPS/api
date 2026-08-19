-- What a probe VM found on a node.
--
-- LNVPS builds a real VM on an operator's machine through the ordinary customer
-- path, logs into it, measures it and destroys it. This is what it saw.
--
-- A **series**, not a verdict. One bad run is a bad afternoon — a backup job, a
-- neighbour compiling something — and suspending a node for it would make the
-- marketplace hostile to the people it needs. A trend is a node to act on. The
-- trust tier that increment 12 assigns also wants the history, not the last
-- answer.
--
-- Nothing here identifies the probe VM itself: no id, no address, no disk. The
-- VM exists for a few minutes and is destroyed, and a row pointing at one that
-- outlived its process would need a reaper — which is one more thing that fails
-- quietly, leaving our VM running on hardware we do not own.
--
-- The **shape and image are recorded with every row** because they are what the
-- numbers mean. Regions sell different templates, so a probe on one node may
-- have had two cores and another four; comparing raw seconds across them would
-- rank the machines by what we happened to ask for. Rates are stored normalised
-- (MB/s, MB/s per GB) so a row is comparable on its own terms, and the shape is
-- kept so a surprising row can be explained rather than argued about.
CREATE TABLE marketplace_node_health
(
    id            INTEGER UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    node_id       INTEGER UNSIGNED NOT NULL,
    created       TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Whether the probe completed at all. A failure is as much a result as a
    -- slow disk, and is kept rather than discarded: a node that never completes
    -- a probe looks identical to one that was never probed unless the failures
    -- are written down.
    passed        BIT(1)           NOT NULL,
    -- Why it failed, in the words of whatever failed. NULL on success.
    failure       TEXT             NULL,

    -- How long from asking for the VM to being able to log into it. The number
    -- a customer actually experiences.
    provision_ms  INTEGER UNSIGNED NULL,
    -- Memory the guest could allocate *and touch*, in MB. Allocating alone
    -- proves nothing on a host that overcommits: the pages have to be written
    -- for the machine to admit it does not have them.
    memory_mb     INTEGER UNSIGNED NULL,
    -- Sequential write and read, MB/s.
    disk_write_mb INTEGER UNSIGNED NULL,
    disk_read_mb  INTEGER UNSIGNED NULL,

    -- What was asked for, so the numbers above can be read. Denormalised on
    -- purpose: a template edited or deleted later must not silently change what
    -- an old measurement appears to say.
    cpu           SMALLINT UNSIGNED NOT NULL,
    memory_bytes  BIGINT UNSIGNED  NOT NULL,
    disk_bytes    BIGINT UNSIGNED  NOT NULL,
    image         VARCHAR(255)     NOT NULL,

    CONSTRAINT fk_marketplace_node_health_node
        FOREIGN KEY (node_id) REFERENCES marketplace_node (id) ON DELETE CASCADE,
    -- Reads are always "this node, most recent first".
    INDEX ix_marketplace_node_health_node (node_id, created DESC)
);
