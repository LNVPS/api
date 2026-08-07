-- The health gate's record: has this node ever carried a packet for a customer?
--
-- A node is approved by a human looking at hardware they cannot see. Everything
-- between that decision and a customer's VM working — a tunnel that handshakes,
-- a route server that routes, a bridge, a packet filter, a forwarding knob — is
-- machinery nobody has tested on that particular machine. The gate tests it, by
-- taking an address from the range customers get, having the node hold it, and
-- pinging it from the route server. That is the customer's path exactly.
--
-- Why a table rather than columns on `marketplace_node`:
--
-- * The probe **holds an address** while it runs. That address must not be
--   handed to a VM at the same time, so the allocator has to be able to see it,
--   which means it has to be queryable by range — a column on the node would
--   make "which addresses in this range are taken?" a scan of every node.
-- * The result outlives the address. When the probe finishes the address goes
--   back (`ip` becomes NULL) but the verdict stays, so an operator can see why
--   their node was refused without the node still consuming an address.
--
-- One row per node: this is the *last* gate run, not a history. A history would
-- be worth having and is not this — it belongs with SLA accounting, where the
-- retention and the questions are different.

CREATE TABLE marketplace_node_probe (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,

    node_id INTEGER UNSIGNED NOT NULL,

    -- The range the address came from. Recorded because the gateway a probe is
    -- reachable through belongs to the range, not to the node, and a failure is
    -- read as "this node cannot carry addresses from that range".
    --
    -- NULL until an address is taken, and for a run that failed before it got
    -- that far: a node whose tunnel never handshook is refused *before* an
    -- address comes out of a customer range to prove the same thing slowly, and
    -- that refusal still has to be recorded or the operator is told nothing.
    ip_range_id INTEGER UNSIGNED NULL,

    -- The address currently held, or NULL once the run is over.
    --
    -- Nullable rather than deleted with the row, because releasing the address
    -- and keeping the verdict are two different things, and a gate that had to
    -- destroy its own result to give an address back would leave no record of
    -- why a node is disabled.
    ip VARCHAR(255) NULL,

    -- 0 running, 1 passed, 2 failed.
    status SMALLINT UNSIGNED NOT NULL DEFAULT 0,

    -- Which step failed, in the words an operator needs: "the node never
    -- handshook", "the route server could not reach the probe address". A
    -- verdict with no reason is a support conversation.
    detail VARCHAR(255) NULL,

    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished TIMESTAMP NULL,

    CONSTRAINT PK_marketplace_node_probe PRIMARY KEY (id),

    -- One live gate per node. Two concurrent runs would hold two addresses and
    -- disagree about the verdict.
    CONSTRAINT uk_marketplace_node_probe_node UNIQUE KEY (node_id),

    -- An address is held by one probe. Two nodes holding the same address would
    -- both be routed it, and the route server would send it to whichever peer
    -- claimed it last. NULLs do not collide in MySQL, which is exactly the
    -- behaviour wanted here: finished probes hold nothing.
    CONSTRAINT uk_marketplace_node_probe_ip UNIQUE KEY (ip),

    CONSTRAINT fk_marketplace_node_probe_node FOREIGN KEY (node_id)
        REFERENCES marketplace_node (id) ON DELETE CASCADE,
    CONSTRAINT fk_marketplace_node_probe_range FOREIGN KEY (ip_range_id)
        REFERENCES ip_range (id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;
