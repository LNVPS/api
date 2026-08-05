-- The node's TLS identity and its authentication token.
--
-- `tls_fingerprint` is the SHA-256 of the DER certificate LNVPS pins when
-- calling a node's control API. NIP-98 authenticates requests *to* a node;
-- nothing authenticates the node's replies. Without a pin, anything able to
-- answer on the node's tunnel address — a guest on that machine that grabbed
-- the IP, a route-server misconfiguration — could report that a VM started when
-- it did not. The node self-signs and registers this value; LNVPS checks it on
-- every later call.
--
-- Binary rather than a hex CHAR column, for the same reason as
-- `tunnel.peer_pubkey`: the default collation is case-insensitive, so a hex
-- string column would compare `AB…` and `ab…` as equal, and its UNIQUE index
-- would reject a distinct fingerprint that happened to differ only in case.
--
-- VARBINARY(32) with a length CHECK rather than BINARY(32), which is what the
-- older key columns use. BINARY(n) pads short values with zero bytes and
-- accepts them silently — verified against MariaDB, where inserting a 2-byte
-- value into BINARY(32) stored `1122000…000`. A padded fingerprint can never
-- match what the node presents, so the node would simply stop being reachable,
-- with nothing failing at the point the bad value was written. The CHECK turns
-- that into an error at write time (MariaDB 4025).
--
-- NULL until the node first registers, because a node row can be created before
-- the daemon has ever run.
--
-- UNIQUE across the fleet: two nodes presenting the same certificate would mean
-- either can answer for the other, which is exactly what the pin exists to
-- prevent.
ALTER TABLE marketplace_node
    ADD COLUMN tls_fingerprint VARBINARY(32) NULL DEFAULT NULL,
    ADD CONSTRAINT ck_marketplace_node_tls_fingerprint
        CHECK (tls_fingerprint IS NULL OR OCTET_LENGTH(tls_fingerprint) = 32),
    ADD UNIQUE KEY uk_marketplace_node_tls_fingerprint (tls_fingerprint);

-- Revocation counter for this node's token, compared against the `ver` claim on
-- every authenticated call the node makes. Bumping it invalidates every token
-- issued for this node and nothing else.
--
-- Deliberately per-node rather than reusing the operator's `users.session_version`:
-- that column revokes the operator's web sessions and every other node they own
-- at the same time, which turns "one node was compromised" into "the operator is
-- locked out of everything".
ALTER TABLE marketplace_node
    ADD COLUMN token_version INTEGER UNSIGNED NOT NULL DEFAULT 0;

-- A node authenticates with a token carrying its own id, not with a nostr key,
-- so the key column now states a fact nothing sets. Dropped rather than left
-- nullable-and-empty, where the next reader would reasonably assume nodes still
-- have keys and write code against a column that is never populated.
ALTER TABLE marketplace_node
    DROP KEY uk_marketplace_node_nostr_pubkey,
    DROP COLUMN nostr_pubkey;
