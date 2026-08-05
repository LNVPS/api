-- Marketplace: operator and node registry.
--
-- Third parties ("operators") run the `lnvps_node` daemon on their own
-- hardware, list that capacity on the LNVPS marketplace, and earn a revenue
-- share on the VMs placed there. See `work/marketplace.md`.
--
-- This migration is registry only: it adds no behaviour. Nothing reads these
-- tables until the node daemon and its control channel land, and a
-- `marketplace_node` row cannot yet cause a VM to be placed anywhere.

-- An operator is an existing user who has enrolled to sell compute.
--
-- Payout configuration deliberately mirrors `referral` column for column
-- (`address` + `mode` + `payout_threshold`), because the payout worker that
-- settles these balances is the referral worker's shape and the two should stay
-- reconcilable by the same reporting. There is no KYC state: v1 operators are
-- not identity-checked (confidentiality is enforced by attestation and guest
-- encryption, not by knowing who the operator is).
CREATE TABLE marketplace_operator (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INTEGER UNSIGNED NOT NULL,
    -- Payout target. Its type is determined by `mode`: a Lightning address for
    -- LightningAddress, an on-chain Bitcoin address for OnChain, NULL for Nwc
    -- (which pays via the user's saved NWC connection).
    address VARCHAR(200) NULL DEFAULT NULL,
    -- PayoutMode, shared with `referral.mode`.
    mode SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    -- Minimum accrued earnings (in satoshis) before an automated payout runs,
    -- so operators can batch up instead of taking many tiny payments. NULL uses
    -- the system minimum.
    payout_threshold BIGINT UNSIGNED NULL DEFAULT NULL,
    -- Per-operator revenue share override, as a whole percentage of the invoice
    -- value of VMs running on this operator's nodes. NULL falls back to
    -- `company.marketplace_rate`, exactly as `referral.referral_rate` falls back
    -- to `company.referral_rate`.
    rate FLOAT NULL DEFAULT NULL,
    -- Set by an admin to stop new placements on every node this operator owns
    -- without deleting their nodes or withholding already-accrued earnings.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created DATETIME NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    -- One enrolment per user, matching `uk_referral_user`.
    UNIQUE KEY uk_marketplace_operator_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- A single machine offered by an operator.
--
-- Deliberately carries no region: an approved node's region lives on its backing
-- `vm_host` row, which is what capacity and placement actually read. Storing it
-- here too would be a second copy of the same fact, free to drift the moment an
-- admin edits the host — and the copy nothing reads is the one that would be
-- wrong. The region is chosen when the host row is created, at approval.
CREATE TABLE marketplace_node (
    id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    operator_id INTEGER UNSIGNED NOT NULL,
    -- Operator-chosen label, shown to the operator and to admins. Not unique:
    -- it is a display name, not an identifier.
    name VARCHAR(100) NOT NULL,
    -- The nostr public key the daemon authenticates its *control channel* with.
    -- Its data-plane identity (WireGuard key, assigned tunnel addresses) lives
    -- in `tunnel`, not here.
    -- Unique across the fleet so a key identifies exactly one node. NULL while
    -- the node is registered but has not yet presented a key (or authenticates
    -- with a session token issued to the operator's account instead).
    nostr_pubkey BINARY(32) NULL DEFAULT NULL,
    -- MarketplaceNodeStatus: pending / approved / suspended / draining.
    status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    -- MarketplaceTrustTier: untrusted / verified / partner. Gates placement
    -- policy (workload class, capacity caps, upgrade rings) — not
    -- confidentiality, which is enforced cryptographically.
    trust_tier SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    -- Last control-channel contact. NULL until the node first connects; used by
    -- SLA accounting and to decide whether a node is reachable.
    last_seen DATETIME NULL DEFAULT NULL,
    created DATETIME NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id),
    UNIQUE KEY uk_marketplace_node_nostr_pubkey (nostr_pubkey),
    KEY ix_marketplace_node_operator (operator_id),
    FOREIGN KEY (operator_id) REFERENCES marketplace_operator(id)
);

-- The backing host row for an approved node. NULL for every LNVPS-owned host,
-- which is all of them today.
--
-- ON DELETE RESTRICT (the default) is deliberate: a node with a live host must
-- be drained through the offboarding path, not deleted out from under running
-- VMs.
ALTER TABLE vm_host
    ADD COLUMN marketplace_node_id INTEGER UNSIGNED NULL DEFAULT NULL,
    ADD UNIQUE KEY uk_vm_host_marketplace_node (marketplace_node_id),
    ADD FOREIGN KEY (marketplace_node_id) REFERENCES marketplace_node(id);

-- Company-wide default revenue share, used when an operator has no override.
-- Mirrors `company.referral_rate`. Defaults to 0: revenue share is off until
-- somebody deliberately sets a rate, so a half-configured marketplace cannot
-- start accruing payouts.
ALTER TABLE company
    ADD COLUMN marketplace_rate FLOAT NOT NULL DEFAULT 0;
