-- SSH host keys a VM presented after first boot, as captured `ssh-keyscan`
-- lines (`host keytype base64`).
--
-- Stored as the raw scan rather than a row per key: the set is written and read
-- whole, is replaced outright when the guest regenerates its keys on reinstall,
-- and is never queried by key. Public key material only — nothing here is a
-- secret, and the guest's private keys are never read.
--
-- NULL means "not captured yet", which is the honest state for a VM that has
-- not booted, whose IP is unreachable, or that predates this column: an empty
-- capture must not read as "this host has no keys".
ALTER TABLE vm
    ADD COLUMN ssh_host_keys TEXT NULL AFTER mac_address;
