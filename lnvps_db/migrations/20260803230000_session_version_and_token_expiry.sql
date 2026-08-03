-- Security hardening for token lifecycle (see work/security-audit-2026-08.md).
--
-- F-10: session (Bearer JWT) tokens were valid for 30 days with no way to
-- revoke them. `session_version` is embedded in every issued token and compared
-- on every request, so bumping it invalidates all outstanding sessions for that
-- user (logout-everywhere, credential change, suspected compromise).
--
-- F-18: email verification tokens never expired, so a link sitting in an old
-- inbox stayed usable forever. `email_verify_sent` records when the pending
-- token was issued so it can be aged out.
--
-- Both columns are NOT NULL DEFAULT so existing rows are unaffected: every
-- current user starts at session version 0, and rows with no pending
-- verification have a NULL sent-time which the code treats as "no expiry
-- information", falling back to rejecting the token.

ALTER TABLE users
    ADD COLUMN session_version INTEGER UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN email_verify_sent TIMESTAMP NULL DEFAULT NULL;
