# Threat model: outside attackers

Scope: bad actors with no legitimate admin access. Insider misuse is out of scope. The goal is to limit what a stolen session, key, token or database/backup leak can do, and to reconstruct what an attacker did.

Reviewed from master `c029787` plus this branch. Nothing here was probed against production.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Customer PII (email, billing name, address, tax id, IPs) | `users`, `audit_log`, `swap_order_client` | Data theft, phishing material |
| Payment instruments and provider tokens | `user_payment_method`, `subscription_payment.external_data` | Payment fraud |
| Host and infrastructure credentials | `vm_host.api_token`, `vm_host.ssh_key`, `router.token`, `dns_server.token`, `tunnel_pool.private_key`, `ip_provider.token` | Pivot to Proxmox, routers, DNS |
| Encryption key | `LNVPS_ENCRYPTION_KEY` (k8s secret) | Decrypts everything above |
| Session signing secret | `session.secret` | Forges any account's session |
| Admin identities (NIP-98 keys, roles) | `admin_user_roles` | Full control |
| Money paths | refunds, account credit, discounts | Direct loss |
| Customer compute and IP space | VMs, `185.18.221.0/24` | Free VMs, abuse hosting |
| Support agent and its tools | `lnvps_agent` | Steering by attacker-written text |

## Entry points and trust boundaries

1. Public API (`lnvps_api`): NIP-98 and session JWT (OAuth, WebAuthn). Untrusted.
2. Payment webhooks (`/api/v1/webhook/{revolut,stripe}`): signature verified by `payments_rs`. Untrusted until verified.
3. Unauthenticated LNURL-pay and contact endpoints. Untrusted.
4. Admin API (`lnvps_api_admin`): NIP-98 plus role permissions. Authenticated, still reachable from the internet if exposed.
5. Support agent: reads customer text (mail, Nostr DMs, web chat). Text is untrusted, the agent holds DB read access and power controls.
6. Customer VMs: hostile tenants on shared hosts. Boundary is Proxmox, the host firewall (`lnvps_fw`) and VLANs.
7. Backups and the database: trusted store, but a leak must not expose plaintext.
8. External AI agents (mail triage, admin API skills) holding admin tokens: not part of this repository, same trust problem as 5.

## Attacker goals

Free VMs, refund or payment fraud, account takeover, data theft, abuse hosting, pivot to hosts or Proxmox, denial of service, steering our own agents.

## Findings

Severity: H high, M medium, L low.

| # | Sev | Finding | Exploit path | Location | Fix | Slice |
|---|---|---|---|---|---|---|
| 1 | H | No tamper-evident record of actions. A stolen admin session can refund, delete or reassign roles with only `vm_history` as trace, and a DB write can alter it | Compromise a session or the DB, act, edit history | previously only `ip_order_audit`, `vm_history` | Append-only hash-chained `audit_log`, write refused if the log write fails, JSON line stream per entry for off-box capture, verify command and admin endpoint | A1 |
| 2 | H | Billing name, address, city, state, postcode and tax id stored in plaintext | DB or backup leak | `lnvps_db/src/model.rs` `User`, migration `20250501132143_billing_info.sql` | Typed as `EncryptedString`, columns widened, rotation tool encrypts old rows | E1 |
| 3 | H | Release builds could start with no key (PII and tokens in plaintext) or auto-generate a key file on an ephemeral disk, losing all data on redeploy | Misconfigured deploy | `lnvps_api/src/bin/api.rs`, `lnvps_db/src/encryption.rs` | Release builds refuse to start without a key and refuse `auto-generate` | E2 |
| 4 | M | No key rotation. One leaked key decrypts all history forever | Key leak | `lnvps_db/src/encryption.rs` | Key ring (`LNVPS_ENCRYPTION_KEY_PREVIOUS`), `rotate_encryption_key` bin re-encrypts every encrypted column, then the old key is dropped | E3 |
| 5 | M | Plaintext IPs and user agents on `users.geo_ip`, `swap_order_client`, `ip_order_audit` and the new `audit_log` | DB leak | `lnvps_db/src/mysql.rs` (purge helpers exist for geo and swap) | Decided: truncate `audit_log.ip` to /24 (IPv4) or /48 (IPv6) after 90 days, once the off-box copy exists (#636) | Done: daily `PurgeExpiredRecords` job calls `truncate_audit_ips`; the row hash covers the truncated form so the chain stays valid |
| 6 | M | Rate limits are per IP and in-process only. Only WhatsApp sends have a per-account limit. VM create, payment and refund have no per-account bound. The client IP is the right-most `X-Forwarded-For`, spoofable if the pod is reachable without the proxy | Botnet spreads across IPs to brute force or mass-order | `lnvps_api_common/src/rate_limit.rs`, `client_ip.rs` | Per-account limiters on order, payment and refund endpoints, shared (Redis) counters, burst alert | Done: `AccountLimiter` (Redis `INCR`+`EXPIRE`, memory fallback), burst logged on target `lnvps_abuse` |
| 7 | M | Customer credentials cannot be scoped. A session JWT lives 30 days and grants the whole account. There is no read-only or VM-only token and no last-used IP | Stolen session or token has full account power | `lnvps_api_common/src/session.rs` (`DEFAULT_SESSION_TTL_SECS`) | Scoped, expiring API tokens with last-used tracking, shorter session TTL | Done: `read` and `vm` scopes, hashed at rest, 7 day default session |
| 8 | M | Admin destructive and financial actions need no step-up. A stolen admin NIP-98 key or session can refund or purge immediately | Stolen admin key | `lnvps_api_admin/src/admin/vms.rs`, `credit.rs`, `roles.rs` | Fresh WebAuthn assertion for refund, purge, credit adjust, role change | Done: `X-Step-Up` token from `/api/v1/webauthn/step-up/finish`, enforced when admin `require-step-up` is on |
| 9 | M | NIP-98 single-use tracking is in process memory, so a captured header can be replayed once per replica inside the 60 s window | Capture a header, replay against another replica | `lnvps_api_common/src/nip98.rs` (`SEEN_EVENTS`) | Share the seen-set through Redis | Done: `SET NX EX` via `RedisSeenSet`, local set kept as first check |
| 10 | H | Agents handling attacker text could be given admin tokens. A mail saying "refund VM 5" must never act | Prompt injection through support mail, ticket text, VM names, hostnames | `lnvps_agent/src/tools/mod.rs`, `agent/db/mod.rs` | Code guard: any tool named like a refund, delete, extend, credit, role or token action is refused at execution time and a test asserts no offered tool set contains one. Third-party text channels get read-only tools. Written rule below | G1 |
| 11 | M | TLS verification can be switched off for host API clients (`allow_invalid_certs`) | MITM on the management network | `lnvps_api_common/src/json_api.rs:91` | Keep off in production, pin CA per host | open |
| 12 | L | Backup CronJob output encryption cannot be verified from this repository | Backup leak | k8s manifests live outside the repo | Checked `~/git/v0l-k8s/lnvps/mysql.yml`: the CronJob runs `mariadb-dump | gzip` onto the `data` PVC (`backups/`, 14 day retention). Not encrypted by the job, and the root password is inline in the manifest. Proposed change in the Operations section | Verified, change proposed |
| 13 | M | Tenant abuse (scanning, proxying) known from the intel-sec cases: symmetric traffic, k3s agents, throwaway email domains, card-after-abandoned-BTC | Pay, rent, abuse | `lnvps_api/src/api/abuse.rs`, `lnvps_api_admin/src/admin/abuse.rs` | Alert heuristics (new account plus large template plus throwaway domain) | Done: `abuse_signals`, three signals raise an admin notification on order |

### What was already in place

NIP-98 has a 60 s window and single-use check. Session JWTs carry `session_version` for revocation and a separate `typ` for node tokens. Webhooks are size-capped and signature verified. A per-IP limiter covers auth ceremonies, verification codes and LNURL-pay. The support agent tool sets are read-only plus reversible power controls on authenticated live chat.

## Agent safety rule

Any process that reads customer-supplied text (support mail, Nostr DMs, web chat, tickets, VM names, hostnames, app config) is treated as steerable by the author of that text.

1. It never holds an admin token. It holds the narrowest credential that does its job, preferably read-only database access.
2. It never performs a refund, delete, purge, credit change, role change, token or key creation, email change, or extension of paid time. It drafts, a human performs.
3. Reversible power controls (start, stop, restart) are only offered on channels where the authenticated customer is present (live chat), never on mail or public channels.
4. Text in a tool result is data, not instructions.
5. Code enforces this: `lnvps_agent/src/tools/guard.rs` refuses human-only tool names at execution and its tests fail if any tool set offers one. Adding a destructive tool means changing the guard list, which shows up in review.

External agents (mail triage, admin-API skills) are not enforced by this repository. Give them an admin role limited to `view` permissions, and never `Payments`, `AccountCredit`, `Roles` or `VirtualMachines::Delete`.

## Operations

- Encryption key: provided only through `LNVPS_ENCRYPTION_KEY` from a Kubernetes secret (or an existing key file). Release builds exit at startup if neither is present.
- Rotation: generate a new key, set `LNVPS_ENCRYPTION_KEY` to it and `LNVPS_ENCRYPTION_KEY_PREVIOUS` to the old one, deploy (old values still decrypt), run `rotate_encryption_key`, then remove the previous key.
- Verify the audit chain: `verify_audit_log --config config.yaml` exits non-zero on tampering, or `GET /api/admin/v1/audit-log/verify`.
- Search: `GET /api/admin/v1/audit-log?actor_id=&action=&target_type=&target_id=&since=&until=` (needs `audit::view`).
- Off-box: every entry is logged as JSON on log target `lnvps_audit` (`warn` level with a `high-risk` prefix for role changes, refunds, deletes, purges, token and passkey creation). Ship that stream to Loki or a write-once bucket. The DB chain head can then be compared with the shipped copy, so a database compromise cannot silently erase history. The table also rejects UPDATE and DELETE through triggers.
- Deletion of customer data: the audit log intentionally keeps rows. Do not store secrets in `before_summary` or `after_summary`.

- Abuse alerts: filter the log stream for target `lnvps_abuse` (burst of per-account limit hits, suspicious orders) and `lnvps_audit` lines starting `high-risk` (role changes, refunds, deletes, purges, token and passkey creation, email change).
- IP retention: the daily purge job truncates `audit_log.ip` older than 90 days. Run it only once the off-box copy of the `lnvps_audit` stream is confirmed, because truncation is irreversible.
- Step-up: set `require-step-up: true` and a `session.secret` (same value as the public API) in the admin config. Admins get a token from `POST /api/v1/webauthn/step-up/start` then `finish` on the public API and send it as `X-Step-Up` (valid 5 minutes).
- Backup encryption (proposal, nothing deployed): in `mysql.yml` pipe the dump through `age -r <recipient>` (or `gpg --encrypt`) before it lands on the PVC, keep only the public recipient in the manifest and the private key offline, and move the root password into a Secret referenced by env. Old unencrypted dumps on the PVC need purging after the first encrypted run.

## Summary

| Finding | Slice | Status |
|---|---|---|
| 1 audit log | A1 | Done for: admin role assign/revoke, VM delete/purge/transfer, refunds (queue and record), credit adjust, user SSH key add, user VM delete. Table, chain, triggers, verify bin, admin search and verify API, JSON stream. Also login (OAuth, passkey), token create and revoke, passkey add, step-up, email change, firewall rules, reinstall, and every `vm_history` and `ip_order_audit` entry is mirrored. DNS has no customer endpoint to audit |
| 2 billing PII | E1 | Done (types, widened columns, rotation tool encrypts existing rows). Keyed hash for search not needed: no query filters on these columns |
| 3 no-key start | E2 | Done |
| 4 rotation | E3 | Done (key ring, `rotate_encryption_key`) |
| 5 IP retention | | Done (#636) |
| 6 rate limits | | Done (#636) |
| 7 scoped tokens | | Done (#636) |
| 8 step-up | | Done (#636), off until `require-step-up: true` |
| 9 shared replay set | | Done (#636) |
| 10 agent guardrails | G1 | Done in `lnvps_agent`; external agents need operational role limits |
| 11 TLS verify | | Open |
| 12 backup encryption | | Checked, not encrypted, fix proposed below |
| 13 abuse heuristics | | Done (#636) |
