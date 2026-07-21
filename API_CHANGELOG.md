# API Changelog

All notable changes to the LNVPS APIs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **Sunset a host** (issue #175) — hosts now support an optional `sunset_date`. Setting it **decommissions the host**: the host is forced `enabled = false` (so it takes no new VMs, via the existing disabled-host handling), while existing VMs keep running and can still be **renewed up to the sunset date**. Once a VM's current expiry has reached the sunset date, its renewals are rejected — users renew right up to the deadline, then must migrate to another VM. Set/clear via the admin host endpoints: `sunset_date` is accepted on `POST /api/admin/v1/hosts` and `PATCH /api/admin/v1/hosts/{id}` (send `null` to un-sunset — `enabled` is left untouched so the operator re-enables explicitly), and returned on the admin host info responses. The user-facing VM status (`GET /api/v1/vm/{id}` and `GET /api/v1/vms`) now includes a `host_sunset_date` field on VMs whose host is being sunset (omitted otherwise), so clients can warn the user to migrate before the deadline.
- **Payment method minimum amount** — payment method configs now support a `min_amount` (+ `min_amount_currency`) in smallest currency units. Payments whose gross total (net + tax + processing fee) is below the configured minimum are rejected for that method, avoiding uneconomic small charges (e.g. Revolut's flat 20c base fee dominating a tiny payment). Exposed on the public `GET /api/v1/payment/methods` and admin `vm`/payment method config endpoints (`GET/POST/PATCH /api/admin/v1/payment_method_configs`). Lightning has no minimum. Fixes #170.
- **New OS distributions** — the `OsDistribution` / `ApiOsDistribution` enum now includes `almalinux`, `rockylinux`, `alpine`, `nixos`, `openbsd`, `netbsd`, `gentoo`, and `voidlinux`. Affects `GET /api/v1/image`, VM status responses, and the admin VM OS image endpoints (`GET/POST/PATCH /api/admin/v1/vm_os_image`).

### Changed

- **Renewals are now bounded by a maximum prepay window** — a renewal is rejected (with a clear error) once it would push a subscription's expiry beyond `now + max_prepay_days`. This bounds both an oversized single `?intervals=N` request and repeated back-to-back renewals (once expiry is ~the window out, further renewals are rejected until real time passes). Affects `POST /api/v1/vm/{id}/renew` and `POST /api/v1/subscriptions/{id}/renew`. The limit is configured per company (`max_prepay_days` on `POST`/`PATCH /api/admin/v1/companies`, also returned on company info; `0` inherits the global default) with a global fallback (`max-prepay-days` in service config, default 365 days). It composes with host sunsetting — the effective ceiling is the earlier of the sunset date and the prepay window. The effective window is also surfaced to clients on the user-facing VM status (`GET /api/v1/vm/{id}` and `GET /api/v1/vms`) as `max_prepay_days`, so the UI can cap the renewal interval selector to what the server will accept.
- **Exchange module: precise conversions + fiat FX rates** — currency conversion is now integer-precise (done in `f64` on smallest-unit values instead of routing through `f32`, which previously lost a unit, e.g. €1.00 → 999,999 msat instead of 1,000,000). The exchange service now also pulls fiat FX rates (from frankfurter.app / ECB) between the distinct company billing currencies — anchored on each company's own `base_currency`, not a hardcoded base, and only when companies bill in more than one fiat currency — alongside BTC prices. The pricing engine can resolve arbitrary currency pairs directly, inverse, or via a BTC/EUR cross rate. The processing-fee base amount is now properly converted into the transaction currency instead of being used as-is.
- **OS image downloads now run in parallel across hosts** — the `DownloadOsImages` worker job previously processed hosts strictly sequentially (each host waited for the previous host to finish all images). Hosts are now processed concurrently; images on a single host remain sequential to avoid saturating that host's storage backend. Affects the admin `POST /api/admin/v1/vm_os_images/{id}/download` endpoint and the periodic image check.
- **DNS is now best-effort during VM provisioning** — forward (A/AAAA) and reverse (PTR) DNS records are convenience only and no longer block or roll back a deploy. Previously a reverse-DNS failure (notably OVH rejecting a PTR with a `4xx` until the forward name resolves — a fatal, non-retried error) tore down the whole pipeline and destroyed the freshly-created VM. Now such failures are logged and the deploy proceeds; the VM keeps its IPs and MAC. Any records that failed to create are reconciled automatically on the periodic VM check (and can still be forced via the existing DNS patch job).

### Fixed

- **On-chain payment config now imported on existing deployments** — the payment method config data migration skipped entirely when *any* config already existed, so deployments that had already imported their LND Lightning config never got the newer LND on-chain config seeded. The migration now checks per payment method (Lightning / OnChain / Revolut) and imports only the missing ones.
- **OS image checksum discovery hardened** — checksum (`SHASUMS`) fetching now sends a `User-Agent` header (some CDNs, e.g. CloudFront in front of `cloud.centos.org`, return 403 without one), enforces connect/request timeouts and a 1 MiB download cap, probes additional file conventions (`CHECKSUM`, `.SHA256SUM`/`.SHA512SUM`, Rocky's `.CHECKSUM`), parses digest-only sidecar files (e.g. Alpine's `.sha512`), handles filenames containing parentheses in BSD-format lines, and logs (instead of silently ignoring) transient errors while probing. Affects checksum auto-discovery used by admin VM OS image management.
- **Clean up orphaned custom templates** — a startup data migration now deletes `vm_custom_template` rows not referenced by any VM. Custom templates are 1:1 with their VM, but historical hard-deletes could leave orphans behind. The migration is idempotent (a no-op once clean).

- **Purge historical never-paid soft-deleted VMs** — a startup data migration now hard-deletes VMs that were soft-deleted (`deleted = 1`) while their subscription was never paid (`is_setup = 0`), along with their `vm_history`, `vm_firewall_rule`, `vm_ip_assignment` and orphaned subscription. Never-paid VMs are purged going forward by the worker, but the worker skips already soft-deleted rows so older ones lingered. Ever-paid VMs are left untouched to preserve payment history. Idempotent (a no-op once clean).

- **Data migrations now log their progress** — each startup data migration logs when it starts and a summary of what it did (e.g. "purged 3 of 3 never-paid soft-deleted VM(s)"), so no-op runs are no longer silent.

- **Cascade-delete owned child tables** — added `ON DELETE CASCADE` to pure owned-child tables (SSH keys, passkeys, saved payment methods, referrals/payouts, cached router tunnel/BGP inventory, custom pricing disks). Fixes latent FK-violation failures when deleting a router with cached inventory or a referral with payouts, and simplifies user purges.

### Added

- **On-chain Bitcoin payments** (issue #109) — VMs and subscriptions can now be paid on-chain. A new `onchain` payment method is accepted wherever a payment method is selected (e.g. `GET /api/v1/vm/{id}/renew?method=onchain`); the payment's `data` field returns `{ "onchain": { "address": "bc1…" } }` with a freshly derived receive address (BTC only). The txid is recorded on the payment (`external_id`) once the deposit confirms. Deposits are never rejected: the exchange rate is re-calculated when the transaction is discovered, and the time credited is pro-rated by the value received at that rate (partial, late and over-payments included). Any further deposit to an already-settled address automatically creates a new pro-rated renewal payment. Admin payment-method configs accept a new `onchain` provider type (reuses the LND wallet of the Lightning backend).

- **Transfer a VM to another user (admin)** — new `POST /api/admin/v1/vms/{id}/transfer` (`virtual_machines::update`) reassigns a VM to another user account, e.g. for account recovery (issue #178). It atomically moves the VM and its billing subscription to the target `user_id` and clears the old owner's SSH key from the VM. The change is recorded in VM history as a new `transferred` action. Rejects deleted VMs, self-transfers (`409`) and unknown target users (`404`). Body: `{ user_id, reason? }`.

- **Change OS during re-install** — `PATCH /api/v1/vm/{id}/re-install` now accepts an optional `{ image_id }` body to switch the VM to a different OS image as part of the re-install (issue #177). When omitted, the VM is reinstalled with its current image (unchanged behaviour). The chosen image must exist and be enabled, and the change is recorded in VM history.

- **OS image popularity** — `GET /api/v1/image` now returns a `popularity` field for each OS image: the fraction (0.0–1.0) of active VMs currently using that image (issue #70).

- **Delete (purge) a user (admin)** — new `DELETE /api/admin/v1/users/{id}` (`users::delete`) permanently removes a user and all of their associated data (soft-deleted VMs and their history/IP/firewall rows and 1:1 custom templates, SSH keys, subscriptions and payments, referral records, Nostr domains, passkeys and saved payment methods) in a single transaction. Rejected if the user still has any live (non-deleted) VMs — those must be deleted first so hypervisor resources are released. Admins cannot delete their own account.

- **Manage user passkeys (admin)** — new admin endpoints to view and revoke a user's WebAuthn passkeys.
  - `GET /api/admin/v1/users/{id}/passkeys` (`users::view`) lists a user's registered passkeys (id, optional device `name`, hex `cred_id`, `created`, `last_used`). Credential material is never exposed.
  - `DELETE /api/admin/v1/users/{id}/passkeys/{passkey_id}` (`users::update`) revokes a single passkey. Returns `404` if the passkey doesn't belong to the user, and refuses (`400`) to remove the **last** passkey of a passwordless (`webauthn`) account to avoid locking the user out.
  - `GET /api/admin/v1/users/{id}` now also returns `account_type` (`nostr` | `oauth` | `webauthn`) and `passkey_count`.

- **Permanently delete VMs (admin)** — `DELETE /api/admin/v1/vms/{id}` now accepts an optional `purge` flag in the request body (issue #168).
  - VMs that have **never been paid** (their subscription was never set up) are now **hard-deleted** from the database instead of being soft-deleted, both when an admin deletes them and when the worker's hourly cleanup removes unpaid VMs. Nothing is left behind: the VM row and all related records (history, firewall rules, IP assignments, and the VM's own subscription + line items + payment history) are removed.
  - `purge: true` lets a **super_admin** permanently delete *any* VM — including VMs with payment history — clearing up all related entities. This is intended for removing test VMs. The flag is rejected with `403` for non-super-admins (checked before the VM lookup); regular deletes and never-paid purges are unaffected.

- **Import existing host VMs (admin)** — new admin endpoints to adopt VMs that exist on a host but aren't tracked in the database (issue #166).
  - `GET /api/admin/v1/hosts/{id}/vms/unmanaged` lists VMs present on the host with no matching database record (returns host vmid, mapped database id, name, CPU/memory/disk specs, storage, MAC, running state). The admin service dispatches a discovery job to the worker and reads the reply over a temporary Redis pub/sub channel.
  - `POST /api/admin/v1/hosts/{id}/vms/import` (`{ host_vm_id, user_id, reason? }`) imports one VM: it is assigned to `user_id` and billed via the region's **custom pricing** (required — import fails if the region has none), capturing the VM's current CPU/memory/disk specs into a custom template. Currently supports Proxmox hosts. Returns a `job_id`.

- **Per-request OAuth return URL** — `GET /api/v1/oauth/{provider}/login` now accepts an optional `?redirect=<url>` to override the configured `success-redirect` for that login only (e.g. `http://localhost:3000/oauth/complete` in dev). The URL is validated against a new `allowed-redirects` allowlist (`localhost` host always allowed; `success-redirect` always implicitly allowed) and rejected with `400` otherwise, then round-tripped through the signed `state`. See the OAuth login flow in API_DOCUMENTATION.md for details and a `config.yaml` example.

- **2026-07-18** - Passwordless WebAuthn / passkey login
  - New `fetch`-based endpoints `POST /api/v1/webauthn/register/start` + `/register/finish` (creates a passwordless account) and `POST /api/v1/webauthn/login/start` + `/login/finish` (usernameless / discoverable login). Each `start` returns a `challenge` for the browser `navigator.credentials` API plus an opaque signed `state`; the matching `finish` posts back that `state` with the credential and returns a `{ token, token_type, expires_in }` session response.
  - Uses the same stateless session **JWT** as OAuth (`Authorization: Bearer <jwt>`), so passkey users reach every existing authenticated endpoint. Configured under a new `webauthn` config section (`rp-id`, `rp-origin`, `rp-name`); the signing secret lives in the shared `session` block (below).
  - Passkey accounts are stored with a new `account_type` of `webauthn` and a synthetic identity (`sha256("webauthn\\0{user_handle}")`, in a namespace provably disjoint from OAuth). Like OAuth accounts they have no usable Nostr key: NIP-17 DMs, npub display and LIR signing are gated off, and `GET /api/v1/account` reports `account_type: "webauthn"`. Credentials are stored in the new `user_webauthn_credentials` table (one account may register several devices).
  - **Add passkeys to existing accounts:** authenticated endpoints `GET /api/v1/webauthn/credentials` (list), `POST /api/v1/webauthn/credentials/start` + `/finish` (register another passkey to the current account — any account type, Nostr/OAuth/passkey), and `DELETE /api/v1/webauthn/credentials/{id}` (remove one). A later discoverable login with such a passkey resolves back to the same account (by credential id), so its session token carries the account's real identity. A pure passkey account cannot delete its only credential.

- **2026-07-18** - Generic OAuth / OIDC login (Google, GitHub, Facebook, Apple)
  - New endpoints `GET /api/v1/oauth/{provider}/login` (redirects to the provider) and `GET`/`POST /api/v1/oauth/{provider}/callback` (exchanges the authorization code, resolves/creates the user and issues a session token). Providers are configured under the new `oauth` config section, each with a `type` of `google`, `github`, `facebook`, `apple`, or generic `oidc`.
  - Built-in flavors handle each provider's quirks: GitHub's `User-Agent` requirement and numeric `id` subject, Facebook's Graph `me` endpoint, and Sign in with Apple's `id_token`-based subject, dynamically-signed **ES256** client secret, and `form_post` (POST) callback.
  - After a successful login the API issues a stateless session **JWT**. It is accepted on every existing authenticated endpoint via `Authorization: Bearer <jwt>`, alongside the existing `Authorization: Nostr <event>` (NIP-98) scheme. The JWT signing secret and lifetime live in a shared top-level `session` config block (`session.secret`, `session.ttl`) used by both OAuth and WebAuthn — required whenever either login method is enabled.
  - On first login the provider's email is synced into the account (marked verified when the provider asserts it) and email notifications are enabled by default, since OAuth accounts have no NIP-17 channel. GitHub's primary verified address is fetched from `/user/emails`; Apple's email comes from the `id_token`. The sync is non-destructive — a user's later email edits are not overwritten — and best-effort (a sync failure never blocks login).
  - OAuth accounts are stored with a new `account_type` of `oauth` and a synthetic identity (`sha256("{provider}:{subject}")`) in place of a Nostr pubkey. Nostr-only features (NIP-17 DMs, npub display, LIR agreement signing) are gated to native Nostr accounts.
  - `GET /api/v1/account` now returns `account_type` (`nostr` | `oauth`, read-only) so the frontend can hide Nostr-only UI for OAuth users. `PATCH /api/v1/account` rejects enabling `contact_nip17` for OAuth accounts (their pubkey is not a usable Nostr key).

### Changed

- **2026-07-18** - Drop npub from invoices and VM-created notifications
  - VM-created notifications (user + admin) no longer include the `NPUB:` line — it was noise and meaningless for OAuth accounts.
  - The rendered invoice replaces the `Nostr Pubkey` line with the account `Email` (shown only when set), which is a universal identifier across Nostr and OAuth accounts.

### Fixed

- **Passkey usernameless login failing on non-synced authenticators** — passkey registration now always creates a **discoverable (resident-key)** credential (`residentKey: "required"`, `userVerification: "required"`), so "Sign in with a passkey" reliably works on security keys and Windows Hello, not just synced platform passkeys (iCloud Keychain / Google Password Manager). Previously registration went through webauthn-rs' high-level flow which hardcodes `residentKey: "discouraged"`, causing those authenticators to store a non-discoverable credential that usernameless login (`start_discoverable_authentication`) couldn't find (`NotAllowedError`). Applies to both new-account registration and adding a passkey to an existing account. New optional config `webauthn.require-resident-key` (default `true`) can relax this for a misbehaving authenticator. Trade-off: a security key with no free resident-key slots now fails clearly at registration instead of silently registering an unusable-for-login credential.

- **2026-07-18** - Referral commission rate not visible to referrers (user API)
  - `GET`/`POST`/`PATCH /api/v1/referral` only returned `referral_rate`, the per-referrer override, which is `null` for most referrers (it's admin-set). A referrer with an unset override therefore saw no commission rate even though the default company rate applied. The response now also includes `effective_referral_rate` (whole %): the rate that currently applies — the override when set, otherwise the default (primary) company's `referral_rate`.

### Added

- **2026-07-18** - Admin referral code renaming
  - `PATCH /api/admin/v1/referrals/{id}` now accepts an optional `code` to rename a referral enrollment's code. Renaming **cascades**: every existing VM that recorded the old code at ordering time (`vm.ref_code`) is re-pointed to the new code in the same transaction, so all prior usage/earnings stay attributed to that referrer (e.g. when assigning a user a custom vanity code without losing their existing referrals). This also relinks a user's enrollment to a historical `vm.ref_code` that was tracked before the user auto-generated their own code. The new code must be non-empty and not already in use by another referral (409-style validation error otherwise). Requires `referral::update`.

- **2026-07-18** - Referral program: leave + per-VM usage (user API)
  - `DELETE /api/v1/referral` lets a referrer leave the program. Blocked (409) while a payout is pending, or when paid payout history exists (retained for accounting).
  - `GET /api/v1/referral/usage` returns a **paginated** per-referred-VM breakdown (query params `limit` default 50/max 100, `offset` default 0; response is `{ data, total, limit, offset }`). Each row has `created`, `amount` (the VM's first payment), `currency`, `effective_rate`, and `commission`. The referred VM's id is intentionally not exposed so a referrer cannot map commission back to specific customers' VMs.

- **2026-07-18** - Automated referral commission payouts
  - A new opt-in worker job pays referrers their accrued **BTC** commission over Lightning. For each referrer whose owed commission (earned minus already paid/reserved) clears a configurable threshold, it reserves a payout, fetches a BOLT11 invoice (LNURL-pay for a `lightning_address` referrer, or NWC `make_invoice` for an `nwc` referrer), pays it from the node, and records the preimage. Non-BTC (fiat) commission is not auto-paid and is left for manual admin payout. Enabled by adding a `referral` config section (`min-payout-sats`, default 1000); when omitted, automated payouts are disabled. `GET /api/v1/referral` payout records now include `pre_image` (hex, once settled).

- **2026-07-18** - Admin referral program management
  - New admin endpoints under the `referral` RBAC resource (granted to `super_admin`): `GET /api/admin/v1/referrals` (paginated; `search` by code substring or 64-char hex pubkey), `GET /api/admin/v1/referrals/{id}` (referral + per-currency earned commission + payout history + success/failed counts), `PATCH /api/admin/v1/referrals/{id}` (set/clear the per-referrer commission override), `GET`/`POST /api/admin/v1/referrals/{id}/payouts` (list / create a manual payout record), and `PATCH /api/admin/v1/referrals/{id}/payouts/{payout_id}` (mark paid / set invoice / set preimage for reconciliation). NWC secrets are never exposed.

- **2026-07-18** - Flexible referral payout mode (replaces `use_nwc`)
  - The referral payout method is now an extensible `mode` enum instead of the `use_nwc` boolean. `GET /api/v1/referral` returns `mode` (`lightning_address` | `nwc` | `account_credit`) instead of `use_nwc`. `POST`/`PATCH /api/v1/referral` accept `mode` instead of `use_nwc`: `lightning_address` (default) requires a resolvable `lightning_address`; `nwc` requires a configured NWC connection; `account_credit` is reserved for a future account-balance payout and is currently rejected. Existing enrollments migrate `use_nwc = true` → `nwc`, otherwise `lightning_address`.

- **2026-07-18** - Referral commission rate (percentage of first payment)
  - The referral program now pays a commission = a percentage of each referred VM's **first** payment. The effective rate is per-referrer with a company default: `company.referral_rate` (new, default `0`) applies unless the referrer has an override. Admin company `POST`/`PATCH /api/admin/v1/companies` accept `referral_rate` (whole %, `>= 0`) and GET/list responses expose it.
  - `GET /api/v1/referral` now returns `referral_rate` (the per-referrer override, `null` = use company default; read-only — set by admins) and its `earned` amounts are now the commission (`payment * effective_rate%`) rather than the full first payment.
  - `GET /api/admin/v1/reports/referral-usage/time-series` rows gain `effective_rate` and `commission`.

- **2026-07-18** - OSS (One-Stop Shop) VAT report
  - `GET /api/admin/v1/reports/oss` aggregates cross-border EU B2C sales (`tax_treatment = oss_b2c`) by filing period and destination member state for transcription onto an OSS VAT return. Query params: `start_date`, `end_date` (YYYY-MM-DD), optional `company_id` (`0`/omitted = all), and `period` = `quarter` (default, calendar Q1-Q4) | `bimonthly` (two-month buckets B1-B6). Rows are keyed by `(period, company, destination country, VAT rate)` and expressed in each seller company's base currency using the exchange rate frozen on each payment. Only paid payments are counted. Requires `analytics::view`.

- **2026-07-18** - VIES trader name/address verification on tax ID
  - `PATCH /api/v1/account` now sends the customer's billing name/address to VIES alongside the VAT number so VIES can match them against the registered values. An invalid VAT number is still a hard error; name/address mismatches are non-fatal. The endpoint response body changed from `null` to `{ "warnings": [string] }` (a `warnings` array is present only when VIES reports a confirmed field mismatch, e.g. name or address; the account is still saved).

- **2026-07-18** - Admin user list gains region/role/has_vms filters
  - `GET /api/admin/v1/users` accepts optional query params to narrow the list (combined with AND, alongside the existing `search` pubkey filter): `region_id` (only users with at least one non-deleted VM whose host is in that region), `role` (`super_admin`/`admin`/`read_only` — only users with an active assignment to that admin role), and `has_vms` (`true`/`false` — filter by whether the user has any non-deleted VMs). Requires `users::view`.

- **2026-07-18** - Toggle subscription auto-renewal (user-facing)
  - `PATCH /api/v1/subscriptions/{id}` accepts optional `auto_renewal_enabled` to enable/disable automatic renewal on an existing subscription. Ownership is enforced (NIP-98). Returns the updated `ApiSubscription`. Previously auto-renewal could only be set at creation time (`POST /api/v1/subscriptions`) or via the admin API.

- **2026-07-18** - Pay VM upgrades with saved payment methods
  - `POST /api/v1/vm/{id}/upgrade` now accepts `method=nwc` and `method=saved` (with optional `payment_method_id`), matching the renewal endpoint. Saved methods are collected on the spot: NWC pays the Lightning invoice via the user's saved wallet, and `saved` charges a saved Revolut card off-session. For these off-session methods the request briefly waits (~10s) for settlement, returning the `VmPayment` as `is_paid: true` if it settled in time, otherwise pending (settles asynchronously). An immediate charge failure returns an error and leaves the payment unpaid.
  - `GET /api/v1/subscriptions/{id}/renew` accepts the same `method=nwc` for parity with VM renewals/upgrades.

- **2026-07-18** - VM upgrades now include VAT and processing fee
  - Upgrade payments (`POST /api/v1/vm/{id}/upgrade`) are now charged VAT on the net upgrade cost plus the payment processing fee (previously both were `0`). `VmUpgradeQuote` (`POST /api/v1/vm/{id}/upgrade/quote`) gains `tax` and `processing_fee` fields so the full upgrade total can be shown up-front.

- **2026-07-18** - VM status exposes its subscription id
  - `GET /api/v1/vm` and `GET /api/v1/vm/{id}` responses include a read-only `subscription_id`. A VM is billed by a subscription underneath, so clients can renew a VM by renewing its subscription (`GET /api/v1/subscriptions/{id}/renew`) and unify VM/subscription payment handling. `null`/omitted for VMs that were never paid.

- **2026-07-18** - VM host regions expose their seller company
  - `VmHostRegion` (embedded in template/VM responses, e.g. `GET /api/v1/vms`, `GET /api/v1/vm/templates`) now includes a read-only `company_id`. Match it against `account.tax[].company_id` to display the VAT rate that applies to a specific VM up-front.

- **2026-07-15** - Admin API exposes IP-derived geolocation evidence on users
  - `AdminUserInfo` (returned by `GET /api/admin/v1/users`, `.../users/{id}`, `.../users/by-email`) now includes read-only `geo_country_code` (ISO 3166-1 alpha-3, resolved from the client IP as independent VAT place-of-supply evidence), `geo_ip`, and `geo_updated` (ISO 8601).
  - `PATCH /api/admin/v1/users/{id}` accepts optional `geo_country_code` (validated alpha-3; empty string clears) and `geo_ip` (empty string clears). Editing either bumps `geo_updated` to the edit time. Requires `users::update`.

- **2026-07-15** - VM status now includes the actual deletion date
  - `GET /api/v1/vms` and `GET /api/v1/vms/{id}` responses include a read-only `deleting_on` (ISO 8601) — the date the VM will be deleted if not renewed. This is `expires` plus the subscription's grace period, which is dynamic (tiered by subscription age), so the field reflects the real deletion date rather than a fixed offset. It is `null`/omitted for VMs with no expiry (never paid).

- **2026-07-17** - Account info now includes the applicable tax rate
  - `GET /api/v1/account` returns a read-only `tax` array with one entry per seller company: `{company_id, company_name, rate, country_code, treatment}`. The rate is determined from the user's current billing information (VAT number, declared country, IP-derived country) using the same EU place-of-supply rules as invoicing, so frontends can show the expected VAT up-front. The field is ignored on PATCH.

### Changed

- **2026-07-18** - New VMs default to auto-renewal enabled
  - Ordering a VM (standard or custom template) now creates its subscription with `auto_renewal_enabled = true` by default (previously `false`), matching the subscription-creation API which already defaulted on. Auto-renewal only actually charges when the user has a saved payment method (NWC wallet or Revolut card); users without one are unaffected and still receive the normal expiry reminders. Users can opt out anytime via `PATCH /api/v1/subscriptions/{id}` (`auto_renewal_enabled: false`).

- **2026-07-16** - Invoices now show the VAT treatment
  - `GET /api/v1/payment/{id}/invoice` renders the applied VAT rate on the tax line (e.g. "VAT 23% (IRL)"), and prints a legal note for **reverse charge** ("VAT reverse charged — the recipient is liable to account for VAT (Article 196, Council Directive 2006/112/EC)") and **out-of-scope** ("Outside the scope of EU VAT.") supplies. Seller and customer VAT numbers were already shown.

- **2026-07-16** - VAT determination frozen on every payment (OSS filing / audit)
  - Each `subscription_payment` now stores the VAT determination made at sale time: a per-line-item `tax_breakdown` (JSON array of `{net, tax, rate, country_code, treatment}`) as the authoritative record, a uniform summary (`tax_rate`, `tax_country_code`, `tax_treatment`, left NULL when the payment mixes rates/treatments across line items), and the customer `tax_evidence` (declared country, IP-derived country, VAT number). Admin time-series reports expose these per payment.
  - The breakdown is per-line-item so a payment whose lines resolve to different sellers (e.g. reverse charge on one, domestic VAT on another) is recorded losslessly rather than collapsed to one rate.

- **2026-07-16** - Retired the defunct `vm_payment` table
  - `vm_payment` is dropped; all payments live in `subscription_payment` (the public API already read from it). The startup backfill's payment-copy phase (Phase 2) and all `vm_payment` models/queries/DTO conversions are removed. The `ApiVmPayment` response shape and the `vm_payment` RBAC resource are unchanged.

- **2026-07-16** - VAT is now charged using EU place-of-supply rules instead of a flat per-country lookup
  - **EU VAT only, gated on the seller.** The seller's country is taken from the company's own VAT number (`tax_id`, i.e. its VIES registration) when set, else `country_code`. Tax is applied only when that country is in the EU VAT area. A non-EU seller (e.g. a US company) charges no tax here; other systems such as US sales tax are not handled.
  - When the seller is in the EU, the tax charged is determined from the **seller's country** and the **customer's status/location**:
    - **B2B** with a stored (VIES-validated) VAT number: same country as seller → domestic VAT; another EU country → **reverse charge** (0%); outside the EU → out of scope (0%).
    - **B2C**: place of supply is taken from the self-declared country, falling back to the IP-derived country. EU → that country's destination rate (OSS); non-EU → out of scope (0%).
    - **Undetermined** (no customer country evidence): the seller-country rate is applied as a fallback.
  - **Behaviour change:** non-EU customers are now correctly out of scope (0%). Previously any country present in the `tax_rate` config map was charged its configured rate regardless of EU membership (e.g. a placeholder `USA: 1%`).
  - **Config removed:** the static `tax-rate` config map is gone. Standard EU rates for all member states are now fetched at startup and refreshed daily, cached in-memory by a shared cloneable `VatClient` (formerly `EuVatClient`). Until the first successful refresh, VAT falls back to 0%.
  - New public API in `lnvps_api_common`: `PricingEngine::determine_tax` (full treatment + audit detail), `TaxTreatment`, `TaxDetermination`, `is_eu_vat_country`, `vat_number_country_alpha3`; `VatClient` gains `refresh_rates`/`rate_for`/`with_rates`. `get_tax_for_user` now also takes the seller `company_id`.

### Added

- **2026-07-16** - Cost tracking (P/L groundwork, issue #82)
  - Optional, admin-only cost data stored in a new generic `resource_cost` table, weakly linked to any resource via `(resource_type, resource_id)` — no schema change needed to add new cost-bearing resource kinds, and a single resource can hold multiple cost records (e.g. a host's recurring rent plus a one-time hardware investment).
    - `GET /api/admin/v1/resource_costs` — paginated list; optional `resource_type` (`vm_host`|`ip_range`) and `resource_id` filters (`resource_cost::view`).
    - `GET /api/admin/v1/resource_costs/{id}` — fetch one (`resource_cost::view`).
    - `POST /api/admin/v1/resource_costs` — create (`resource_cost::create`).
    - `PATCH /api/admin/v1/resource_costs/{id}` — update; interval/billing fields use PATCH-clear semantics (omit = unchanged, `null` = clear) (`resource_cost::update`).
    - `DELETE /api/admin/v1/resource_costs/{id}` — remove (`resource_cost::delete`).
  - Each cost record has `cost_type` (`recurring`|`one_time`), `amount` (smallest currency units; per-IP for `ip_range` recurring), `currency`, an optional billing interval (`interval_amount` + `interval_type`), and optional `billing_start`/`billing_end` dates (`billing_end` null = still active).
  - `resource_type` supports `vm_host`, `ip_range`, and `generic` — the latter is not tied to any internal entity and is identified by a free-form `label` (e.g. a colo/transit subscription); `resource_id` is ignored for `generic` costs.
  - Cost data is never exposed to end users. Currency conversion between costs and revenues is deferred to a follow-up.
  - Adds the `AdminResource::ResourceCost` (24) RBAC resource; a migration grants the full permission set to the default `super_admin` role.
  - `GET /api/admin/v1/reports/profit-loss` — per-period (month/year) profit/loss report netting paid revenue against tracked resource costs. Reported in a single target currency (`currency` param, or the selected company's base currency), so each period is one row. Revenue uses each payment's stored historical exchange rate to value it in its company base currency; costs (no stored rate) use current exchange rates. Recurring costs are normalized per active calendar month, `ip_range` per-IP costs scale by the range's current assigned-IP count, and one-time costs are booked in their `billing_start` period. Optional `group_by` (`month`|`year`), `company_id` and `region_id` filters (`currency` required when `company_id` omitted). Requires `analytics::view`.

- **2026-07-16** - IP geolocation captured as VAT place-of-supply evidence
  - `PATCH /api/v1/account` **and both VM order endpoints** (`POST /api/v1/vm`, `POST /api/v1/vm/custom-template`) now record the client's IP-derived country (ISO 3166-1 alpha-3) alongside the self-declared `country_code`, stored independently on the user (`geo_country_code`, `geo_ip`, `geo_updated`) so the two signals can be compared when determining EU VAT. Capturing at order time ensures customers who never touch the account API still have a resolved country at purchase. The client IP is read from the `X-Forwarded-For`/`X-Real-IP` headers set by the trusted front proxy.
  - New optional config key `geoip-database`: path to a local MaxMind GeoLite2/GeoIP2 Country `.mmdb`. When unset, IP geolocation is disabled and no country is recorded. Lookups are local and never leave the host.
  - Non-routable addresses (private/loopback/link-local/documentation) are skipped without a lookup.

- **2026-07-15** - Admin management of users' saved payment methods
  - New admin endpoints to list/inspect/edit/delete the payment methods users save for automatic renewals (NWC connections and off-session Revolut cards). Distinct from the existing `payment_methods` provider-config endpoints.
    - `GET /api/admin/v1/user_payment_methods` — paginated list across all users; optional `user_id` filter (`user_payment_method::view`).
    - `GET /api/admin/v1/user_payment_methods/{id}` — fetch one (`user_payment_method::view`).
    - `PATCH /api/admin/v1/user_payment_methods/{id}` — set `name` (nullable), `is_default`, and/or `enabled` (`user_payment_method::update`).
    - `DELETE /api/admin/v1/user_payment_methods/{id}` — remove a saved method (`user_payment_method::delete`).
  - Responses expose only non-sensitive metadata (provider, label, card brand/last4/expiry, default/enabled) plus a `has_external_customer_id` flag; encrypted provider tokens / NWC strings are never returned.
  - Adds the `AdminResource::UserPaymentMethod` (23) RBAC resource; a migration grants the full permission set to the default `super_admin` role.

- **2026-07-15** - Save cards on demand and pay with a saved card
  - Card-payment renewal/purchase requests now accept `save_card=true` to explicitly tokenize the entered card as a reusable payment method, **independent of `auto_renewal_enabled`**. Previously a card was only saved when auto-renewal happened to be enabled, so ticking a "save card" checkout box without auto-renewal saved nothing.
  - Renewal requests now accept `method=saved` to charge an already-saved card directly (merchant-initiated, no checkout). An optional `payment_method_id` selects a specific saved card; omitted uses the user's default saved card.
  - Applies to `POST /api/v1/vm/{id}/renew` and `POST /api/v1/subscriptions/{id}/renew` via the shared query params (`method`, `intervals`, `save_card`, `payment_method_id`).

- **2026-07-15** - `GET /api/admin/v1/dns_servers/{id}/zones` (admin) — list the DNS zones available on a configured DNS server (`{ id, name }` per zone), for populating forward/reverse zone id pickers on IP ranges. Cloudflare returns its zones; OVH (reverse-only, zoneless) returns an empty list. Requires `dns_server::view`.

- **2026-07-14** - `DELETE /api/v1/ssh-key/{id}` — remove a saved SSH key from the account. Only the key's owner may delete it.
- **2026-07-14** - `GET /api/v1/ssh-key` now includes a `vms` field on each key: the list of the user's active (non-deleted) VM IDs currently using that SSH key.
- **2026-07-14** - VM orders now validate that the supplied `ssh_key_id` belongs to the requesting user (previously any existing key id was accepted). Ordering a VM continues to require a valid `ssh_key_id`.
- **2026-07-14** - When a VM is deleted its SSH key reference is now cleared (`vm.ssh_key_id` is nullable), so an SSH key that was only ever used by now-deleted VMs can be removed via `DELETE /api/v1/ssh-key/{id}` instead of failing with a foreign-key error.

- **2026-07-14** - Unified saved payment methods + Revolut auto-renewal
  - Subscriptions with `auto_renewal_enabled` are now renewed automatically by charging the user's **default** saved payment method, dispatched by provider: Nostr Wallet Connect (Lightning) or a saved Revolut card charged off-session (merchant-initiated). Closes #159.
  - Saved methods live in a new provider-agnostic `user_payment_method` table (one-to-many per user, with `is_default` and `enabled`). NWC and Revolut are both modelled as payment methods, so users can keep several and choose which is the default. Only opaque provider token references are stored, encrypted at rest, alongside non-sensitive card metadata (brand, last 4, expiry) for display + expiry handling — never card PAN/CVV.
  - Revolut cards are saved automatically the next time the user completes a Revolut checkout while auto-renewal is enabled (no separate setup step).
  - **New endpoints:**
    - `GET /api/v1/payment-methods` — list saved methods (`id`, `provider`, `name`, `card_brand`, `card_last_four`, `exp_month`, `exp_year`, `is_default`, `enabled`, `created`). Tokens/NWC strings are never returned.
    - `POST /api/v1/payment-methods` — add a Nostr Wallet Connect connection (`{ nwc_connection_string, name? }`); validated for `pay_invoice` support.
    - `PATCH /api/v1/payment-methods/{id}` — set a user-defined `name`, set as default (`is_default`), and/or enable-disable (`enabled`).
    - `DELETE /api/v1/payment-methods/{id}` — remove a saved method.
  - **Breaking:** the `nwc_connection_string` field on `GET`/`PATCH /api/v1/account` has been removed. Existing NWC connections are migrated into `user_payment_method` (provider `nwc`); manage NWC via the new payment-methods endpoints instead.

## [0.4.0] - 2026-07-13

### Added

- **2026-07-10** - Database-configured DNS providers + OVH reverse DNS (admin)
  - DNS providers are now configured in the database (`dns_server` table) instead of the static `dns` block in `config.yaml`. Each provider has `kind` (`"cloudflare"` or `"ovh"`), `url`, and an encrypted `token`.
  - `GET /api/admin/v1/dns_servers` — paginated list (`id`, `name`, `enabled`, `kind`, `url`, `ip_range_count`; token never returned). Requires `dns_server::view`.
  - `GET /api/admin/v1/dns_servers/{id}` — get one. Requires `dns_server::view`.
  - `POST /api/admin/v1/dns_servers` — create. Body: `{ name, enabled?, kind, url?, token }`. Cloudflare token is the bearer token; OVH token is `"application_key:application_secret:consumer_key"`. Requires `dns_server::create`.
  - `PATCH /api/admin/v1/dns_servers/{id}` — update (all fields optional). Requires `dns_server::update`.
  - `DELETE /api/admin/v1/dns_servers/{id}` — delete (blocked while referenced by any IP range). Requires `dns_server::delete`.
  - IP ranges gained `forward_dns_server_id`, `reverse_dns_server_id`, and `forward_zone_id` fields (in addition to the existing `reverse_zone_id`) on the create/update/list admin endpoints, selecting which DNS provider + zone manages forward (A/AAAA) and reverse (PTR) records for the range.
  - New `ovh` DNS provider implements reverse DNS (PTR) via OVH's `POST/DELETE /ip/{ip}/reverse` (reverse only; forward records must use another provider). Closes #78.
  - New `dns_server` admin permission resource.
  - `POST /api/admin/v1/ip_ranges/{id}/patch_dns` — queue a `PatchIpRangeDns` job that re-applies forward + reverse DNS for every IP assignment in a range, reconciling them to the range's current DNS server config (e.g. after switching reverse DNS to OVH). Returns a `JobResponse`. Requires `ip_range::update`.
  - Migration: the legacy `config.yaml` `dns` block is migrated into a `dns_server` row on startup, and existing IP ranges are pointed at it automatically. OVH additional-IP routers are also imported as `Ovh` DNS servers (reusing their `url` + token), with reverse DNS auto-mapped onto the ranges they route. Existing OVH-routed IPs that still carry a stale Cloudflare reverse record are force-refreshed to a real OVH PTR (idempotent — keyed on the IP; working Cloudflare reverse records are left untouched). (The OVH consumer key may need `/ip/*/reverse` permissions granted for reverse DNS calls to succeed.) Record backfill/refresh is best-effort and never blocks startup.

## [0.3.0] - 2026-07-09

### Added

- **2026-06-25** - List configured notification channels
  - `GET /api/v1/notification/channels` — returns which notification channels are configured on this server so the UI can show/hide the relevant contact inputs. Response: `{ "nip17": boolean, "email": boolean, "telegram": boolean, "whatsapp": boolean }`. No authentication required.

- **2026-06-24** - Basic per-VM firewall rules (user API)
  - `GET /api/v1/vm/{id}/firewall` — list a VM's firewall rules (ordered by `priority`).
  - `POST /api/v1/vm/{id}/firewall` — create a rule. Body: `{ priority?, direction: "inbound"|"outbound", protocol: "any"|"tcp"|"udp"|"icmp", action: "accept"|"drop"|"reject", src_cidr?, dst_port_start?, dst_port_end?, enabled? }`. Returns the created `FirewallRule`. Enforces a per-VM rule limit (configurable per template, default 20) and validates `src_cidr` (CIDR) and the port range (1–65535, start ≤ end).
  - `PATCH /api/v1/vm/{id}/firewall/{rule_id}` — update a rule; all fields optional. Send `src_cidr: null` / `dst_port_*: null` to clear a field to "any".
  - `DELETE /api/v1/vm/{id}/firewall/{rule_id}` — delete a rule.
  - `GET /api/v1/vm/{id}/firewall/policy` — get the per-VM default firewall policy. Returns `{ policy_in, policy_out }` where each is `"accept"|"drop"|"reject"` or `null` (inherit the host default, i.e. allow-all).
  - `PATCH /api/v1/vm/{id}/firewall/policy` — set the per-VM default inbound/outbound policy. Body: `{ policy_in?, policy_out? }`; omit a field to leave it unchanged, send `null` to reset it to the host default, or a value (`"accept"|"drop"|"reject"`) to set it explicitly.
  - Any change queues an asynchronous re-apply (`ApplyVmFirewall`) of the full ruleset on the host. Default policy remains allow-all inbound/outbound; host anti-spoof (IP filter) protection is always enforced regardless of user rules. Backend rule application on the host is implemented separately.

- **2026-06-23** - Enable/disable a tunnel on a router (admin)
  - `POST /api/admin/v1/routers/{id}/tunnels/{name}/toggle` — enable or disable a tunnel interface. Body: `{ "enabled": boolean }`. Returns a `JobResponse` (`{ "job_id": string }`); applied asynchronously by the worker (Linux `ip link set <iface> up|down`, RouterOS `disabled` flag), which then refreshes the tunnel cache. Requires `router::update`.

- **2026-06-23** - Set/clear the static default route on a router (admin)
  - `POST /api/admin/v1/routers/{id}/routes/default` — install or replace the router's static default route. Body: `{ "next_hop": string }` (an IP address; the address family `0.0.0.0/0` vs `::/0` is inferred from it). Returns a `JobResponse` (`{ "job_id": string }`); applied asynchronously by the worker, which refreshes the route cache afterwards. Requires `router::update`.
  - `DELETE /api/admin/v1/routers/{id}/routes/default` — remove the router's static default route(s) (idempotent). Returns a `JobResponse`. Requires `router::update`.
  - Backed by new `BgpRouter::set_default_route`/`clear_default_route` capabilities (Linux/iproute2 `ip route replace|del default`, RouterOS `/ip|/ipv6/route`). Only available on routers that support BGP/routing.

- **2026-06-23** - Router BGP route table visibility + IP range router attribution (admin)
  - `GET /api/admin/v1/routers/{id}/bgp/routes` — list the router's cached BGP route table: the prefixes it originates/announces plus a detected default route. Each `AdminRouterBgpRoute`: `router_id`, `prefix` (CIDR), `next_hop`, `is_default`, `last_seen`. Refreshed by the background sampler (~60s) alongside tunnels/BGP sessions, which replaces the whole per-router snapshot each cycle. Multiple routes to the same prefix (ECMP / differing next-hops) are preserved. Requires `router::view`.
  - IP range responses (`GET /api/admin/v1/ip_ranges`, `GET /api/admin/v1/ip_ranges/{id}`, and create/update) now include a `routers` array (`{ id, name }`) listing the routers that route the range, resolved via the range's access policy. Empty when the range has no access policy or the policy has no router.

- **2026-06-21** - Route server management: BGP session and tunnel visibility/control (admin)
  - New `RouterKind` value `linux_ssh` — a Linux router managed over SSH (BIRD/Pathvector routing, iproute2/WireGuard tunnels). Configure with `url = ssh://<user>@<host>[:<port>]/<interface>` and `token` = the SSH private key (PEM). Selectable via `kind` on `POST/PATCH /api/admin/v1/routers`.
  - `GET /api/admin/v1/routers/{id}/tunnels` — list cached tunnels discovered on the router. Each `AdminRouterTunnel`: `id`, `router_id`, `name`, `kind` (`gre`|`vxlan`|`wireguard`), `local_addr`, `remote_addr`, `enabled`, `last_seen`. Requires `router::view`.
  - `GET /api/admin/v1/routers/{id}/tunnels/{name}/traffic` — per-tunnel traffic history (`AdminRouterTunnelTraffic`: `tunnel_name`, `rx_bytes`, `tx_bytes`, `sampled_at`). Optional `from`/`to` RFC3339 query params (default: last 24h). Tunnel interface counters are the canonical per-session traffic source — BGP sessions have no byte counters. Requires `router::view`.
  - `GET /api/admin/v1/routers/{id}/bgp/sessions` — list cached BGP sessions (`AdminRouterBgpSession`: `id`, `router_id`, `name`, `peer_ip`, `peer_asn`, `local_asn`, `state`, `prefixes_received`, `prefixes_sent`, `enabled`, `direction` (`upstream`|`downstream`|`peer`|`unknown`), `last_seen`). Requires `router::view`.
  - `POST /api/admin/v1/routers/{id}/bgp/sessions/toggle` — enable/disable a BGP session. Body: `{ "session_id": string, "enabled": boolean }` (`session_id` is the backend id from the sessions listing — protocol name on BIRD, `.id` on Mikrotik). Returns a `JobResponse` (`{ "job_id": string }`); the action is applied asynchronously and the session cache refreshed. Requires `router::update`.
  - Tunnel inventory, per-tunnel traffic, and BGP session state are refreshed by a background sampler (~60s). All router queries are bounded and safe on routers carrying a full DFZ table.

- **2026-06-18** - Subscription line items now expose a typed `resource` reference
  - `SubscriptionLineItem` (public `GET /api/v1/subscriptions/{id}`) and `AdminSubscriptionLineItemInfo` (admin subscription + line-item endpoints) gain a `resource` field: a tagged union resolved server-side from the line item's subscription type. Shapes: `{ "type": "vps", "vm_id": number }`, `{ "type": "ip_range", "ip_range_subscription_id": number }`, or `null` when there is no linked resource.
  - `AdminSubscriptionLineItemInfo` now also includes the `subscription_type` discriminant.

- **2026-06-18** - `GET /api/admin/v1/subscriptions` — new optional filter query parameters
  - `search` (string) — case-insensitive substring match against subscription name and description
  - `status` (`active` | `inactive`) — filter by the `is_active` flag; omit for all
  - `auto_renewal` (boolean) — filter by the `auto_renewal_enabled` flag; omit for all
  - All filters are optional and combine with AND (and with the existing `user_id`). Filtering is applied before pagination, so `total` reflects the filtered count. Response shape is otherwise unchanged.

- **2026-06-18** - `AdminSubscriptionInfo` now includes a `user_pubkey` field
  - Hex-encoded Nostr pubkey of the owning user, returned alongside the existing `user_id` by every endpoint that emits an `AdminSubscriptionInfo`: `GET /api/admin/v1/subscriptions`, `GET /api/admin/v1/subscriptions/{id}`, `POST /api/admin/v1/subscriptions`, `PATCH /api/admin/v1/subscriptions/{id}`, and the embedded `subscription` object on `GET /api/admin/v1/vms/{id}`.

- **2026-06-15** - `GET /api/admin/v1/users/by-email` — find a user by email address
  - Looks up a user via an indexed SHA-256 hash of the (lowercased, trimmed) email and returns the full `AdminUserInfo`, or a `"User not found"` error if no match.
  - Query parameter: `email` (required). Requires the `users::view` permission.
  - Backed by a new `email_hash` column on the users table, backfilled for existing users at startup.

- **2026-04-03** - LNURL-pay endpoints for VM renewal restored
  - `GET /.well-known/lnurlp/{id}` — LNURL PayResponse for a VM. These endpoints were lost during the Rocket→Axum migration and are now working again (the path-parameter syntax was corrected for Axum).
  - `GET /api/v1/vm/{id}/renew-lnurlp?amount={millisats}` — returns an invoice to extend the VM via LNURL pay.

- **2026-03-10** - `"creating"` VM state for cleaner first-provision UX (closes #119)
  - `GET /api/v1/vm`, `GET /api/v1/vm/{id}` — `status.state` now transitions to `"creating"` immediately after the first payment is confirmed and before the VM is provisioned on the host. The state is replaced by a real host state (`"running"`, `"stopped"`, etc.) once provisioning completes.
  - `GET /api/admin/v1/vms`, `GET /api/admin/v1/vms/{id}` — Same `"creating"` state visible in the admin API.
  - This gives frontends a meaningful status to display instead of a stale `"stopped"` state during initial provisioning.

- **2026-03-10** - WebSocket console endpoint for VM serial terminal access (User API)
  - `ANY /api/v1/vm/{id}/console` (WebSocket upgrade) — Bidirectional relay between the client and the VM's serial console via the host provisioner. Authentication is passed via query parameter `?auth=<base64_nip98_event>`.

- **2026-03-10** - Stripe payment **completion** handling implemented
  - `POST /api/v1/webhook/stripe` — Incoming Stripe `payment_intent.succeeded` webhooks are now verified and processed, marking the matching subscription payment paid and running the standard completion pipeline.
  - Note: Stripe payment **creation** (checkout/intent creation for `method=stripe` on VM purchase, renewal, upgrade, and subscription renewal) is **not yet implemented** — those endpoints return an error for `method=stripe`. Only completion of externally-created Stripe payments is wired up.

- **2026-03-10** - `LNURL` added as a payment method variant
  - `GET /api/v1/payment/methods` — Response may now include `{ "name": "lnurl", ... }` when Lightning is enabled

- **2026-03-10** - `Upgrade` added as a `SubscriptionPayment.payment_type` variant
  - `GET /api/v1/subscriptions/{id}/payments` — Payments created for VM upgrades now carry `payment_type: "Upgrade"`
  - Previously only `Purchase` and `Renewal` were possible

- **2026-03-10** - `processing_fee` field added to `SubscriptionPayment` user API response
  - `GET /api/v1/subscriptions/{id}/payments` — Each payment now includes `processing_fee: { currency, amount }`

- **2026-03-03** - Multi-interval VM renewal support
  - `POST /api/v1/vm/{id}/renew` — Accepts optional `intervals` query parameter to pre-pay multiple billing periods at once
  - `POST /api/admin/v1/vms/{id}/renew` — Same `intervals` support in admin renewal endpoint

- **2026-02-25** - Resource limits on custom pricing plans, propagated to custom templates
  - `POST /api/admin/v1/custom_pricing` — Accepts new optional fields: `disk_iops_read`, `disk_iops_write`, `disk_mbps_read`, `disk_mbps_write`, `network_mbps`, `cpu_limit`
  - `PATCH /api/admin/v1/custom_pricing/{id}` — Accepts the same limit fields; send `null` to remove a limit
  - `GET /api/admin/v1/custom_pricing` / `GET /api/admin/v1/custom_pricing/{id}` — Response now includes limit fields (omitted when uncapped)
  - Limits are copied from the pricing plan into each `VmCustomTemplate` at VM provisioning time (new VMs and template upgrades)
  - `None` / omitted = uncapped
- **2026-02-25** - Template resource limits for fair-use and SLA enforcement (closes #26)
  - `POST /api/admin/v1/vm_templates` — Accepts new optional fields: `disk_iops_read`, `disk_iops_write`, `disk_mbps_read`, `disk_mbps_write`, `network_mbps`, `cpu_limit`
  - `PATCH /api/admin/v1/vm_templates/{id}` — Accepts the same limit fields; send `null` to remove a limit
  - `GET /api/admin/v1/vm_templates` / `GET /api/admin/v1/vm_templates/{id}` — Response now includes limit fields (omitted when uncapped)
  - Limits are applied at VM create time and on any VM configure/upgrade:
    - **Disk IO**: `mbps_rd`/`mbps_wr`/`iops_rd`/`iops_wr` on the primary disk via Proxmox API
    - **Network bandwidth**: `rate=N` on `net0` interface
    - **CPU limit**: `cpulimit` VM config option (fraction of allocated cores)
  - `None` / omitted = uncapped (preserves existing behaviour for all current VMs)
- **2026-02-24** - Cloud image checksum verification and on-demand download (closes #69)
  - `POST /api/admin/v1/vm_os_images/{id}/download` — Enqueue an immediate download/re-check of an OS image on all hosts (requires `vm_os_image::update`)
  - `PATCH /api/admin/v1/vm_os_images/{id}` — Now correctly applies `sha2` and `sha2_url` updates
  - Worker: `DownloadOsImages` job fetches `sha2_url`, compares checksum via SSH, and re-downloads stale images; checksum is also passed to Proxmox `download-url` API for in-flight verification
- **2026-02-24** - Added `company_base_currency` field to `AdminVmPaymentInfo`
  - `GET /api/admin/v1/vms/{id}/payments` — Response now includes `company_base_currency`
  - `GET /api/admin/v1/vms/{id}/payments/{payment_id}` — Response now includes `company_base_currency`
  - `POST /api/admin/v1/vms/{id}/payments/{payment_id}/complete` — Response now includes `company_base_currency`
- **2026-02-23** - Sponsoring LIR Agreement generation (User API)
  - `GET /api/v1/legal/sponsoring-lir-agreement?data={base64url_json}` — Renders an unsigned LIR agreement HTML document from base64url-encoded JSON agreement data. Rejects data that carries a cryptographic proof.
  - `GET /api/v1/legal/sponsoring-lir-agreement/from-subscription/{subscription_id}` (NIP-98 auth) — Generates a cryptographically signed LIR agreement for one of the caller's own subscriptions, populating provider/end-user details from company and billing data. Returns a `SignedAgreementUrlResponse`.
- **2026-02-23** - Admin endpoints to manually complete payments
  - `POST /api/admin/v1/vms/{id}/payments/{payment_id}/complete` — Mark a VM payment as paid, extend VM expiry, and dispatch provisioning (requires `payments::update`)
  - `POST /api/admin/v1/subscription_payments/{id}/complete` — Mark a subscription payment as paid, extend subscription by 30 days, and activate it (requires `subscription_payments::update`)

### Fixed

- **2026-07-06** - `PATCH /api/v1/vm/{id}/re-install` on an expired VM now returns `402 Payment Required` with a clear message instead of `500 Internal Server Error`. The expiry is checked up-front (before touching the host) so an expired VM can no longer trigger a failed reinstall pipeline. (#141)

### Changed

- **2026-07-06** - More accurate HTTP status codes on error responses (full audit of the user and admin APIs). API errors previously almost always returned `500 Internal Server Error`; they now use appropriate codes:
  - `400 Bad Request` — client/validation errors (e.g. invalid SSH key, invalid lightning address, empty/invalid fields on admin create/update, invalid date ranges on reports). Many admin validation errors previously returned `500`.
  - `401 Unauthorized` — authentication failures.
  - `403 Forbidden` — accessing a resource you don't own (VM/subscription/SSH key), ordering before email verification, modifying system roles, and **insufficient admin permissions** (previously `500`).
  - `404 Not Found` — missing resources, including any database lookup that finds no matching row, and nested resources not under their parent (e.g. a firewall rule / payment / history entry that doesn't belong to the given VM).
  - `409 Conflict` — state conflicts (e.g. already enrolled in referrals, acting on an already-deleted VM, a payment that is already completed, assigning an IP to a deleted/expired VM).
  - `501 Not Implemented` — not-yet-implemented subscription types (ASN sponsoring, DNS hosting).
  - Genuine internal failures continue to return `500`. Response bodies are unchanged (`{ "error": string }`).


- **2026-06-25** - Subscription payments now include the payment data needed to pay
  - `ApiSubscriptionPayment` (returned by `GET /api/v1/subscriptions/{id}/renew`, `GET /api/v1/subscriptions/{id}/payments`, and the admin subscription-payment endpoints) gains a `data` field carrying the payment-method-specific data, e.g. `{ "lightning": "lnbc..." }` for Lightning. Previously the renew endpoint returned a payment record with no way to actually pay it.

- **2026-06-25** - Email verification is only required to order a VM when SMTP is configured
  - `POST /api/v1/vm` and `POST /api/v1/vm/custom-template` previously always rejected orders from users without a verified email. The check is now skipped when the server has no `smtp` config (verification emails can't be sent), so ordering remains usable on installs without email. The API logs a startup warning when SMTP is unconfigured.

- **2026-06-18** - `subscription_type` is now immutable on subscription line items
  - `PATCH /api/admin/v1/subscription_line_items/{id}` no longer accepts `subscription_type`. A line item is bound to its resource at creation time, so its type must not change afterward (previously the field was accepted but silently ignored).

- **2026-06-18** - `configuration` on subscription line items is now upgrade bookkeeping only
  - Previously documented as a tagged resource link (`{ "type": "vps", "vm_id": ... }`). It is now returned as raw JSON holding upgrade data (e.g. `new_cpu`/`new_memory`/`new_disk`) and is `null` for line items that have never been upgraded. Resolve the linked resource via the new `resource` field instead.
  - **SubscriptionType** values are now serialized in `snake_case` (`"vps"`, `"ip_range"`, `"asn_sponsoring"`, `"dns_hosting"`) wherever the enum appears in JSON (e.g. the admin `subscription_type` field and the create-line-item request body), matching the rest of the API.

- **2026-04-03** - Unpaid VMs with a non-expired pending payment are no longer auto-deleted
  - The worker cleanup loop now skips deletion of unpaid VMs that still have a pending (non-expired) payment, giving slower payment methods (e.g. Revolut) time to settle before the VM is removed.

- **2026-03-10** - `VmRunningStates` enum simplified — `"starting"` and `"deleting"` removed
  - `GET /api/v1/vm`, `GET /api/v1/vm/{id}` — `status.state` now has four possible values: `"unknown"` (default before first poll), `"running"`, `"stopped"`, `"creating"`. The former `"starting"` and `"deleting"` variants are no longer emitted.
  - `GET /api/admin/v1/vms`, `GET /api/admin/v1/vms/{id}` — Same change applies to `running_state.state`.
  - `"unknown"` is now the default value when no state has been cached yet, replacing the previous implicit `"stopped"` default.

- **2026-03-10** - `VmStatus.expires` is now nullable
  - `GET /api/v1/vm`, `GET /api/v1/vm/{id}` — The `expires` field is now `string | null` (was always a string). It will be `null` for newly created VMs that have not yet been paid.

- **2026-03-10** - `GET /api/v1/vm/{id}/payments` now uses database-level pagination
  - The endpoint now accepts `?limit=N&offset=N` query parameters and returns a paginated response (`data`, `total`, `limit`, `offset`). Previously the list was unbounded.

- **2026-03-03** - Admin subscription list now returns results in descending order
  - `GET /api/admin/v1/subscriptions` — Results ordered by `id DESC` (newest first); applies to both the all-subscriptions list and the `?user_id=N` filtered list

- **2026-03-03** - Admin VM info response now includes subscription details
  - `GET /api/admin/v1/vms/{id}` — Response now includes a `subscription` object with the full `AdminSubscriptionInfo` (id, status, interval, currency, line items, payment count); omitted if no subscription is linked

- **2026-03-03** - Admin subscription payment response now includes `company_base_currency`
  - `GET /api/admin/v1/subscriptions/{id}/payments` — Each payment now includes `company_base_currency`
  - `GET /api/admin/v1/subscription_payments/{id}` — Response now includes `company_base_currency`
  - `POST /api/admin/v1/subscription_payments/{id}/complete` — Response now includes `company_base_currency`

- **2026-03-03** - VM payments now use the unified `subscription_payment` table
  - All VM renewal, purchase, and upgrade payments are now stored in `subscription_payment` instead of `vm_payment`
  - `GET /api/v1/vm/{id}/payments` — Response format unchanged; now backed by `subscription_payment`; supports pagination via `?limit=N&offset=N` query params
  - `GET /api/v1/vm/{id}/payments/{payment_id}` — Now looks up by `subscription_payment.id`
  - `GET /api/v1/vm/{id}/payments/{payment_id}/invoice` — Now backed by `subscription_payment`
  - `POST /api/v1/vm/{id}/renew` — Returns payment from `subscription_payment`
  - `POST /api/v1/vm/{id}/upgrade` — Returns payment from `subscription_payment`; upgrade parameters stored in `metadata` JSON field
  - `GET /api/admin/v1/vms/{id}/payments` — Now backed by `subscription_payment`; uses real DB-level pagination
  - `GET /api/admin/v1/vms/{id}/payments/{payment_id}` — Now looks up by `subscription_payment.id`
  - `POST /api/admin/v1/vms/{id}/payments/{payment_id}/complete` — Now completes a `subscription_payment`
  - `GET /api/admin/v1/reports/time-series` — Revenue data now sourced from `subscription_payment`
  - `GET /api/admin/v1/reports/referral-usage/time-series` — Referral data now sourced from `subscription_payment`
  - **Automatic data migration**: existing VMs and `vm_payment` rows are backfilled into the subscription system automatically at app startup (no manual step). The backfill runs after schema migrations and before any VM reads, and is idempotent.
  - **Schema migrations**: `20260302151134_vm_subscription_link.sql` (the DB-level `NOT NULL` on `vm.subscription_line_item_id` and the drop of legacy `vm.expires`/`created`/`auto_renewal_enabled` are deferred to finalization, run manually after production verification)

- **2026-03-03** - Every VM is now linked to a `subscription` and `subscription_line_item`
  - `vm` table has a new `subscription_line_item_id` column (NOT NULL) linking it to the subscriptions system
  - New VMs provisioned via `POST /api/v1/vm` or `POST /api/v1/vm/custom` automatically get a subscription created
  - The subscription interval is copied from the cost plan (standard VMs) or defaults to 1 month (custom VMs)

- **2026-03-03** - `IntervalType` enum renamed from `VmCostPlanIntervalType`
  - Affects admin responses that include cost plan or subscription interval information

- **2026-02-25** - Email verification is now required before creating a VM (closes #92)
  - `POST /api/v1/vm` — Returns `400` with error message if the user's email is not verified
  - `POST /api/v1/vm/custom-template` — Same gate applied

### Removed

- **2026-03-10** - Clarification: `POST /api/admin/v1/vms/{id}/renew` does **not** exist
  - The 2026-03-03 changelog entry incorrectly stated that multi-interval renewal was added to an admin renew endpoint. No such endpoint exists in the admin API. Multi-interval renewal is only available via the user-facing `GET /api/v1/vm/{id}/renew?intervals=N`.

### Fixed

- **2026-07-07** - Codebase audit: correctness and safety fixes
  - **Payments:** subscription payment settlement is now idempotent — duplicate webhook deliveries or replayed Lightning settle events no longer extend a subscription's expiry more than once (`subscription_payment_paid` now guards on `is_paid` and skips the extension when the payment was already paid). Revolut order metadata is now persisted on settlement.
  - **Custom VM orders:** requested CPU/memory/disk are now validated against the pricing plan's configured min/max limits, disk pricing is matched on both disk kind *and* interface, and sub-GB memory/disk is billed (rounded up) instead of truncating to zero. Previously a custom order could be under-billed or effectively free.
  - **VM lifecycle:** `PATCH /api/v1/vm/{id}/restart` now actually restarts the VM (it previously only issued a stop, leaving the VM powered off). VM deletion no longer frees the DB record and IP assignments when the hypervisor is merely unreachable — only a definitive 404 is treated as "already gone"; transient errors abort the delete. Proxmox HTTP errors are now classified fatal/transient by status code instead of blanket-retrying 4xx.
  - **Renewals & pricing:** a pending renewal invoice is no longer reused for a request covering a different number of intervals (which let a multi-interval request be paid off with a smaller single-interval invoice); VPS-only subscription setup fees are now charged on the first invoice; and extending an already-expired VM now clamps the new expiry to "now" consistently with every other renewal path.
  - **Robustness:** fixed remote-triggerable panics in NIP-98 auth (malformed single-element tags) and VAT-number parsing (multi-byte input), and a panic in VM status when an IP range fails to load.
  - **Admin/DB:** creating or updating available IP space now persists `company_id` (the insert previously failed on the NOT-NULL column); non-VM subscription payments are correctly attributed to their company in admin payment views and revenue reports; `admin_update_company` now persists `base_currency`; and per-region capacity stats no longer under-count hosts that share the same CPU/memory values.
  - **Support agent, health checks & host tooling:** the support agent no longer crashes on non-ASCII messages or empty LLM responses, uses UID-based IMAP operations (no duplicate replies), and URL-encodes email lookups; health-check metrics handle IPv6 DNS servers and IPv6 bind addresses; and host CPU-feature detection uses a safe CPUID intrinsic with a max-leaf guard.
  - **XDP firewall:** corrected the SYN rate-limiter token-bucket refill math (previously refilled far too fast, defeating the limit), stopped counting SYN-ACK replies, and guarded against a zero-limit division.

- **2026-06-25** - Admin VM `template_id` is now `null` for custom-template VMs
  - `AdminVmInfo.template_id` (returned by `GET /api/admin/v1/vms` and `GET /api/admin/v1/vms/{id}`) changed from `u64` to a nullable integer. VMs on a custom template previously reported `template_id: 0`; they now correctly report `template_id: null` (with the linked template carried by `custom_template_id`). Standard-template VMs are unaffected.

- **2026-06-25** - Expired subscriptions are now handled even when expiry predates the last check
  - The worker's `CheckSubscriptions` expiry handling previously only fired when a subscription crossed its expiry between two check cycles (`expires >= last_check`). Subscriptions that expired before the last check (admin/retroactive expiry, clock changes, or worker downtime) were left running until the grace period elapsed. The worker now fires the one-shot expiry handling (stop VM + notify) for any expired-but-in-grace subscription, using VM history as an idempotency marker so it still acts exactly once.

- **2026-06-23** - Toggling a BGP session now persists on routers where the backend session id differs from the session name (e.g. Mikrotik, where the id is `.id` and the name is the protocol name). Previously `POST /api/admin/v1/routers/{id}/bgp/sessions/toggle` updated nothing in the cache for such routers because the persist was keyed by the backend id instead of the cached session name.

- **2026-06-16** - VM→subscription backfill now runs reliably at startup
  - The backfill is executed during app startup, after schema migrations and before any VM read, and preserves each VM's existing expiry and auto-renewal preference. The legacy `vm.expires` / `vm.created` columns are no longer dropped before the backfill runs, which previously caused the backfill to fail for every VM and break all VM reads. (No external API surface change — listed for operator awareness.)

- **2026-04-26** - Region capacity no longer reports IP ranges as full incorrectly
  - `GET /api/v1/vm/templates` and region availability — the gateway IP is now only counted as a used address when it actually falls within the allocation CIDR. Previously a gateway outside the range inflated the used-IP count and could falsely report a region/range as full while free IPs remained.

- **2026-04-02** - Payments for already-deleted VMs are handled gracefully
  - `POST /api/v1/vm/{id}/renew` and payment confirmation — a payment that arrives for a VM auto-deleted before the (slow) payment settled now un-deletes the VM and applies the payment instead of erroring; the VM is then re-provisioned by the next check. Renewal/invoice creation for VMs that remain deleted is rejected with `"VM not found"`.
  - A race where a VM paid between the cleanup snapshot and the deletion step could be deleted is fixed by re-reading VM state immediately before deletion.

- **2026-03-10** - VM subscription lookup query used incorrect type filter
  - Internal fix: the query that finds a VM's linked subscription was incorrectly using `IN (3, 4)` instead of `= 3`, which could return incorrect results.

- **2026-03-10** - `ApiVmPayment::from_subscription_payment` now propagates JSON parse errors
  - Previously, a malformed `metadata` JSON field in a `subscription_payment` row would be silently ignored, potentially returning incorrect upgrade parameter data. Errors are now surfaced to the API caller.

- **2026-03-10** - Expiry notification always sent when NWC auto-renewal is inactive
  - Workers now always send the expiry notification email/NIP-17 DM even when NWC is configured but `auto_renewal_enabled` is false for the subscription.

- **2026-03-03** - VM upgrade no longer leaves subscription renewal cost stale
  - `POST /api/v1/vm/{id}/upgrade` — After payment confirmation, `SubscriptionLineItem.amount` is now updated to the new base-currency cost of the upgraded template for both standard→custom and custom→custom upgrade paths
  - `GET /api/v1/subscriptions/{id}` and admin equivalents — `line_items[].price` now reflects the post-upgrade renewal cost immediately after an upgrade completes

- **2026-03-03** - Migration tool no longer marks subscriptions active for deleted VMs
  - VM subscription backfill — Subscriptions created for deleted VMs are now inserted with `is_active = false`

- **2026-02-23** - Fixed inability to unset `cpu_mfg`, `cpu_arch`, `cpu_features` fields via PATCH endpoints
  - `PATCH /api/admin/v1/vm_templates/{id}` — Now supports setting `cpu_mfg`, `cpu_arch`, `cpu_features` to `null` to clear values
  - `PATCH /api/admin/v1/custom_pricing/{id}` — Now supports setting `cpu_mfg`, `cpu_arch`, `cpu_features` to `null` to clear values
  - `PATCH /api/admin/v1/hosts/{id}` — Now supports setting `cpu_mfg`, `cpu_arch`, `cpu_features` to `null` to clear values
  - Previously, sending `null` for these fields was treated the same as omitting them (no change)

### Documentation

- **2026-07-06** - Documented previously-undocumented user API endpoints in `API_DOCUMENTATION.md`
  - Added docs for the Telegram/WhatsApp notification-linking endpoints: `POST`/`DELETE /api/v1/account/telegram/link`, `POST`/`DELETE /api/v1/account/whatsapp/verify`, and `POST /api/v1/account/whatsapp/confirm`.
  - Added a new "Nostr Domains (NIP-05)" section documenting `GET`/`POST /api/v1/nostr/domain`, `GET`/`POST /api/v1/nostr/domain/{dom}/handle`, and `DELETE /api/v1/nostr/domain/{dom}/handle/{handle}`, including the `NostrDomain` and `NostrDomainHandle` data types. No API behaviour changed.

- **2026-06-23** - Documented the BGP session and tunnel field semantics in `ADMIN_API_ENDPOINTS.md` and rustdoc. Clarified that `enabled` (administrative on/off) and `state` (live BGP FSM state: `Idle`/`Connect`/`Active`/`OpenSent`/`OpenConfirm`/`Established`/`Down`) are independent — `"enabled": true` with `"state": "Down"` is administratively on but not yet up, not a contradiction. Also documented tunnel `"any"` endpoints and the `direction` classification.

## [v0.2.0] - 2026-02-22

### Changed
- **2026-02-22** - Reduced unpaid VM deletion time from 24 hours to 1 hour
  - Unpaid VM orders are now deleted after 1 hour instead of 24 hours
  - Fixes #63

### Added
- **2026-02-22** - Added `disabled` field to VM model and admin PATCH endpoint
  - `vm` table now includes `disabled` column (default: false)
  - `AdminVmInfo` response now includes `disabled` field in all GET endpoints
  - `PATCH /api/admin/v1/vms/{id}` — New endpoint to update VM properties
  - Allows admins to disable/enable VMs without deleting them
  - When disabled state changes, a `ConfigureVm` work job is dispatched to reconfigure the VM on the host
  - On Proxmox hosts, disabled VMs have `link_down=1` set on their network interface

- **2026-02-22** - Added `mtu` field to host configuration
  - `vm_host` table now includes `mtu` column (optional, SMALLINT UNSIGNED)
  - `AdminHostInfo` response now includes `mtu` field in all GET endpoints
  - `POST /api/admin/v1/hosts` — Added optional `mtu` field for host creation
  - `PATCH /api/admin/v1/hosts/{id}` — Added optional `mtu` field for host update (use `null` to clear)

- **2026-02-22** - Added additional fields to sales time-series report
  - `GET /api/admin/v1/reports/time-series` — Response now includes `user_id`, `host_id`, `host_name`, `region_id`, `region_name` fields in each payment record
  - Enables client-side filtering by user, host, or region

- **2026-02-21** - Added endpoint to list free IPs in an IPv4 range (Admin API)
  - `GET /api/admin/v1/ip_ranges/{id}/free_ips` — Returns list of unassigned IP addresses
  - Only available for IPv4 ranges; IPv6 ranges return an error (too large to enumerate)
  - Excludes reserved IPs (gateway, network address, broadcast address)

- **2026-02-20** - Added `supported_currencies` to payment method configuration
  - `AdminPaymentMethodConfigInfo` — New `supported_currencies` field (array of currency codes)
  - `CreatePaymentMethodConfigRequest` — New optional `supported_currencies` field
  - `UpdatePaymentMethodConfigRequest` — New optional `supported_currencies` field
  - `GET /api/v1/payment/methods` — Now returns currencies from DB config instead of hardcoded defaults
  - Empty array means use default currencies based on payment method type (Lightning: BTC, others: EUR/USD)

- **2026-02-20** - Added `cpu_mfg`, `cpu_arch`, `cpu_features` to all admin API response models
  - `AdminVmInfo` — Now includes CPU specification fields from the VM's template
  - `AdminVmTemplateInfo` — Now includes CPU specification fields
  - `AdminCustomPricingInfo` — Now includes CPU specification fields
  - `AdminHostInfo` — CPU fields are now consistently documented as optional (omitted when unknown/empty)
  - `POST /api/admin/v1/hosts` — Added optional `cpu_mfg`, `cpu_arch`, `cpu_features` fields for host creation
  - `PATCH /api/admin/v1/hosts/{id}` — Added optional `cpu_mfg`, `cpu_arch`, `cpu_features` fields for host update
  - Fields are omitted from JSON when value is unknown (cpu_mfg/cpu_arch) or empty (cpu_features)

- **2026-02-20** - Added `paid_at` timestamp to payment responses
  - `VmPayment` — New optional `paid_at` field (ISO 8601 datetime) indicating when the payment was completed
  - `SubscriptionPayment` — New optional `paid_at` field (ISO 8601 datetime) indicating when the payment was completed
  - `AdminVmPaymentInfo` — New optional `paid_at` field for admin payment views
  - `AdminSubscriptionPaymentInfo` — New optional `paid_at` field for admin payment views
  - Field is only present when `is_paid` is true; null/omitted for unpaid payments

- **2026-02-20** - Added processing fee information to payment methods response
  - `GET /api/v1/payment/methods` — Response now includes optional `processing_fee_rate`, `processing_fee_base`, and `processing_fee_currency` fields
  - `processing_fee_rate`: Percentage rate (e.g., 1.0 for 1%)
  - `processing_fee_base`: Base amount in smallest currency units (cents for fiat, millisats for BTC)
  - `processing_fee_currency`: Currency for the base fee (e.g., "EUR")
  - NWC payment method is now only returned when Lightning is enabled

- **2026-02-20** - Added CPU-aware host filtering to VM Templates, Custom Pricing, and Hosts (Admin API)
  - New enums: `CpuMfg`, `CpuArch`, `CpuFeature`, `GpuMfg`
  - `POST /api/admin/v1/vm_templates` — Added optional `cpu_mfg`, `cpu_arch`, `cpu_features` fields
  - `PATCH /api/admin/v1/vm_templates/{id}` — Added optional `cpu_mfg`, `cpu_arch`, `cpu_features` fields
  - `POST /api/admin/v1/custom_pricing` — Added optional `cpu_mfg`, `cpu_arch`, `cpu_features` fields
  - `PATCH /api/admin/v1/custom_pricing/{id}` — Added optional `cpu_mfg`, `cpu_arch`, `cpu_features` fields
  - `AdminHostInfo` response now includes `cpu_mfg`, `cpu_arch`, `cpu_features` (detected via lnvps-host-info)
  - When `cpu_mfg`/`cpu_arch` is "unknown" or `cpu_features` is empty, no filtering is applied (matches any host)

- **2026-02-20** - Added SSH credentials for host utilities to Admin Host API
  - `POST /api/admin/v1/hosts` — Added optional `ssh_user` and `ssh_key` fields for host creation
  - `PATCH /api/admin/v1/hosts/{id}` — Added optional `ssh_user` and `ssh_key` fields for host update
  - `AdminHostInfo` response now includes `ssh_user` (string or null) and `ssh_key_configured` (boolean)
  - SSH key itself is never exposed in responses for security (only a boolean indicator)
  - SSH credentials are used by the PatchHosts worker to run `lnvps-host-info` utility for CPU/GPU detection

- **2026-02-20** - Added CPU feature requirements to custom VM requests (User API)
  - `POST /api/v1/vm/custom` — `cpu_mfg`, `cpu_arch`, `cpu_feature` fields now accept strings instead of enums
  - Valid `cpu_mfg` values: "intel", "amd", "apple", "nvidia", "unknown"
  - Valid `cpu_arch` values: "x86_64", "arm64", "unknown"
  - CPU features are parsed from strings (e.g. "AVX2", "AES", "VMX"); invalid values are silently ignored

- **2026-02-19** - Added Referral Program API endpoints
  - `POST /api/v1/referral` - Enroll in referral program with lightning address or NWC payout options
  - `GET /api/v1/referral` - Get referral state including per-currency earnings, payout history, and success/failed counts
  - `PATCH /api/v1/referral` - Update payout options (lightning_address, use_nwc)

- **2026-02-17** - Added embedded API documentation served at root path (both User and Admin APIs)
  - `GET /` or `GET /index.html` - Renders API documentation with markdown viewer
  - `GET /docs/endpoints.md` - Raw markdown content of API endpoints documentation
  - `GET /docs/changelog.md` - Raw markdown content of API changelog
  - Documentation is embedded at compile time using `include_str!` and rendered client-side with marked.js
  - User API serves `API_DOCUMENTATION.md`, Admin API serves `ADMIN_API_ENDPOINTS.md`

- **2026-02-17** - Added `tax` and `processing_fee` fields to `AdminVmPaymentInfo` response
  - Affected endpoints: `GET /api/admin/v1/vms/{vm_id}/payments`, `GET /api/admin/v1/vms/{vm_id}/payments/{payment_id}`
  - Both fields are `u64` in smallest currency unit (cents for fiat, millisats for BTC)

- **2026-02-17** - Added `processing_fee` field to `AdminSubscriptionPaymentInfo` response
  - Affected endpoints: `GET /api/admin/v1/subscriptions/{id}/payments`, `GET /api/admin/v1/subscriptions/{id}/payments/{payment_id}`
  - Field is `u64` in smallest currency unit (cents for fiat, millisats for BTC)

### Changed
- **2026-02-18** - **BREAKING CHANGE**: `ApiPrice.amount` changed from `f32` to `u64` in smallest currency units
  - The `Price` type returned by user-facing endpoints now uses `u64` integers instead of floats
  - Amounts are in smallest currency units: cents for fiat (EUR, USD, etc.), millisats for BTC
  - Affected endpoints: all endpoints returning `Price` objects, including:
    - `GET /api/v1/templates` — `VmCostPlan.amount`
    - `GET /api/v1/vm/{id}/upgrade/quote` — `cost_difference`, `new_renewal_cost`, `discount`
    - `GET /api/v1/subscriptions` / `GET /api/v1/subscriptions/{id}` — `SubscriptionLineItem.price`, `SubscriptionLineItem.setup_fee`
    - `GET /api/v1/subscriptions/{id}/payments` — `SubscriptionPayment.amount`, `SubscriptionPayment.tax`
    - `POST /api/v1/vm/custom/price` — returned `Price`
  - Example: `"amount": 10.99` (EUR float) becomes `"amount": 1099` (cents)
  - Example: `"amount": 0.00012345` (BTC float) becomes `"amount": 12345` (millisats)

- **2026-02-16** - **BREAKING CHANGE**: All money amounts now use `u64` in smallest currency units (cents for fiat, millisats for BTC)
  - **Requires database migration**: Run `20260217100000_amount_to_cents.sql` which converts existing data
  - Cost plan `amount` field changed from `f32` (human-readable) to `u64` (smallest units)
  - Custom pricing costs (`cpu_cost`, `memory_cost`, `ip4_cost`, `ip6_cost`) changed from `f32` to `u64`
  - Custom pricing disk `cost` field changed from `f32` to `u64`
  - VM template `cost_plan_amount` field changed from `f32` to `u64`
  - Payment method config `processing_fee_base` field changed from `f32` to `u64`
  - Affected endpoints:
    - `POST /api/admin/v1/cost_plans`, `PATCH /api/admin/v1/cost_plans/{id}`
    - `POST /api/admin/v1/custom_pricing`, `PATCH /api/admin/v1/custom_pricing/{id}`
    - `POST /api/admin/v1/vm_templates`, `PATCH /api/admin/v1/vm_templates/{id}`
    - `POST /api/admin/v1/custom_pricing/{id}/calculate`
    - `POST /api/admin/v1/payment_methods`, `PATCH /api/admin/v1/payment_methods/{id}`
  - Example: `"amount": 10.99` (EUR) becomes `"amount": 1099` (cents)
  - Example: `"cpu_cost": 0.05` (BTC) becomes `"cpu_cost": 5000000` (millisats = 5000 sats)
  - Example: `"processing_fee_base": 0.20` (EUR) becomes `"processing_fee_base": 20` (cents)

- **2026-02-16** - Payment method config updates now support partial config updates
  - `PATCH /api/admin/v1/payment_methods/{id}` now accepts `PartialProviderConfig` instead of full `ProviderConfig`
  - Only fields included in the request are updated; missing fields retain their existing values
  - The `type` field is still required to identify the provider type
  - Cannot change provider type during update (e.g., from `lnd` to `revolut`)

### Deprecated
- **2026-02-16** - Bitvora payment provider has been disabled
  - Bitvora service has been shut down and is no longer available
  - The `bitvora` provider type is no longer supported for new configurations
  - Existing Bitvora configurations in the database are preserved for historical reference
  - Affected endpoints: `POST /api/admin/v1/payment_methods`, `PATCH /api/admin/v1/payment_methods/{id}`

### Security
- **2026-02-16** - Sanitized sensitive fields in `AdminPaymentMethodConfigInfo` responses
  - Provider config secrets (tokens, API keys, webhook secrets) are no longer returned in GET/list responses
  - Affected endpoints: `GET /api/v1/admin/payment-config`, `GET /api/v1/admin/payment-config/{id}`
  - Secrets are replaced with boolean indicators (e.g., `has_token: true`, `has_webhook_secret: true`)
  - Public/non-sensitive fields (URLs, client IDs, publishable keys) are still returned
