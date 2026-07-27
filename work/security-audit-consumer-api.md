# Consumer API Security Audit

> **Status: all findings fixed** in the changeset accompanying this report
> (rate limiting + WhatsApp attempt cap, downgrade blocking, XFF direction,
> VIES/contact hardening, hashed verification tokens, security headers,
> SSRF timeout + subscription-scoped payment lookup). See `API_CHANGELOG.md`
> `[Unreleased] → Security` for the user-facing summary.

Audit of the customer-facing API (`lnvps_api` crate + auth/payments in `lnvps_api_common` / `lnvps_db`). Scope: all routers merged in `lnvps_api/src/bin/api.rs` (main, subscriptions, ip_space, referral, apps, legal, oauth, webauthn, contacts, webhooks, docs, nostr-domain). The admin API was **not** in scope.

## Authentication architecture (summary, sound)

- **NIP-98** (`Authorization: Nostr <b64-event>`) — kind/URL/method/600 s timestamp window/signature all checked in `Nip98Auth::check`; malformed single-element tags handled without panic (regression tests present). Solid.
- **Session JWT** (`Authorization: Bearer`) — HS256, verified before claim parse, fixed header, 30-day expiry, `sub` length-checked to 32 bytes. Signed-state and challenge tokens (OAuth CSRF, WebAuthn ceremonies) all verify HMAC before deserialising and carry purpose tags + short TTLs. Solid.
- **Synthetic identities** — `oauth_pubkey` = `sha256("provider:subject")`, `webauthn_pubkey` = `sha256("webauthn\0handle")`. Provably disjoint namespaces; a user-controlled provider tag can't collide with a real Nostr key.
- **OAuth** — signed CSRF state bound to provider, redirect allowlist with path-boundary matching, open-redirect on the login endpoint correctly rejected. id_token is trusted without signature re-verification, which is acceptable because it arrives over the TLS back-channel from the provider token endpoint.
- **WebAuthn** — discoverable credentials, server state carried in signed challenge tokens, credential-id uniqueness enforced across accounts, UV required, counter updates persisted.
- **Ownership/IDOR** — checked on every audited handler: `get_user_vm`, `owned_ip_range`, `owned_deployment`, subscription/payment/firewall/ssh-key/payment-method/nostr-domain handlers all compare `user_id` before acting. `v1_get_subscription_payment` deliberately 404s a payment from another subscription rather than leaking existence.

## Findings

### 1. No rate limiting anywhere — brute-force and resource-exhaustion exposure (HIGH)

No rate limiting exists at any layer of the consumer API (no governor/throttle middleware, no per-IP or per-account caps). Consequences by endpoint:

- `POST /api/v1/account/whatsapp/confirm` — the 6-digit code (`rand::random::<u32>() % 1_000_000`) is checked with no attempt limit and no per-code expiry. ~500k requests brute-forces a code; each code is single-use and stored in the clear. An attacker who triggers `whatsapp/verify` to their own number can't gain much, but the missing attempt cap is a general pattern problem.
- `POST /api/v1/webauthn/login/start|finish`, `register/start|finish`, `oauth/{provider}/login` — unauthenticated; can be hammered to generate challenge-token churn / DB upserts (`upsert_user` writes on every authenticated request is by design, but unauth endpoints have no throttle at all).
- `POST /api/v1/vm` / `custom-template` / `app-deployments` — authenticated; one valid key can provision unbounded unpaid VMs/deployments (each reserves host capacity for 1 h until the unpaid-VM reaper runs). Capacity admission (`select_in_region`) will eventually 409, but the unpaid-order spam still churns DB rows and host allocation attempts.
- `PATCH /api/v1/vm/{id}/start|stop|restart` — each call drives a host client (`start_vm`/`stop_vm`/`reset_vm`) plus a `CheckVm` work job; an authenticated user can flap their VM in a tight loop, hammering Proxmox/libvirt and flooding the work queue.
- `GET /api/v1/vm/{id}/console` — a new host terminal connection per upgrade; no concurrent-session cap.

**Recommendation:** add a per-IP + per-pubkey rate-limit middleware (e.g. `tower_governor`) with stricter buckets on the unauthenticated auth-start endpoints, the verification-confirm endpoints, and VM power/provisioning actions. Add an attempt counter + expiry to the WhatsApp code check specifically (store attempts alongside the code, lock after N failures).

### 2. VM "upgrade" permits silent downgrades (MEDIUM)

`v1_vm_upgrade` / `v1_vm_upgrade_quote` (`lnvps_api/src/api/routes.rs:2131-2217`) take arbitrary `cpu`/`memory`/`disk` and pass them to `calculate_vm_upgrade_cost`, which validates only the *plan's* min/max (`validate_custom_vm_spec`) — never that the new spec is **higher** than the current one. A request that lowers CPU/RAM produces a negative/zero prorated delta, a near-zero (or negative) `SubscriptionPayment` amount, and `on_payment` in `subscription/vm.rs` then applies the *reduced* spec. Effect: a user can downgrade their VM mid-cycle and pay ~nothing, or an attacker with a stolen session token can shrink a victim's VM (availability impact). Note `create_upgrade_payment`'s tax/`CurrencyAmount::sub` path may also error on a negative delta, making the failure mode inconsistent rather than safe.

**Recommendation:** in `calculate_vm_upgrade_cost` (or the API layer), `ensure!` that `new_cpu >= current.cpu`, `new_memory >= current.memory`, `new_disk >= current.disk` (disk-shrink is usually impossible anyway) and that at least one dimension strictly increases.

### 3. `X-Forwarded-For` trusted without a proxy allowlist (MEDIUM)

`ClientIp` (`lnvps_api_common/src/client_ip.rs`) reads the **left-most** `X-Forwarded-For` entry, i.e. the value closest to client control. The doc comment says the API "always runs behind a reverse proxy", but if the front proxy appends rather than replaces (or a request reaches the API directly), an attacker sets their own country via `X-Forwarded-For`. That feeds `capture_client_geo` → `set_user_geo` on **every** authenticated mutating request and VM order — a piece of EU VAT place-of-supply evidence. Left-most is the wrong end to trust: the entry written by the *nearest trusted proxy* is the right-most. Low direct impact (evidence is "non-contradictory" and combined with other signals), but the trust assumption is backwards and it's trivially spoofable.

**Recommendation:** document/enforce that the edge proxy must strip client-supplied XFF and set the value itself; consider using the right-most XFF entry or a dedicated `X-Real-IP` set only by the edge.

### 4. Contact form: header-injection-adjacent and spoofable Reply-To, plus tax-ID enumeration via VIES (LOW)

- `POST /api/v1/contact` builds `Reply-To: {name} <{email}>` and subject `Contact Form: {subject}` straight from request strings (`api/contact.rs`). `lettre`'s `parse()` will reject a CRLF-containing address, so classic SMTP header injection is largely mitigated, but the **name** is attacker-controlled text placed in the display-name position and the message body is sent to the support inbox unfiltered — a spam/phishing channel aimed at staff (well-formed, DKIM-passing mail from your own SMTP with an attacker's chosen Reply-To). Turnstile raises the cost but doesn't authenticate the sender.
- `PATCH /api/v1/account` calls the VIES `validate_vat_number_with_trader` and returns `mismatched_fields` to the caller (`api/routes.rs:258-290`). The caller can therefore probe **any** EU VAT number and learn the registered name/street/postcode/city mismatch set — an information-disclosure oracle on third parties' VAT registration data (and it can be scripted; see finding 1). Mismatch warnings should only be returned when the number is plausibly the caller's own; consider returning a generic "details do not match" without field names.

**Recommendation:** strip/replace newlines and angle brackets in the contact `name`/`subject`, send the submission as a plain-body quote with a fixed Reply-To (or none) and include the sender address in the body only. Reduce VIES mismatch detail to a boolean.

### 5. Sensitive material handled in plaintext in a few spots (LOW)

- **Email verification token** — 32 random bytes stored in the clear in `users.email_verify_token` (`api/routes.rs:190`) and looked up by direct equality. A DB read leak lets an attacker verify (and thus redirect notifications for) any account with a pending email change. Same class as a password-reset token: store a SHA-256 hash of the token, compare hashes.
- **WhatsApp code** — 6 digits, plaintext (`whatsapp_verify_code`). Low value, but hash + attempt cap (finding 1).
- **NWC connection string** — stored as `external_id` and correctly *not* exposed in `PaymentMethodResponse` (only `provider`/`card_*`/flags are serialised) — good. Just confirm logs never print `UserPaymentMethod` with `external_id` (NWC URI contains a secret).

### 6. Security headers absent on HTML responses (LOW)

`v1_verify_email`, `v1_get_payment_invoice` and `v1_get_sponsoring_lir_agreement` return `Html` with no `X-Frame-Options`/`Content-Security-Policy`/`Referrer-Policy` (the CORS layer only adds CORS headers). Mustache HTML-escapes interpolated values, so stored/reflected XSS via these pages is unlikely, but a defense-in-depth header set on the whole router (`tower_http::set_header`) is cheap. The invoice page is authenticated via a **query-string** NIP-98 event (`?auth=…`) — that token lands in reverse-proxy/browser access logs; the 600 s validity window bounds the exposure, but a short-lived single-use download token would be cleaner than a reusable signed event in a URL.

### 7. Misc / hardening notes (INFO)

- **Error surface**: consumer build correctly returns generic `"An internal error occurred"` (the verbose variant is behind the `admin` feature); keep `lnvps_api` from ever enabling that feature transitively.
- **SSRF via referral Lightning-address validation** (`api/referral.rs` `validate_lightning_address`): the server fetches `https://{domain}/.well-known/lnurlp/{name}` for a user-supplied Lightning address. Scheme is pinned by `LightningAddress::lnurlp_url()` but the **host** is attacker-controlled — a blind-SSRF probe of arbitrary HTTPS hosts (response content isn't returned, only success/invalid). Minor; consider an egress allowlist/timeout and treat as low risk.
- **`v1_get_payment`** resolves ownership via `get_vm_by_subscription`, which only matches `subscription_type = 3` (VPS); payments for IP-range/app subscriptions will 500 rather than resolve — a correctness/DoS-of-self wart, not an IDOR (ownership of the invoice endpoint is checked properly via `subscription.user_id`). Prefer the subscription-based lookup everywhere.
- **CORS**: wildcard origin + no credentials is the right call for header-token auth (avoids the `Origin: null` + credentials trap) and mirrors request headers so `Authorization` works cross-origin from `.onion`/Tor. No change.
- **Webhooks** (`bitvora`/`revolut`/`stripe`) are verified in the payments_rs layer with provider signing secrets before any state change — confirmed in `payments/revolut.rs`.
- **Payment races**: renewal reuses an existing pending payment matching method+type+time_value, and expiry extension is driven by webhook/invoice settlement (`on_payment`) with the DB row as source of truth; no client-supplied amount is ever trusted (custom specs are re-priced server-side and min/max-validated at order/upgrade). No double-spend or amount-manipulation vector found.

## Priority order

1. Rate limiting (esp. verify-confirm + auth-start + VM power/provision endpoints) — finding 1.
2. Block downgrades in the upgrade path — finding 2.
3. Fix XFF trust direction / document edge-proxy contract — finding 3.
4. VIES mismatch detail + contact-form Reply-To hygiene — finding 4.
5. Hash verification tokens at rest; security headers; single-use invoice download token — findings 5–6.
