# API Changelog

All notable changes to the LNVPS APIs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
