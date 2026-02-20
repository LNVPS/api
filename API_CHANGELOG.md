# API Changelog

All notable changes to the LNVPS APIs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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
