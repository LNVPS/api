# API Changelog

All notable changes to the LNVPS APIs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed
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
