# API Changelog

All notable changes to the LNVPS APIs are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security
- **2026-02-16** - Sanitized sensitive fields in `AdminPaymentMethodConfigInfo` responses
  - Provider config secrets (tokens, API keys, webhook secrets) are no longer returned in GET/list responses
  - Affected endpoints: `GET /api/v1/admin/payment-config`, `GET /api/v1/admin/payment-config/{id}`
  - Secrets are replaced with boolean indicators (e.g., `has_token: true`, `has_webhook_secret: true`)
  - Public/non-sensitive fields (URLs, client IDs, publishable keys) are still returned
