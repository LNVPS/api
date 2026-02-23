# E2E Integration Tests

**Status:** complete
**Started:** 2026-02-23
**Last updated:** 2026-02-23

## Goal

Create a comprehensive E2E integration test suite that tests all user API and admin API endpoints against localhost. Tests use NIP-98 Nostr auth with auto-generated keys. Includes CRUD lifecycle tests and full VM order flow.

## Findings

- API uses NIP-98 (Nostr HTTP Auth) for authenticated endpoints
- User API defaults to `http://localhost:8000`, Admin API defaults to `http://localhost:8001`
- Response types wrap in `{"data": ...}` or `{"data": [...], "total": N, "limit": N, "offset": N}`
- Errors return `{"error": "message"}`
- Auth keys are auto-generated when env vars not set, so all tests run unconditionally
- CRUD lifecycle tests for regions, roles, cost plans, OS images
- SSH key CRUD lifecycle and VM order creation flow

## Tasks

- [x] Create test crate structure (Cargo.toml, lib crate)
- [x] Implement NIP-98 auth helper
- [x] Implement common test client with base URL and auth support
- [x] Test unauthenticated user API endpoints (docs, templates, images, payment methods, ip_space)
- [x] Test authenticated user API endpoints (account, VMs, SSH keys, payments, subscriptions, referral)
- [x] Test admin API endpoints (users, VMs, hosts, regions, roles, templates, etc.)
- [x] Change defaults to localhost:8000/8001
- [x] Add admin CRUD lifecycle tests (region, role, cost plan, OS image)
- [x] Add SSH key CRUD lifecycle test
- [x] Add VM order creation test with payment verification
- [x] Add VM extend admin test
- [x] Verify compilation and test execution

## Notes

- Environment variables: `LNVPS_API_URL`, `NOSTR_SECRET_KEY`, `LNVPS_ADMIN_API_URL`, `ADMIN_NOSTR_SECRET_KEY`
- Auth keys auto-generated when env vars not set (random Nostr keys)
- 93 total tests, all compiling cleanly with no clippy warnings
